package pqcratchet_test

import (
	"sync"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/pqcratchet"
)

// TestOPKConcurrentReservation fires many concurrent CreateSessionResponder
// calls targeting the same OPK index. The mutex in CreateSessionResponder must
// ensure the OPK is consumed exactly once; all other goroutines must find a nil
// slot and receive an error, not a duplicate session derived from the reused key.
func TestOPKConcurrentReservation(t *testing.T) {
	alice, err := pqc.GenerateIdentity(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := pqc.GenerateIdentity(2, 1, 1) // 1 OPK
	if err != nil {
		t.Fatal(err)
	}

	// Build a bundle that uses OPK index 0.
	bundleWire, err := pqc.MakeBundleWire(bob, 0, 0) // spkIdx=0, opkIdx=0
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pqc.ParseBundleWire(bundleWire)
	if err != nil {
		t.Fatal(err)
	}

	_, result, err := pqc.CreateSessionInitiator(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Build the wire PreKeyMessage that all goroutines will present to Bob.
	pkmWire := buildPKMWire(t, alice, bundle, result)
	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 50
	successes := make(chan bool, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pqc.CreateSessionResponder(bob, pkm)
			successes <- (err == nil)
		}()
	}
	wg.Wait()
	close(successes)

	var nSuccess int
	for ok := range successes {
		if ok {
			nSuccess++
		}
	}
	if nSuccess != 1 {
		t.Errorf("expected exactly 1 successful OPK use, got %d", nSuccess)
	}
}
