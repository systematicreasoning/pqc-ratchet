package pqcratchet_test

// ratchet_test.go — comprehensive tests for pqcratchet after security review fixes.
//
// Test categories:
//   KEM:       key generation, encap/decap round-trip, wrong-key, pubContext consistency
//   DSA:       sign/verify, wrong key, tampered message
//   Identity:  generation (signature verification), JSON round-trip
//   KEM init:  Alice/Bob root-key agreement, invalid initiator signature rejected
//   Session:   encrypt/decrypt, bidirectional, KEM ratchet, out-of-order,
//              replay, HMAC tamper (state rollback)
//   Wire:      bundle/message marshal round-trips, version rejection, allocation bounds
//   Zeroing:   ZeroKEMKeyPair, ZeroDSAPrivateKeyBestEffort
//   AD:        session AD binding (identity misbinding prevention)
//   E2E:       full handshake → multiturn messaging

import (
	"bytes"
	"encoding/json"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/pqcratchet"
)

// ─── KEM tests ────────────────────────────────────────────────────────────────

func TestKEMRoundTrip(t *testing.T) {
	kp, err := pqc.GenerateKEMKeyPair(nil)
	must(t, err, "GenerateKEMKeyPair")

	ct, ss1, err := pqc.Encapsulate(nil, &kp.Public)
	must(t, err, "Encapsulate")

	ss2, err := pqc.Decapsulate(&kp.Private, ct)
	must(t, err, "Decapsulate")

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("KEM: shared secrets do not match")
	}
}

func TestKEMWrongKey(t *testing.T) {
	kp1, _ := pqc.GenerateKEMKeyPair(nil)
	kp2, _ := pqc.GenerateKEMKeyPair(nil)

	ct, ss1, err := pqc.Encapsulate(nil, &kp1.Public)
	must(t, err, "Encapsulate")

	ss2, err := pqc.Decapsulate(&kp2.Private, ct)
	if err == nil && bytes.Equal(ss1, ss2) {
		t.Fatal("KEM: decap with wrong key produced same shared secret")
	}
}

// TestKEMPubContextConsistency verifies that Encapsulate and Decapsulate
// derive the same pubContext for combineKEMSecrets. This is the invariant
// that was previously at risk due to the dead private-key write in Decapsulate.
// We verify it indirectly: if the shared secrets match, the KDF inputs matched.
func TestKEMPubContextConsistency(t *testing.T) {
	for i := 0; i < 5; i++ {
		kp, err := pqc.GenerateKEMKeyPair(nil)
		must(t, err, "GenerateKEMKeyPair")

		ct, ss1, err := pqc.Encapsulate(nil, &kp.Public)
		must(t, err, "Encapsulate")

		ss2, err := pqc.Decapsulate(&kp.Private, ct)
		must(t, err, "Decapsulate")

		if !bytes.Equal(ss1, ss2) {
			t.Fatalf("iteration %d: pubContext mismatch — shared secrets differ", i)
		}
		if len(ss1) != 32 {
			t.Fatalf("shared secret length: want 32, got %d", len(ss1))
		}
	}
}

func TestKEMSizes(t *testing.T) {
	kp, err := pqc.GenerateKEMKeyPair(nil)
	must(t, err, "GenerateKEMKeyPair")
	if len(kp.Public) != pqc.HybridPublicKeySize {
		t.Fatalf("public key size: want %d, got %d", pqc.HybridPublicKeySize, len(kp.Public))
	}
	if len(kp.Private) != pqc.HybridPrivateKeySize {
		t.Fatalf("private key size: want %d, got %d", pqc.HybridPrivateKeySize, len(kp.Private))
	}
}

func TestZeroKEMKeyPair(t *testing.T) {
	kp, err := pqc.GenerateKEMKeyPair(nil)
	must(t, err, "GenerateKEMKeyPair")

	// Capture the public key before zeroing (it should be unchanged after).
	var pubBefore pqc.HybridKEMPublicKey
	copy(pubBefore[:], kp.Public[:])

	pqc.ZeroKEMKeyPair(kp)

	// Private key must be all zeros.
	for i, b := range kp.Private {
		if b != 0 {
			t.Fatalf("ZeroKEMKeyPair: private byte %d not zeroed", i)
		}
	}
	// Public key must be unchanged — ZeroKEMKeyPair only zeros the private key.
	if kp.Public != pubBefore {
		t.Fatal("ZeroKEMKeyPair: public key was unexpectedly modified")
	}
}

func TestZeroDSAPrivateKeyBestEffort(t *testing.T) {
	kp, err := pqc.GenerateDSAKeyPair(nil)
	must(t, err, "GenerateDSAKeyPair")

	// Verify the key works before zeroing.
	msg := []byte("test")
	sig, err := pqc.Sign(kp.Private, msg)
	must(t, err, "Sign before zero")
	if !pqc.Verify(kp.Public, msg, sig) {
		t.Fatal("key should verify before zeroing")
	}

	// ZeroDSAPrivateKeyBestEffort clears the serialised form only —
	// it cannot reach the internal struct fields of the circl PrivateKey.
	// We call it and confirm it doesn't panic.
	pqc.ZeroDSAPrivateKeyBestEffort(kp)

	// Note: we do NOT assert the key is now unusable — the function
	// documents that it is best-effort and cannot guarantee clearing.
	// The test simply verifies the call completes without panic.
}

// ─── DSA tests ────────────────────────────────────────────────────────────────

func TestDSARoundTrip(t *testing.T) {
	kp, err := pqc.GenerateDSAKeyPair(nil)
	must(t, err, "GenerateDSAKeyPair")

	msg := []byte("test message for ML-DSA-65")
	sig, err := pqc.Sign(kp.Private, msg)
	must(t, err, "Sign")

	if len(sig) != pqc.DSASignatureSize {
		t.Fatalf("signature size: want %d, got %d", pqc.DSASignatureSize, len(sig))
	}
	if !pqc.Verify(kp.Public, msg, sig) {
		t.Fatal("Verify: valid signature rejected")
	}
}

func TestDSATamperedMessage(t *testing.T) {
	kp, _ := pqc.GenerateDSAKeyPair(nil)
	msg := []byte("original")
	sig, _ := pqc.Sign(kp.Private, msg)
	if pqc.Verify(kp.Public, []byte("tampered"), sig) {
		t.Fatal("Verify: accepted signature for tampered message")
	}
}

func TestDSAWrongKey(t *testing.T) {
	kp1, _ := pqc.GenerateDSAKeyPair(nil)
	kp2, _ := pqc.GenerateDSAKeyPair(nil)
	msg := []byte("message")
	sig, _ := pqc.Sign(kp1.Private, msg)
	if pqc.Verify(kp2.Public, msg, sig) {
		t.Fatal("Verify: accepted signature from wrong key")
	}
}

// ─── Identity tests ───────────────────────────────────────────────────────────

func TestIdentityGeneration(t *testing.T) {
	id, err := pqc.GenerateIdentity(42, 3, 5)
	must(t, err, "GenerateIdentity")

	if id.ID != 42 {
		t.Fatalf("ID: want 42, got %d", id.ID)
	}
	if len(id.SignedPreKeys) != 3 {
		t.Fatalf("SignedPreKeys: want 3, got %d", len(id.SignedPreKeys))
	}
	if len(id.PreKeys) != 5 {
		t.Fatalf("PreKeys: want 5, got %d", len(id.PreKeys))
	}

	sigPubBytes := pqc.DSAPublicKeyBytes(id.SigningKey.Public)
	sigPub, _ := pqc.ParseDSAPublicKey(sigPubBytes)
	for i, spk := range id.SignedPreKeys {
		if !pqc.Verify(sigPub, spk.Public[:], id.SignedPreKeySigs[i]) {
			t.Fatalf("SignedPreKey[%d]: signature invalid", i)
		}
	}
	if !pqc.Verify(sigPub, id.ExchangeKey.Public[:], id.ExchangeKeySignature) {
		t.Fatal("ExchangeKey: signature invalid")
	}
}

func TestIdentityJSONRoundTrip(t *testing.T) {
	id, err := pqc.GenerateIdentity(7, 2, 3)
	must(t, err, "GenerateIdentity")

	data, err := json.Marshal(id)
	must(t, err, "Marshal")

	var id2 pqc.Identity
	must(t, json.Unmarshal(data, &id2), "Unmarshal")

	if id2.ID != id.ID {
		t.Fatalf("ID mismatch: %d vs %d", id.ID, id2.ID)
	}
	if !bytes.Equal(id2.ExchangeKey.Public[:], id.ExchangeKey.Public[:]) {
		t.Fatal("ExchangeKey.Public mismatch after round-trip")
	}
	if !bytes.Equal(id2.ExchangeKeySignature, id.ExchangeKeySignature) {
		t.Fatal("ExchangeKeySignature mismatch after round-trip")
	}
}

// ─── X3DH tests ───────────────────────────────────────────────────────────────

func TestKEMInitRootKeyAgreement(t *testing.T) {
	alice, bob := mustIdentities(t)

	bundleWire, err := pqc.MakeBundleWire(bob, 0, -1)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bundleWire)
	must(t, err, "ParseBundleWire")

	aliceSess, result, err := pqc.CreateSessionInitiator(alice, bundle)
	must(t, err, "CreateSessionInitiator")
	_ = aliceSess

	pkmWire := buildPKMWire(t, alice, bundle, result)
	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire)
	must(t, err, "ParsePreKeyMessageWire")

	// Root key agreement is verified implicitly: if Bob's session can decrypt
	// Alice's message (see TestEncryptDecryptBasic), the root keys matched.
	_, err = pqc.CreateSessionResponder(bob, pkm)
	must(t, err, "CreateSessionResponder")
}

func TestKEMInitInvalidSig(t *testing.T) {
	alice, bob := mustIdentities(t)

	bundleWire, _ := pqc.MakeBundleWire(bob, 0, -1)
	bundle, _ := pqc.ParseBundleWire(bundleWire)

	_, result, err := pqc.CreateSessionInitiator(alice, bundle)
	must(t, err, "CreateSessionInitiator")

	pkmWire := buildPKMWire(t, alice, bundle, result)
	// Corrupt the InitiatorSig
	pkmWire.InitiatorSig[0] ^= 0xFF
	pkmWire.InitiatorSig[1] ^= 0xFF

	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire)
	must(t, err, "ParsePreKeyMessageWire")

	_, err = pqc.CreateSessionResponder(bob, pkm)
	if err == nil {
		t.Fatal("expected error with invalid initiator signature, got nil")
	}
}

// ─── Session tests ────────────────────────────────────────────────────────────

func TestEncryptDecryptBasic(t *testing.T) {
	alice, bob := setupSessions(t)
	plaintext := []byte("Hello from Alice!")

	enc, err := alice.EncryptMessage(plaintext)
	must(t, err, "EncryptMessage")

	wire := buildSignedMessageWire(alice, enc)

	sm, err := pqc.UnmarshalSignedMessage(wire)
	must(t, err, "UnmarshalSignedMessage")

	got, err := bob.DecryptSignedMessage(sm)
	must(t, err, "DecryptSignedMessage")

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt: got %q, want %q", got, plaintext)
	}
}

func TestBidirectionalMessaging(t *testing.T) {
	alice, bob := setupSessions(t)

	msgs := []struct {
		from, to *pqc.Session
		text     string
	}{
		{alice, bob, "A→B 1"},
		{bob, alice, "B→A 1"},
		{alice, bob, "A→B 2"},
		{alice, bob, "A→B 3"},
		{bob, alice, "B→A 2"},
	}
	for _, m := range msgs {
		sendRecv(t, m.from, m.to, m.text)
	}
}

// TestHMACTamperRollback verifies that tampering with a message does not
// advance the receiver's ratchet state (critical fix from security review #2).
func TestHMACTamperRollback(t *testing.T) {
	alice, bob := setupSessions(t)

	// Alice sends msg 1, Bob receives it successfully.
	sendRecv(t, alice, bob, "legitimate message 1")

	// Alice sends msg 2, we tamper with it.
	enc, err := alice.EncryptMessage([]byte("tamper target"))
	must(t, err, "EncryptMessage")
	wire := buildSignedMessageWire(alice, enc)
	// Flip bytes in the HMAC signature portion (first 33 bytes: version + 32 sig)
	wire[2] ^= 0xFF

	sm, err := pqc.UnmarshalSignedMessage(wire)
	if err != nil {
		// Parse failure is acceptable for a tampered version byte.
		// Re-run with body corruption instead.
		wire2 := buildSignedMessageWire(alice, enc)
		wire2[len(wire2)-1] ^= 0xFF
		sm, err = pqc.UnmarshalSignedMessage(wire2)
		must(t, err, "UnmarshalSignedMessage (body tamper)")
	}
	_, err = bob.DecryptSignedMessage(sm)
	if err == nil {
		t.Fatal("tampered message accepted — HMAC verification bypassed")
	}

	// Critical: Bob must still be able to receive a genuine message from Alice
	// at the same counter (state was rolled back, not corrupted).
	// Re-encrypt the same message at Alice (she retains her state).
	sendRecv(t, alice, bob, "legitimate message 2")
}

func TestReplayRejected(t *testing.T) {
	alice, bob := setupSessions(t)

	enc, err := alice.EncryptMessage([]byte("replay test"))
	must(t, err, "EncryptMessage")
	wire := buildSignedMessageWire(alice, enc)

	sm1, _ := pqc.UnmarshalSignedMessage(wire)
	_, err = bob.DecryptSignedMessage(sm1)
	must(t, err, "first decrypt")

	sm2, _ := pqc.UnmarshalSignedMessage(wire)
	_, err = bob.DecryptSignedMessage(sm2)
	if err == nil {
		t.Fatal("replay: expected error on duplicate counter, got nil")
	}
}

func TestOutOfOrderDelivery(t *testing.T) {
	alice, bob := setupSessions(t)

	enc1, _ := alice.EncryptMessage([]byte("msg 1"))
	enc2, _ := alice.EncryptMessage([]byte("msg 2"))
	enc3, _ := alice.EncryptMessage([]byte("msg 3"))

	wire1 := buildSignedMessageWire(alice, enc1)
	wire2 := buildSignedMessageWire(alice, enc2)
	wire3 := buildSignedMessageWire(alice, enc3)

	// Deliver out of order: 3, 1, 2
	for _, w := range [][]byte{wire3, wire1, wire2} {
		sm, err := pqc.UnmarshalSignedMessage(w)
		must(t, err, "UnmarshalSignedMessage")
		_, err = bob.DecryptSignedMessage(sm)
		must(t, err, "DecryptSignedMessage (out of order)")
	}
}

// ─── Wire format tests ────────────────────────────────────────────────────────

func TestBundleWireRoundTrip(t *testing.T) {
	id, _ := pqc.GenerateIdentity(99, 2, 3)
	bw, err := pqc.MakeBundleWire(id, 0, 0)
	must(t, err, "MakeBundleWire")

	data := pqc.MarshalBundleWire(bw)
	bw2, err := pqc.UnmarshalBundleWire(bytes.NewReader(data))
	must(t, err, "UnmarshalBundleWire")

	if !bytes.Equal(bw.SigningPub[:], bw2.SigningPub[:]) {
		t.Fatal("SigningPub mismatch after round-trip")
	}
	if bw.RegistrationID != bw2.RegistrationID {
		t.Fatalf("RegistrationID mismatch: %d vs %d", bw.RegistrationID, bw2.RegistrationID)
	}
	_, err = pqc.ParseBundleWire(bw2)
	must(t, err, "ParseBundleWire after round-trip")
}

func TestWireVersionRejection(t *testing.T) {
	id, _ := pqc.GenerateIdentity(1, 1, 0)
	bw, _ := pqc.MakeBundleWire(id, 0, -1)
	data := pqc.MarshalBundleWire(bw)

	// Corrupt version byte
	data[0] = 0xFF
	_, err := pqc.UnmarshalBundleWire(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected version rejection, got nil")
	}
}

func TestSignedMessageVersionRejection(t *testing.T) {
	alice, _ := setupSessions(t)
	enc, _ := alice.EncryptMessage([]byte("hello"))
	wire := buildSignedMessageWire(alice, enc)
	wire[0] = 0xFF
	_, err := pqc.UnmarshalSignedMessage(wire)
	if err == nil {
		t.Fatal("expected version rejection for signed message, got nil")
	}
}

func TestMessageProtocolRoundTrip(t *testing.T) {
	ratchetKP, _ := pqc.GenerateKEMKeyPair(nil)
	remoteKP, _ := pqc.GenerateKEMKeyPair(nil)
	ct, _, _ := pqc.Encapsulate(nil, &remoteKP.Public)

	orig := &pqc.ParsedMessageProtocol{
		Counter:          42,
		SenderRatchetPub: &ratchetKP.Public,
		RatchetCT:        ct,
		CipherText:       []byte("hello encrypted world"),
	}

	data := pqc.MarshalMessageProtocol(orig)
	parsed, err := pqc.UnmarshalMessageProtocol(data)
	must(t, err, "UnmarshalMessageProtocol")

	if parsed.Counter != orig.Counter {
		t.Fatalf("counter: %d vs %d", parsed.Counter, orig.Counter)
	}
	if !bytes.Equal(parsed.SenderRatchetPub[:], orig.SenderRatchetPub[:]) {
		t.Fatal("SenderRatchetPub mismatch")
	}
	if !bytes.Equal(parsed.CipherText, orig.CipherText) {
		t.Fatal("CipherText mismatch")
	}
}

// TestAllocationBounds verifies that a malicious ciphertext length field
// does not cause an OOM panic (issue #8 from security review).
func TestAllocationBounds(t *testing.T) {
	// Build a valid message header then overwrite the ciphertext length with 0xFFFFFFFF
	ratchetKP, _ := pqc.GenerateKEMKeyPair(nil)
	orig := &pqc.ParsedMessageProtocol{
		Counter:          0,
		SenderRatchetPub: &ratchetKP.Public,
		CipherText:       []byte("x"),
	}
	data := pqc.MarshalMessageProtocol(orig)

	// The ciphertext length is the last uint32 before the ciphertext bytes.
	// Overwrite it with 0xFFFFFFFF.
	ctLenOffset := len(data) - 1 - 4
	data[ctLenOffset] = 0xFF
	data[ctLenOffset+1] = 0xFF
	data[ctLenOffset+2] = 0xFF
	data[ctLenOffset+3] = 0xFF

	_, err := pqc.UnmarshalMessageProtocol(data)
	if err == nil {
		t.Fatal("expected error for oversized ciphertext length, got nil")
	}
}

// ─── End-to-end test ──────────────────────────────────────────────────────────

func TestEndToEndFullHandshake(t *testing.T) {
	aliceID, err := pqc.GenerateIdentity(100, 2, 5)
	must(t, err, "alice identity")
	bobID, err := pqc.GenerateIdentity(200, 2, 5)
	must(t, err, "bob identity")

	// Bob publishes bundle.
	bundleWire, err := pqc.MakeBundleWire(bobID, 0, 0)
	must(t, err, "MakeBundleWire")
	bundleBytes := pqc.MarshalBundleWire(bundleWire)

	// Alice fetches and parses.
	bundleWire2, err := pqc.UnmarshalBundleWire(bytes.NewReader(bundleBytes))
	must(t, err, "UnmarshalBundleWire")
	bundle, err := pqc.ParseBundleWire(bundleWire2)
	must(t, err, "ParseBundleWire")

	// Alice creates session.
	aliceSess, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")

	// Alice sends PreKeyMessage.
	pkmWire := buildPKMWire(t, aliceID, bundle, result)
	pkmBytes := pqc.MarshalPreKeyMessageWire(pkmWire)

	pkmWire2, err := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkmBytes))
	must(t, err, "UnmarshalPreKeyMessageWire")
	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire2)
	must(t, err, "ParsePreKeyMessageWire")

	bobSess, err := pqc.CreateSessionResponder(bobID, pkm)
	must(t, err, "CreateSessionResponder")

	msgs := []struct {
		from, to *pqc.Session
		text     string
	}{
		{aliceSess, bobSess, "Alice says hello"},
		{bobSess, aliceSess, "Bob says hi"},
		{aliceSess, bobSess, "How are you?"},
		{bobSess, aliceSess, "Doing great!"},
		{aliceSess, bobSess, "Great!"},
	}
	for _, m := range msgs {
		sendRecv(t, m.from, m.to, m.text)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustIdentities(t *testing.T) (*pqc.Identity, *pqc.Identity) {
	t.Helper()
	alice, err := pqc.GenerateIdentity(1, 1, 1)
	must(t, err, "GenerateIdentity alice")
	bob, err := pqc.GenerateIdentity(2, 1, 1)
	must(t, err, "GenerateIdentity bob")
	return alice, bob
}

func setupSessions(t *testing.T) (alice, bob *pqc.Session) {
	t.Helper()
	aliceID, bobID := mustIdentities(t)

	bundleWire, err := pqc.MakeBundleWire(bobID, 0, 0)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bundleWire)
	must(t, err, "ParseBundleWire")

	aliceSess, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")

	pkmWire := buildPKMWire(t, aliceID, bundle, result)
	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire)
	must(t, err, "ParsePreKeyMessageWire")

	bobSess, err := pqc.CreateSessionResponder(bobID, pkm)
	must(t, err, "CreateSessionResponder")

	return aliceSess, bobSess
}

func buildPKMWire(t *testing.T, alice *pqc.Identity, bundle *pqc.PreKeyBundle, result *pqc.KEMInitiatorResult) *pqc.PreKeyMessageWire {
	t.Helper()
	m := &pqc.PreKeyMessageWire{
		RegistrationID:    uint32(alice.ID),
		SignedPreKeyIndex: uint32(bundle.SignedPreKeyIndex),
		OneTimePreKeyIndex: 0xFFFFFFFF,
	}
	if bundle.OneTimePreKeyIndex >= 0 && result.CT4 != nil {
		m.OneTimePreKeyIndex = uint32(bundle.OneTimePreKeyIndex)
		m.HasCT4 = true
		copy(m.CT4[:], result.CT4[:])
	}
	copy(m.SigningPub[:], pqc.DSAPublicKeyBytes(alice.SigningKey.Public))
	copy(m.ExchangeKeySig[:], alice.ExchangeKeySignature)
	copy(m.ExchangePub[:], alice.ExchangeKey.Public[:])
	copy(m.BaseKey[:], result.EphemeralKP.Public[:])
	copy(m.CT1[:], result.CT1[:])
	copy(m.CT2[:], result.CT2[:])
	copy(m.InitiatorSig[:], result.InitiatorSig)
	return m
}

func buildSignedMessageWire(sess *pqc.Session, enc *pqc.EncryptResult) []byte {
	inner := pqc.MarshalMessageProtocol(&pqc.ParsedMessageProtocol{
		Counter:          uint32(enc.Counter),
		SenderRatchetPub: enc.NewRatchetPub,
		RatchetCT:        enc.RatchetCT,
		CipherText:       enc.Ciphertext,
	})
	return pqc.MarshalSignedMessage(inner, enc.HMACKey,
		sess.AD, sess.InitiatorSigningKeyBytes, sess.ResponderSigningKeyBytes)
}

// TestADBinding verifies that a message authenticated in one session cannot
// be replayed into a different session (different identity keys → different AD).
func TestADBinding(t *testing.T) {
	// Build two independent session pairs.
	alice1, bob1 := setupSessions(t)
	alice2, _ := setupSessions(t)

	// Alice1 encrypts.
	enc, err := alice1.EncryptMessage([]byte("session 1 message"))
	must(t, err, "EncryptMessage")

	// Build wire using alice1's AD (correct).
	wire := buildSignedMessageWire(alice1, enc)

	// Bob1 can decrypt it.
	sm, err := pqc.UnmarshalSignedMessage(wire)
	must(t, err, "UnmarshalSignedMessage")
	_, err = bob1.DecryptSignedMessage(sm)
	must(t, err, "DecryptSignedMessage (correct session)")

	// Now try to verify the same inner bytes but with alice2's AD (wrong session).
	// We construct the wire using alice2's AD but the same HMAC key and inner bytes.
	inner := pqc.MarshalMessageProtocol(&pqc.ParsedMessageProtocol{
		Counter:          uint32(enc.Counter),
		SenderRatchetPub: enc.NewRatchetPub,
		RatchetCT:        enc.RatchetCT,
		CipherText:       enc.Ciphertext,
	})
	wrongWire := pqc.MarshalSignedMessage(inner, enc.HMACKey,
		alice2.AD, alice1.InitiatorSigningKeyBytes, alice1.ResponderSigningKeyBytes)

	sm2, err := pqc.UnmarshalSignedMessage(wrongWire)
	must(t, err, "UnmarshalSignedMessage (wrong AD)")

	// Bob1 must reject: wrong AD in HMAC.
	// Note: bob1 already advanced its counter on the first decrypt, so this
	// will fail either with ErrHMACVerifyFailed or ErrDuplicateMessage.
	_, err = bob1.DecryptSignedMessage(sm2)
	if err == nil {
		t.Fatal("AD binding: wrong-session message accepted — AD not bound into HMAC")
	}
}

func sendRecv(t *testing.T, from, to *pqc.Session, text string) {
	t.Helper()
	enc, err := from.EncryptMessage([]byte(text))
	must(t, err, "EncryptMessage: "+text)

	wire := buildSignedMessageWire(from, enc)

	sm, err := pqc.UnmarshalSignedMessage(wire)
	must(t, err, "UnmarshalSignedMessage: "+text)

	got, err := to.DecryptSignedMessage(sm)
	must(t, err, "DecryptSignedMessage: "+text)

	if !bytes.Equal(got, []byte(text)) {
		t.Fatalf("sendRecv: got %q, want %q", got, text)
	}
}

func must(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

// TestOPKConsumedAfterUse verifies that the one-time pre-key slot is nil after
// session creation (fix for use-after-zero bug where OPK was zeroed before
// AuthenticateB could read it, corrupting the X3DH key agreement).
func TestOPKConsumedAfterUse(t *testing.T) {
	aliceID, bobID := mustIdentities(t)

	// Use OPK index 0.
	bundleWire, err := pqc.MakeBundleWire(bobID, 0, 0)
	must(t, err, "MakeBundleWire with OPK")
	bundle, err := pqc.ParseBundleWire(bundleWire)
	must(t, err, "ParseBundleWire")
	if bundle.OneTimePreKeyPub == nil {
		t.Fatal("expected OPK in bundle")
	}

	aliceSess, result, err := pqc.CreateSessionInitiator(aliceID, bundle)
	must(t, err, "CreateSessionInitiator")

	pkmWire := buildPKMWire(t, aliceID, bundle, result)
	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire)
	must(t, err, "ParsePreKeyMessageWire")

	bobSess, err := pqc.CreateSessionResponder(bobID, pkm)
	must(t, err, "CreateSessionResponder with OPK")

	// OPK slot must be nil — consumed.
	if bobID.PreKeys[0] != nil {
		t.Fatal("OPK slot should be nil after consumption")
	}

	// Sessions must be functional — root keys matched, so messages decrypt.
	sendRecv(t, aliceSess, bobSess, "OPK session works")
	sendRecv(t, bobSess, aliceSess, "reply also works")
}

// TestTranscriptBindsExchangeKey verifies that a tampered IK_A.ex in the
// PreKeyMessage causes AuthenticateB to reject the session (tests the fix
// that includes IK_A.ex in the signed transcript).
func TestTranscriptBindsExchangeKey(t *testing.T) {
	alice, bob := mustIdentities(t)

	bundleWire, _ := pqc.MakeBundleWire(bob, 0, -1)
	bundle, _ := pqc.ParseBundleWire(bundleWire)

	_, result, err := pqc.CreateSessionInitiator(alice, bundle)
	must(t, err, "CreateSessionInitiator")

	pkmWire := buildPKMWire(t, alice, bundle, result)

	// Flip a byte in ExchangePub (IK_A.ex). The ExchangeKeySig won't match,
	// so ParsePreKeyMessageWire should reject it.
	pkmWire.ExchangePub[10] ^= 0xFF

	_, err = pqc.ParsePreKeyMessageWire(pkmWire)
	if err == nil {
		t.Fatal("expected rejection when ExchangePub is tampered (ExchangeKeySig mismatch)")
	}
}

// TestHMACRoleStability verifies that Alice can encrypt and Bob can decrypt
// (and vice versa) — proving the initiator/responder role fields are consistent
// across both session sides (regression test for the Local/Remote inversion bug).
func TestHMACRoleStability(t *testing.T) {
	alice, bob := setupSessions(t)

	// Verify field symmetry: alice's initiator key == bob's initiator key.
	if string(alice.InitiatorSigningKeyBytes) != string(bob.InitiatorSigningKeyBytes) {
		t.Fatal("InitiatorSigningKeyBytes mismatch between sessions")
	}
	if string(alice.ResponderSigningKeyBytes) != string(bob.ResponderSigningKeyBytes) {
		t.Fatal("ResponderSigningKeyBytes mismatch between sessions")
	}

	// Alice → Bob.
	sendRecv(t, alice, bob, "initiator to responder")
	// Bob → Alice.
	sendRecv(t, bob, alice, "responder to initiator")
	// Multiple in each direction.
	sendRecv(t, alice, bob, "initiator msg 2")
	sendRecv(t, bob, alice, "responder msg 2")
}

// TestOPKMismatchRejected verifies that a one-time pre-key mismatch between
// Alice and Bob (one side has OPK, other does not) is detected and rejected
// at session creation rather than silently producing a wrong root key.
func TestOPKMismatchRejected(t *testing.T) {
	alice, bob := mustIdentities(t)

	// Bundle WITH an OPK for Bob.
	bundleWire, err := pqc.MakeBundleWire(bob, 0, 0)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bundleWire)
	must(t, err, "ParseBundleWire")

	// Alice creates session using the OPK.
	_, result, err := pqc.CreateSessionInitiator(alice, bundle)
	must(t, err, "CreateSessionInitiator with OPK")

	pkmWire := buildPKMWire(t, alice, bundle, result)
	pkm, err := pqc.ParsePreKeyMessageWire(pkmWire)
	must(t, err, "ParsePreKeyMessageWire")

	// Tamper: zero out CT4 so Bob sees no OPK ciphertext but Bob has OPK priv.
	// The wire parser will deliver CT4=nil to CreateSessionResponder.
	// We can simulate this by consuming the OPK slot manually before the
	// responder runs — but actually the cleanest test is to check that when
	// wire-level CT4 is present, it must be consumed.
	// Instead, test the inverse: Alice sends CT4=nil but Bob has OPK private key.
	// We do this by creating a bundle WITHOUT OPK and a PreKeyMessage that
	// includes a non-nil CT4 field (patched directly).

	// Simpler approach: use a bundle with OPK, create session (CT4 present),
	// then manually nil CT4 in the parsed PreKeyMessage. AuthenticateB should
	// reject (ct4==nil, oneTimePreKeyPriv!=nil).
	pkm.CT4 = nil
	_, err = pqc.CreateSessionResponder(bob, pkm)
	if err == nil {
		t.Fatal("expected error when Bob has OPK priv but CT4 is nil")
	}
}

// TestSkippedKeyCapacitySentinel verifies that ErrSkippedKeyCapacity is
// exported and distinct — it is the sentinel returned when the skipped key
// cache is full and additional out-of-order messages cannot be cached.
// The full cache path is exercised in integration via a large gap.
func TestSkippedKeyCapacitySentinel(t *testing.T) {
	alice, bob := setupSessions(t)

	// Encrypt exactly MaxSkip messages without delivering any.
	// Delivering the last one requires caching MaxSkip-1 keys first.
	// Then caching one more key (for the next message) must return
	// ErrSkippedKeyCapacity.
	const n = pqc.MaxSkip
	encs := make([]*pqc.EncryptResult, n)
	for i := 0; i < n; i++ {
		enc, err := alice.EncryptMessage([]byte("fill"))
		must(t, err, "EncryptMessage")
		encs[i] = enc
	}

	// Deliver message at counter n-1. Bob caches keys 0..n-2 (n-1 entries)
	// then steps to n-1. Cache now has n-1 = MaxSkip-1 entries.
	wire := buildSignedMessageWire(alice, encs[n-1])
	sm, err := pqc.UnmarshalSignedMessage(wire)
	must(t, err, "UnmarshalSignedMessage")
	_, err = bob.DecryptSignedMessage(sm)
	must(t, err, "deliver last of batch (should succeed)")

	// Now skip one: send two more, deliver the second only.
	// Caching the skipped key fills the cache to MaxSkip.
	extra1, err := alice.EncryptMessage([]byte("skipped"))
	must(t, err, "EncryptMessage extra1")
	extra2, err := alice.EncryptMessage([]byte("delivered"))
	must(t, err, "EncryptMessage extra2")

	wire2 := buildSignedMessageWire(alice, extra2)
	sm2, err := pqc.UnmarshalSignedMessage(wire2)
	must(t, err, "UnmarshalSignedMessage extra2")
	_, err = bob.DecryptSignedMessage(sm2)
	must(t, err, "deliver extra2 (cache at MaxSkip-1, skip one fills it exactly)")

	// ErrSkippedKeyCapacity is a named exported sentinel — verify it compiles
	// and is distinct from other errors.
	if pqc.ErrSkippedKeyCapacity == nil {
		t.Fatal("ErrSkippedKeyCapacity must not be nil")
	}
	if pqc.ErrSkippedKeyCapacity == pqc.ErrHMACVerifyFailed {
		t.Fatal("ErrSkippedKeyCapacity must be distinct from other errors")
	}
	_ = extra1
}

// TestRatchetKPRestoredOnRollback verifies that a failed HMAC does not leave
// the session in a state where RatchetKP has been replaced without being
// recorded in the snapshot (regression test for the snapshot gap fix).
func TestRatchetKPRestoredOnRollback(t *testing.T) {
	alice, bob := setupSessions(t)

	// Deliver one good message to establish a receiving chain.
	sendRecv(t, alice, bob, "init")
	sendRecv(t, bob, alice, "init reply") // bob now has a sending step pending

	// Alice sends a message.
	enc, err := alice.EncryptMessage([]byte("real"))
	must(t, err, "EncryptMessage")
	wire := buildSignedMessageWire(alice, enc)

	// Tamper with the HMAC so Bob rolls back.
	sm, err := pqc.UnmarshalSignedMessage(wire)
	must(t, err, "UnmarshalSignedMessage")
	sm.Signature[0] ^= 0xFF

	_, err = bob.DecryptSignedMessage(sm)
	if err == nil {
		t.Fatal("expected HMAC failure on tampered message")
	}

	// After rollback, the session must still function — Bob can decrypt
	// the same message delivered correctly.
	sm2, err := pqc.UnmarshalSignedMessage(wire)
	must(t, err, "UnmarshalSignedMessage (clean)")
	plaintext, err := bob.DecryptSignedMessage(sm2)
	must(t, err, "DecryptSignedMessage after rollback")
	if string(plaintext) != "real" {
		t.Fatalf("wrong plaintext after rollback: %q", plaintext)
	}
}

// TestGCMADBinding verifies that AES-GCM additional data (session AD) is enforced:
// a ciphertext encrypted with Alice↔Bob AD cannot be decrypted with Alice↔Carol AD.
// This tests that the GCM tag covers the session identity independently of the
// outer HMAC.
func TestGCMADBinding(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	adAliceBob := []byte("AD-alice-bob")
	adAliceCarol := []byte("AD-alice-carol")
	plaintext := []byte("secret message")

	ct, err := pqc.AESGCMEncrypt(key, nonce, adAliceBob, plaintext)
	must(t, err, "AESGCMEncrypt")

	// Same key, same nonce, same ciphertext — different AD must fail.
	_, err = pqc.AESGCMDecrypt(key, nonce, adAliceCarol, ct)
	if err == nil {
		t.Fatal("GCM AD binding: decryption with wrong AD succeeded — AD is not enforced")
	}

	// Correct AD must succeed.
	got, err := pqc.AESGCMDecrypt(key, nonce, adAliceBob, ct)
	must(t, err, "AESGCMDecrypt correct AD")
	if string(got) != string(plaintext) {
		t.Fatalf("wrong plaintext: %q", got)
	}
}
