package pqcratchet_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	pqc "github.com/PeculiarVentures/pqc-ratchet/pqcratchet"
)

// TestInteropGoTS is an end-to-end interop test between the Go and TypeScript
// implementations. It:
//
//  1. Generates Bob's identity in Go, produces a fixture JSON.
//  2. Runs the TypeScript interop_verify.mjs to:
//     a. Establish Bob's session from the fixture.
//     b. Decrypt 5 Go→TS messages.
//     c. Encrypt 3 TS→Go replies.
//  3. Go (as Alice) decrypts the TS replies.
//
// The test is skipped if Node.js ≥18 is not available or the TS dist/ is
// not compiled (run `npx tsc` in the TS repo first).
func TestInteropGoTS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interop test in short mode")
	}

	// Locate the TS repo relative to this file.
	_, thisFile, _, _ := runtime.Caller(0)
	goRepo := filepath.Dir(filepath.Dir(thisFile))
	tsRepo := filepath.Join(filepath.Dir(goRepo), "pqc-ratchet-ts")
	tsScript := filepath.Join(tsRepo, "scripts", "interop_verify.mjs")
	tsDist := filepath.Join(tsRepo, "dist", "index.js")

	if _, err := os.Stat(tsDist); os.IsNotExist(err) {
		t.Skipf("TS dist not compiled (%s not found); run `npx tsc` in %s", tsDist, tsRepo)
	}
	if _, err := os.Stat(tsScript); os.IsNotExist(err) {
		t.Skipf("TS interop script not found at %s", tsScript)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH; skipping interop test")
	}

	t.Logf("Go repo: %s", goRepo)
	t.Logf("TS repo:  %s", tsRepo)

	// ── 1. Generate identities ──────────────────────────────────────────────
	bob, err := pqc.GenerateIdentity(42, 3, 10)
	must(t, err, "GenerateIdentity bob")

	alice, err := pqc.GenerateIdentity(7, 1, 0)
	must(t, err, "GenerateIdentity alice")

	bundleWire, err := pqc.MakeBundleWire(bob, 0, 0)
	must(t, err, "MakeBundleWire")
	bundle, err := pqc.ParseBundleWire(bundleWire)
	must(t, err, "ParseBundleWire")

	aliceSess, initResult, err := pqc.CreateSessionInitiator(alice, bundle)
	must(t, err, "CreateSessionInitiator")

	pkmWire := buildInteropPKMWire(alice, bundle, initResult)
	pkmBytes := pqc.MarshalPreKeyMessageWire(pkmWire)

	// ── 2. Encrypt 5 messages as Alice (Go) ─────────────────────────────────
	plaintexts := []string{
		"hello from Go (message 1)",
		"second message from Go",
		"third — ratchet advance test",
		"fourth message",
		"fifth and final message from Go",
	}
	var msgWires []string
	for _, pt := range plaintexts {
		enc, err := aliceSess.EncryptMessage([]byte(pt))
		must(t, err, "EncryptMessage")
		wire := buildInteropSignedMsgWire(aliceSess, enc)
		msgWires = append(msgWires, hex.EncodeToString(wire))
	}

	// ── 3. Write fixture for TS ──────────────────────────────────────────────
	bobJSON, err := json.Marshal(bob)
	must(t, err, "marshal bob")

	type fixture struct {
		BobIdentityJSON  string   `json:"bobIdentityJSON"`
		PreKeyMessageHex string   `json:"preKeyMessageHex"`
		GoToTSMessages   []string `json:"goToTSMessages"`
		Plaintexts       []string `json:"plaintexts"`
	}
	fix := fixture{
		BobIdentityJSON:  string(bobJSON),
		PreKeyMessageHex: hex.EncodeToString(pkmBytes),
		GoToTSMessages:   msgWires,
		Plaintexts:       plaintexts,
	}
	fixData, err := json.MarshalIndent(fix, "", "  ")
	must(t, err, "marshal fixture")

	tmpDir := t.TempDir()
	fixturePath := filepath.Join(tmpDir, "fixture.json")
	replyPath := filepath.Join(tmpDir, "reply.json")
	must(t, os.WriteFile(fixturePath, fixData, 0o644), "write fixture")

	// ── 4. Run TS verifier ──────────────────────────────────────────────────
	cmd := exec.Command(node, tsScript, fixturePath, replyPath)
	cmd.Dir = tsRepo
	out, err := cmd.CombinedOutput()
	t.Logf("TS output:\n%s", out)
	if err != nil {
		t.Fatalf("TS interop_verify.mjs failed: %v\n%s", err, out)
	}

	// ── 5. Decrypt TS→Go replies ────────────────────────────────────────────
	replyData, err := os.ReadFile(replyPath)
	must(t, err, "read reply")
	var reply struct {
		TSToGoMessages  []string `json:"tsToGoMessages"`
		ReplyPlaintexts []string `json:"replyPlaintexts"`
	}
	must(t, json.Unmarshal(replyData, &reply), "unmarshal reply")

	if len(reply.TSToGoMessages) == 0 {
		t.Fatal("TS sent no reply messages")
	}
	for i, msgHex := range reply.TSToGoMessages {
		msgBytes, err := hex.DecodeString(msgHex)
		if err != nil {
			t.Fatalf("reply %d: decode hex: %v", i, err)
		}
		sm, err := pqc.UnmarshalSignedMessage(msgBytes)
		if err != nil {
			t.Fatalf("reply %d: UnmarshalSignedMessage: %v", i, err)
		}
		plaintext, err := aliceSess.DecryptSignedMessage(sm)
		if err != nil {
			t.Fatalf("reply %d: DecryptSignedMessage: %v", i, err)
		}
		want := reply.ReplyPlaintexts[i]
		if !bytes.Equal(plaintext, []byte(want)) {
			t.Fatalf("reply %d: got %q, want %q", i, plaintext, want)
		}
		t.Logf("reply %d ✓: %q", i, plaintext)
	}
	t.Logf("interop: Go→TS %d messages, TS→Go %d replies — all verified",
		len(plaintexts), len(reply.TSToGoMessages))
}

// ── wire helpers ─────────────────────────────────────────────────────────────

func buildInteropPKMWire(alice *pqc.Identity, bundle *pqc.PreKeyBundle, result *pqc.KEMInitiatorResult) *pqc.PreKeyMessageWire {
	var signingPub [pqc.DSAPublicKeySize]byte
	copy(signingPub[:], pqc.DSAPublicKeyBytes(alice.SigningKey.Public))

	var exchangeKeySig [pqc.DSASignatureSize]byte
	copy(exchangeKeySig[:], alice.ExchangeKeySignature)

	var exchangePub [pqc.HybridPublicKeySize]byte
	copy(exchangePub[:], alice.ExchangeKey.Public[:])

	var baseKey [pqc.HybridPublicKeySize]byte
	copy(baseKey[:], result.EphemeralKP.Public[:])

	var ct1 [pqc.HybridCiphertextSize]byte
	copy(ct1[:], result.CT1[:])

	var ct2 [pqc.HybridCiphertextSize]byte
	copy(ct2[:], result.CT2[:])

	var initiatorSig [pqc.DSASignatureSize]byte
	copy(initiatorSig[:], result.InitiatorSig)

	opkIndex := pqc.NoOneTimePreKey
	hasCT4 := false
	var ct4 [pqc.HybridCiphertextSize]byte
	if bundle.OneTimePreKeyIndex >= 0 {
		opkIndex = uint32(bundle.OneTimePreKeyIndex)
		hasCT4 = true
		copy(ct4[:], result.CT4[:])
	}

	return &pqc.PreKeyMessageWire{
		RegistrationID:     uint32(alice.ID),
		SignedPreKeyIndex:  uint32(bundle.SignedPreKeyIndex),
		OneTimePreKeyIndex: opkIndex,
		SigningPub:         signingPub,
		ExchangeKeySig:     exchangeKeySig,
		ExchangePub:        exchangePub,
		BaseKey:            baseKey,
		CT1:                ct1,
		CT2:                ct2,
		HasCT4:             hasCT4,
		CT4:                ct4,
		InitiatorSig:       initiatorSig,
	}
}

func buildInteropSignedMsgWire(sess *pqc.Session, enc *pqc.EncryptResult) []byte {
	inner := pqc.MarshalMessageProtocol(&pqc.ParsedMessageProtocol{
		Counter:          uint32(enc.Counter),
		SenderRatchetPub: enc.NewRatchetPub,
		RatchetCT:        enc.RatchetCT,
		CipherText:       enc.Ciphertext,
	})
	return pqc.MarshalSignedMessage(inner, enc.HMACKey,
		sess.AD, sess.InitiatorSigningKeyBytes, sess.ResponderSigningKeyBytes)
}
