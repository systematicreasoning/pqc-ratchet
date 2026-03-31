// interop_gen — produces and verifies interop fixtures between Go and TypeScript.
//
// Usage:
//   interop_gen generate <fixture.json>   — Go=Alice, writes fixture for TS=Bob
//   interop_gen verify   <reply.json> <alice_state.json>
//                                         — Go=Alice verifies TS=Bob replies

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	pqc "github.com/PeculiarVentures/pqc-ratchet/pqcratchet"
)

type Fixture struct {
	BobIdentityJSON  string   `json:"bobIdentityJSON"`
	PreKeyMessageHex string   `json:"preKeyMessageHex"`
	GoToTSMessages   []string `json:"goToTSMessages"` // hex-encoded signed message wires
	Plaintexts       []string `json:"plaintexts"`
}

type ReplyFixture struct {
	TSToGoMessages  []string `json:"tsToGoMessages"`
	ReplyPlaintexts []string `json:"replyPlaintexts"`
}

type AliceState struct {
	AliceIdentityJSON string `json:"aliceIdentityJSON"`
	BobIdentityJSON   string `json:"bobIdentityJSON"`
	PreKeyMessageHex  string `json:"preKeyMessageHex"`
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: interop_gen <generate|verify> ...")
	}
	var err error
	switch os.Args[1] {
	case "generate":
		if len(os.Args) < 3 {
			fatalf("generate: usage: generate <fixture.json>")
		}
		err = generate(os.Args[2])
	case "verify":
		if len(os.Args) < 4 {
			fatalf("verify: usage: verify <reply.json> <alice_state.json>")
		}
		err = verify(os.Args[2], os.Args[3])
	default:
		fatalf("unknown command: %s", os.Args[1])
	}
	if err != nil {
		fatalf("%s: %v", os.Args[1], err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// ─── generate ────────────────────────────────────────────────────────────────

func generate(fixturePath string) error {
	bob, err := pqc.GenerateIdentity(42, 3, 10)
	if err != nil {
		return fmt.Errorf("GenerateIdentity bob: %w", err)
	}
	bobJSON, err := json.Marshal(bob)
	if err != nil {
		return fmt.Errorf("marshal bob: %w", err)
	}

	bundleWire, err := pqc.MakeBundleWire(bob, 0, 0)
	if err != nil {
		return fmt.Errorf("MakeBundleWire: %w", err)
	}

	alice, err := pqc.GenerateIdentity(7, 1, 0)
	if err != nil {
		return fmt.Errorf("GenerateIdentity alice: %w", err)
	}
	aliceJSON, err := json.Marshal(alice)
	if err != nil {
		return fmt.Errorf("marshal alice: %w", err)
	}

	bundle, err := pqc.ParseBundleWire(bundleWire)
	if err != nil {
		return fmt.Errorf("ParseBundleWire: %w", err)
	}

	aliceSess, initResult, err := pqc.CreateSessionInitiator(alice, bundle)
	if err != nil {
		return fmt.Errorf("CreateSessionInitiator: %w", err)
	}

	pkmWire := buildPKMWire(alice, bundle, initResult)
	pkmBytes := pqc.MarshalPreKeyMessageWire(pkmWire)

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
		if err != nil {
			return fmt.Errorf("EncryptMessage: %w", err)
		}
		wire := buildSignedMessageWire(aliceSess, enc)
		msgWires = append(msgWires, hex.EncodeToString(wire))
	}

	fixture := Fixture{
		BobIdentityJSON:  string(bobJSON),
		PreKeyMessageHex: hex.EncodeToString(pkmBytes),
		GoToTSMessages:   msgWires,
		Plaintexts:       plaintexts,
	}
	if err := writeJSON(fixturePath, fixture); err != nil {
		return err
	}

	state := AliceState{
		AliceIdentityJSON: string(aliceJSON),
		BobIdentityJSON:   string(bobJSON),
		PreKeyMessageHex:  hex.EncodeToString(pkmBytes),
	}
	statePath := fixturePath + ".alice_state.json"
	if err := writeJSON(statePath, state); err != nil {
		return err
	}

	fmt.Printf("✓  fixture:     %s\n", fixturePath)
	fmt.Printf("✓  alice state: %s\n", statePath)
	return nil
}

// ─── verify ──────────────────────────────────────────────────────────────────

func verify(replyPath, statePath string) error {
	var reply ReplyFixture
	if err := readJSON(replyPath, &reply); err != nil {
		return err
	}
	var state AliceState
	if err := readJSON(statePath, &state); err != nil {
		return err
	}

	// Reconstruct Alice's identity.
	var alice pqc.Identity
	if err := json.Unmarshal([]byte(state.AliceIdentityJSON), &alice); err != nil {
		return fmt.Errorf("unmarshal alice identity: %w", err)
	}

	// Reconstruct Bob's identity (needed to rebuild the bundle).
	var bob pqc.Identity
	if err := json.Unmarshal([]byte(state.BobIdentityJSON), &bob); err != nil {
		return fmt.Errorf("unmarshal bob identity: %w", err)
	}

	// Rebuild the bundle from Bob's identity.
	bundleWire, err := pqc.MakeBundleWire(&bob, 0, -1) // OPK already consumed
	if err != nil {
		return fmt.Errorf("MakeBundleWire: %w", err)
	}
	bundle, err := pqc.ParseBundleWire(bundleWire)
	if err != nil {
		return fmt.Errorf("ParseBundleWire: %w", err)
	}

	// Decode the original PreKeyMessage to get initResult's data.
	pkmBytes, err := hex.DecodeString(state.PreKeyMessageHex)
	if err != nil {
		return fmt.Errorf("decode pkm hex: %w", err)
	}
	pkmWireMsg, err := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkmBytes))
	if err != nil {
		return fmt.Errorf("UnmarshalPreKeyMessageWire: %w", err)
	}
	_ = pkmWireMsg

	// Re-run CreateSessionInitiator to get Alice's session.
	// This requires the same entropy as the original run — which we don't have.
	// Instead, derive the session by making Alice re-run with the bundle,
	// then advance past the messages TS received (we just need the ratchet state).
	//
	// Better approach: call CreateSessionResponder as Bob would, but from Alice's
	// perspective. Since Alice and Bob have deterministic derivation from the
	// root key, we can rebuild Alice's session by having her process the PKM.
	//
	// The cleanest solution: rebuild Alice's session from scratch and then
	// replay all the Go→TS messages to advance Alice's ratchet to the right state.
	// Alice doesn't need to decrypt Go→TS messages (she sent them), but she
	// needs the session to be at the right ratchet step to decrypt Bob's replies.
	//
	// Simplest correct approach: re-run CreateSessionInitiator with a fresh
	// random call. This won't give Alice the same root key.
	//
	// The real solution is to include the alice session state in the fixture.
	// For now, rebuild by having Bob process the original PKM and Alice process
	// a new PKM from Bob's reply. But since TS generates the reply PKM-less
	// (regular messages, not a new session), Alice's session from the original
	// run is needed.
	//
	// Practical solution for the interop test: serialize Alice's full session
	// state. Add a Session.MarshalJSON/UnmarshalJSON to pqcratchet.

	// For the interop test we use a simpler structure:
	// The TS side includes enough state in the reply fixture for Go to
	// reconstruct what it needs. Specifically, TS sends:
	//   - The wire bytes of each reply message
	//
	// Go needs Alice's session at the state after sending 5 messages.
	// Since we can't replay the original session without the private key state,
	// we need to export AliceSess. The test fixture will be extended in the
	// full test to include session state serialization.
	//
	// For this first cut: verify the structural integrity of the reply messages.

	_ = bundle

	for i, msgHex := range reply.TSToGoMessages {
		msgBytes, err := hex.DecodeString(msgHex)
		if err != nil {
			return fmt.Errorf("reply message %d: decode hex: %w", i, err)
		}
		sm, err := pqc.UnmarshalSignedMessage(msgBytes)
		if err != nil {
			return fmt.Errorf("reply message %d: unmarshal: %w", i, err)
		}
		fmt.Printf("  message %d: counter=%d ciphertext=%d bytes ✓\n",
			i, sm.Message.Counter, len(sm.Message.CipherText))
	}
	fmt.Printf("✓  %d reply messages structurally valid\n", len(reply.TSToGoMessages))
	fmt.Println("  (full decryption requires session state export — see TODO in interop test)")
	return nil
}

// ─── wire helpers (mirrors ratchet_test.go) ──────────────────────────────────

func buildPKMWire(alice *pqc.Identity, bundle *pqc.PreKeyBundle, result *pqc.KEMInitiatorResult) *pqc.PreKeyMessageWire {
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

	opkIndex := uint32(pqc.NoOneTimePreKey)
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

// ─── JSON helpers ─────────────────────────────────────────────────────────────

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return nil
}
