package pqcratchet

// x3dh.go implements the KEM-based X3DH key agreement.
//
// The original X3DH protocol uses DH computations to establish a shared secret.
// Since ML-KEM is a KEM (encapsulate/decapsulate), not a DH primitive, we
// restructure the computation while preserving the forward secrecy and
// authentication properties.
//
// Alice (initiator) side — AuthenticateA:
//
//	(ct1, ss1) = KEM.Encap(rnd, SPK_B)          // signed pre-key: mutual auth + FS
//	(ct2, ss2) = KEM.Encap(rnd, IK_B.ex)        // identity key: mutual auth
//	EK_A       = KEM.GenerateKeyPair(rnd)        // ephemeral keypair: becomes initial ratchet key
//	SK = HKDF(0xFF×32 || ss1 || ss2)            // without OPK
//
//	With one-time pre-key (OPK_B):
//	(ct4, ss3) = KEM.Encap(rnd, OPK_B)         // forward secrecy against SPK compromise
//	SK = HKDF(0xFF×32 || ss1 || ss2 || ss3)
//
//	Sent to Bob: { IK_A.ex, EK_A.pub, ct1, ct2, [ct4], Sig(IK_A.sig, transcript) }
//
// Bob (responder) side — AuthenticateB:
//
//	verify Sig(IK_A.sig, transcript) before decapsulating
//	ss1 = KEM.Decap(SPK_B.sk, ct1)
//	ss2 = KEM.Decap(IK_B.ex.sk, ct2)
//	[ss3 = KEM.Decap(OPK_B.sk, ct4)]
//	SK  = HKDF(0xFF×32 || ss1 || ss2 [|| ss3])
//
// The ephemeral keypair EK_A is sent to Bob as BaseKey and becomes Alice's
// initial ratchet encapsulation key for the Double Ratchet.
//
// # Deniability tradeoff
//
// The original X3DH provides cryptographic deniability because DH is symmetric:
// anyone with the public keys can compute the same SK, so a transcript doesn't
// prove which party sent it (X3DH spec §4.4).
//
// This KEM-based variant loses deniability. Because KEMs don't provide implicit
// authentication (anyone can encapsulate against Bob's public keys), Alice must
// explicitly sign the transcript with ML-DSA-65 to authenticate herself. This
// signature is non-repudiable — Alice cannot plausibly deny sending the initial
// message. The X3DH spec §4.5 warns explicitly against replacing DH-based
// mutual authentication with signatures for exactly this reason. This is a
// necessary tradeoff in the PQC setting, not a flaw, but applications with
// strong deniability requirements should note it.
//
// # State of the art for PQ X3DH
//
// Several approaches to this tradeoff exist in the literature:
//
// Signal's PQXDH (Kret, Schmidt 2023) — the deployed production protocol —
// takes a hybrid approach: it keeps the full classical X3DH intact and injects
// a KEM shared secret alongside the DH outputs. This preserves classical
// deniability and backward compatibility but authentication still relies on
// classical hardness (discrete log), not PQ hardness. See:
// https://signal.org/docs/specifications/pqxdh/
//
// Hashimoto et al. (PKC 2022, ePrint 2021/616) — the approach this package
// follows — replaces DH entirely with KEM + signature and proves security
// under PQ assumptions. It shows how to progressively restore deniability
// using ring signatures or NIZKs at the cost of additional complexity.
//
// Brendel et al. SPQR (PKC 2022, ePrint 2021/769) achieves deniability using
// designated-verifier signatures. K-Waay (Collins et al., ASIACCS 2025,
// ePrint 2024/120) achieves deniability using a split-KEM without ring
// signatures and is currently the most efficient deniable construction.
//
// This package implements the Hashimoto et al. direct-signature variant
// (weakly deniable per their terminology) because it maps cleanly to NIST
// standard primitives (ML-KEM-768, ML-DSA-65) without requiring ring
// signatures or NIZKs. Applications requiring deniability should use PQXDH
// or evaluate K-Waay.

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KEMInitiatorResult is returned by AuthenticateA.
// The ciphertexts and InitiatorSig must be sent to the responder inside the PreKeyMessage.
type KEMInitiatorResult struct {
	// RootKey is the derived 32-byte session root key.
	RootKey []byte

	// EphemeralKP is Alice's ephemeral KEM keypair.
	// EphemeralKP.Public is sent in the PreKeyMessage as the BaseKey.
	// EphemeralKP.Private becomes Alice's initial ratchet key.
	EphemeralKP *HybridKEMKeyPair

	// CT1: encap against Bob's signed pre-key (for ss1).
	CT1 *HybridKEMCiphertext
	// CT2: encap against Bob's identity exchange key (for ss2).
	CT2 *HybridKEMCiphertext
	// CT4: encap against Bob's one-time pre-key (for ss3), nil if no OPK.
	CT4 *HybridKEMCiphertext

	// InitiatorSig is Alice's ML-DSA-65 signature over the X3DH transcript:
	//   CT1 || CT2 || EphemeralKP.Public || CT4 (if present)
	// This proves Alice holds the private key corresponding to her signing
	// public key, providing mutual authentication at session establishment.
	// Without this, any party with Bob's public bundle could impersonate Alice.
	InitiatorSig []byte
}

// AuthenticateA performs the X3DH key agreement from the initiator's side.
//
// This implements the KEM-based X3DH initiator protocol, following the structure
// of the X3DH specification [1] §3.3 adapted for KEMs as in Hashimoto et al. [2].
//
// Mutual authentication: Alice signs the X3DH transcript (IK_A.ex || CT1 || CT2 ||
// EK_A.pub [|| CT4]) with her ML-DSA-65 signing key. Bob verifies this
// signature against Alice's signing public key from the PreKeyMessage before
// accepting the session. Without this, any party holding Bob's public bundle
// could produce valid CT1/CT2 and impersonate Alice.
//
// Note: this construction provides authentication but NOT deniability.
// The ML-DSA-65 signature over the transcript is Alice-specific and cannot
// be produced by any other party, creating a non-repudiable record.
// See X3DH spec §4.4–4.5 for the original deniability discussion.
//
//	[1] https://signal.org/docs/specifications/x3dh/
//	[2] Hashimoto et al. PKC 2022. https://eprint.iacr.org/2021/616
//
// Parameters:
//   - initiatorSigningKey:   Alice's ML-DSA-65 signing private key (IK_A.sig)
//   - initiatorExchangePub:  Alice's KEM exchange public key (IK_A.ex)
//   - remoteIdentityExPub:   Bob's identity exchange public key (IK_B.ex)
//   - remoteSignedPreKeyPub: Bob's signed pre-key public key (SPK_B)
//   - remoteOneTimePreKeyPub: Bob's one-time pre-key public key (OPK_B), or nil
func AuthenticateA(
	initiatorSigningKey *DSAPrivateKey,
	initiatorExchangePub *HybridKEMPublicKey,
	remoteIdentityExPub *HybridKEMPublicKey,
	remoteSignedPreKeyPub *HybridKEMPublicKey,
	remoteOneTimePreKeyPub *HybridKEMPublicKey,
) (*KEMInitiatorResult, error) {
	return authenticateA(rand.Reader, initiatorSigningKey, initiatorExchangePub, remoteIdentityExPub, remoteSignedPreKeyPub, remoteOneTimePreKeyPub)
}

func authenticateA(
	r io.Reader,
	initiatorSigningKey *DSAPrivateKey,
	initiatorExchangePub *HybridKEMPublicKey,
	remoteIdentityExPub *HybridKEMPublicKey,
	remoteSignedPreKeyPub *HybridKEMPublicKey,
	remoteOneTimePreKeyPub *HybridKEMPublicKey,
) (*KEMInitiatorResult, error) {
	// KEM1 = Encap(SPK_B) → ss1
	ct1, ss1, err := Encapsulate(r, remoteSignedPreKeyPub)
	if err != nil {
		return nil, fmt.Errorf("x3dh KEM1 (SPK): %w", err)
	}

	// KEM2 = Encap(IK_B.ex) → ss2
	ct2, ss2, err := Encapsulate(r, remoteIdentityExPub)
	if err != nil {
		return nil, fmt.Errorf("x3dh KEM2 (IK): %w", err)
	}

	// Generate ephemeral KEM keypair EK_A.
	// EK_A.pub is sent as BaseKey and becomes the initial ratchet key.
	// EK_A contributes to forward secrecy: compromise of long-term keys after
	// session establishment cannot recover the session key because EK_A.priv
	// is discarded immediately after use.
	ephemeralKP, err := GenerateKEMKeyPair(r)
	if err != nil {
		return nil, fmt.Errorf("x3dh ephemeral keygen: %w", err)
	}

	// Optional KEM3 = Encap(OPK_B) → ss3 (one-time pre-key, if available)
	var ct4 *HybridKEMCiphertext
	var ss3 []byte
	if remoteOneTimePreKeyPub != nil {
		ct4, ss3, err = Encapsulate(r, remoteOneTimePreKeyPub)
		if err != nil {
			return nil, fmt.Errorf("x3dh KEM3 (OPK): %w", err)
		}
	}

	rootKey, err := deriveKEMRootKey(ss1, ss2, ss3)
	if err != nil {
		return nil, err
	}

	// Build the transcript to sign: IK_A.ex || CT1 || CT2 || EK_A.pub [|| CT4]
	// Including IK_A.ex explicitly binds Alice's exchange key into the signed
	// statement, giving a single unforgeable proof of her full identity.
	transcript := buildInitiatorTranscript(initiatorExchangePub, ct1, ct2, &ephemeralKP.Public, ct4)
	sig, err := Sign(initiatorSigningKey, transcript)
	if err != nil {
		return nil, fmt.Errorf("x3dh sign transcript: %w", err)
	}

	return &KEMInitiatorResult{
		RootKey:      rootKey,
		EphemeralKP:  ephemeralKP,
		CT1:          ct1,
		CT2:          ct2,
		CT4:          ct4,
		InitiatorSig: sig,
	}, nil
}

// AuthenticateB performs X3DH from the responder's side.
//
// Verifies Alice's ML-DSA-65 signature over the transcript before deriving
// the root key. Returns ErrInvalidSignature if verification fails — the
// caller must not proceed to create a session in that case.
//
//   - identityExchangePriv:  Bob's identity exchange private key (IK_B.ex)
//   - signedPreKeyPriv:      Bob's signed pre-key private key (SPK_B)
//   - oneTimePreKeyPriv:     Bob's one-time pre-key private key (OPK_B), or nil
//   - initiatorSigningPub:   Alice's ML-DSA-65 signing public key
//   - initiatorExchangePub:  Alice's KEM exchange public key (IK_A.ex)
//   - baseKey:               Alice's ephemeral KEM public key (EK_A.pub)
//   - ct1, ct2:              ciphertexts from Alice's X3DH computation
//   - ct4:                   one-time pre-key ciphertext, or nil
//   - initiatorSig:          Alice's signature over the transcript
func AuthenticateB(
	identityExchangePriv *HybridKEMPrivateKey,
	signedPreKeyPriv *HybridKEMPrivateKey,
	oneTimePreKeyPriv *HybridKEMPrivateKey,
	initiatorSigningPub *DSAPublicKey,
	initiatorExchangePub *HybridKEMPublicKey,
	baseKey *HybridKEMPublicKey,
	ct1, ct2 *HybridKEMCiphertext,
	ct4 *HybridKEMCiphertext,
	initiatorSig []byte,
) ([]byte, error) {
	// Step 1: verify Alice's signature over the transcript BEFORE decapsulating.
	// This prevents an attacker from using Bob's decapsulation as an oracle
	// against arbitrary ciphertexts. The transcript includes IK_A.ex to bind
	// Alice's exchange key directly into the signed statement.
	transcript := buildInitiatorTranscript(initiatorExchangePub, ct1, ct2, baseKey, ct4)
	if !Verify(initiatorSigningPub, transcript, initiatorSig) {
		return nil, ErrInvalidSignature
	}

	// ss1 = Decap(SPK_B.sk, ct1)
	ss1, err := Decapsulate(signedPreKeyPriv, ct1)
	if err != nil {
		return nil, fmt.Errorf("x3dh decap KEM1 (SPK): %w", err)
	}

	// ss2 = Decap(IK_B.ex, ct2)
	ss2, err := Decapsulate(identityExchangePriv, ct2)
	if err != nil {
		return nil, fmt.Errorf("x3dh decap KEM2 (IK): %w", err)
	}

	// Optional ss3 = Decap(OPK_B.sk, ct4)
	//
	// Guard both directions of mismatch: if Bob has an OPK private key but
	// Alice sent no CT4, or Alice sent CT4 but Bob has no OPK key, silently
	// skipping ss3 would derive a different root key than the other side,
	// causing silent session establishment failure at message decryption.
	// Return explicit errors so the mismatch surfaces immediately.
	var ss3 []byte
	switch {
	case oneTimePreKeyPriv != nil && ct4 != nil:
		ss3, err = Decapsulate(oneTimePreKeyPriv, ct4)
		if err != nil {
			return nil, fmt.Errorf("x3dh decap KEM3 (OPK): %w", err)
		}
	case oneTimePreKeyPriv != nil && ct4 == nil:
		return nil, fmt.Errorf("x3dh: have OPK private key but initiator sent no CT4")
	case oneTimePreKeyPriv == nil && ct4 != nil:
		return nil, fmt.Errorf("x3dh: initiator sent CT4 but no OPK private key available")
	}

	return deriveKEMRootKey(ss1, ss2, ss3)
}

// buildInitiatorTranscript constructs the byte string that Alice signs and Bob verifies.
//
// Layout: IKA.ex || CT1 || CT2 || BaseKey (EK_A.pub) [|| CT4]
//
// IKA.ex is included explicitly so the signature binds Alice's exchange key
// directly into the transcript. Without it, the binding is only indirect
// (via the separate ExchangeKeySig field in the wire format). Including it
// here provides a single unforgeable statement: "Alice, holding IK_A.sig.sk,
// produced these ciphertexts using IK_A.ex as her identity exchange key."
//
// All fields are fixed-size, so there is no length ambiguity.
func buildInitiatorTranscript(initiatorExchangePub *HybridKEMPublicKey, ct1, ct2 *HybridKEMCiphertext, baseKey *HybridKEMPublicKey, ct4 *HybridKEMCiphertext) []byte {
	size := HybridPublicKeySize + HybridCiphertextSize*2 + HybridPublicKeySize
	if ct4 != nil {
		size += HybridCiphertextSize
	}
	transcript := make([]byte, 0, size)
	transcript = append(transcript, initiatorExchangePub[:]...)
	transcript = append(transcript, ct1[:]...)
	transcript = append(transcript, ct2[:]...)
	transcript = append(transcript, baseKey[:]...)
	if ct4 != nil {
		transcript = append(transcript, ct4[:]...)
	}
	return transcript
}

// deriveKEMRootKey builds the key material and runs HKDF to produce the
// 32-byte root key.
//
// KM = 0xFF×32 || ss1 || ss2 [|| ss3]
// rootKey = HKDF-SHA256(KM, salt=0×32, info="pqcratchet/v1/KEMInit", length=32)
//
// The 0xFF prefix ensures KM is never all-zero and provides domain separation.
// The zero salt is intentional per the X3DH spec — the IKM itself carries
// all the entropy. Using a non-zero salt would require agreement on a value
// that isn't available at this point in the protocol.
func deriveKEMRootKey(ss1, ss2, ss3 []byte) ([]byte, error) {
	// Each shared secret must be exactly 32 bytes (the hybrid KEM combined output).
	// These assertions guard against a future refactor where Decapsulate might return
	// a wrong-length slice, which would silently weaken the IKM without error.
	if len(ss1) != 32 {
		return nil, fmt.Errorf("pqcratchet: x3dh ss1 must be 32 bytes, got %d", len(ss1))
	}
	if len(ss2) != 32 {
		return nil, fmt.Errorf("pqcratchet: x3dh ss2 must be 32 bytes, got %d", len(ss2))
	}
	if ss3 != nil && len(ss3) != 32 {
		return nil, fmt.Errorf("pqcratchet: x3dh ss3 (OPK) must be 32 bytes, got %d", len(ss3))
	}
	domainSep := make([]byte, 32)
	for i := range domainSep {
		domainSep[i] = 0xFF
	}

	keyMaterial := make([]byte, 0, 32+len(ss1)+len(ss2)+len(ss3))
	keyMaterial = append(keyMaterial, domainSep...)
	keyMaterial = append(keyMaterial, ss1...)
	keyMaterial = append(keyMaterial, ss2...)
	keyMaterial = append(keyMaterial, ss3...)

	salt := make([]byte, 32) // zero salt — RFC 5869 §2.2 default when no salt is available
	// https://www.rfc-editor.org/rfc/rfc5869#section-2.2
	// Per the X3DH spec §2.3, the IKM itself carries all entropy here;
	// a non-zero salt would require agreement on a value not present in the protocol.
	hkdfReader := hkdf.New(sha256.New, keyMaterial, salt, infoKEMInit)

	rootKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, rootKey); err != nil {
		return nil, fmt.Errorf("x3dh HKDF: %w", err)
	}
	return rootKey, nil
}
