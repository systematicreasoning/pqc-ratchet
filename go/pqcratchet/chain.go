package pqcratchet

// chain.go implements the symmetric ratchet (sending/receiving chains) and
// message key derivation.
//
// The symmetric ratchet uses only HMAC-SHA-256 and HKDF-SHA-256, which are
// already quantum-safe. No changes to the symmetric layer were needed for the
// PQC migration — all changes are in the KEM ratchet layer (session.go).
//
// KEMRatchetStep holds *HybridKEMPublicKey (the peer's ratchet encapsulation
// key) rather than the ECDH public key used in the classical implementation.

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ─── Symmetric chain ─────────────────────────────────────────────────────────

// SymmetricChain implements a sending or receiving chain.
// Each Step() call advances the chain and returns fresh cipher key material.
type SymmetricChain struct {
	// RootKey is the current chain key (32 bytes). It is exported to support
	// session serialisation and interop testing.
	//
	// Forward-secrecy constraint: do NOT retain references to old RootKey
	// values after Step() has been called. Each Step() replaces RootKey with
	// a new slice derived from the old one. Retaining an old value allows
	// computation of all subsequent cipher keys from that point forward,
	// breaking forward secrecy for those messages.
	//
	// Note: "RootKey" here is the per-chain key, not the session root key
	// (Session.RootKey). The name follows the original 2key-ratchet convention.
	RootKey []byte
	Counter int
}

// Step advances the chain and returns the cipher key for the current position.
//
//	cipherKey    = HMAC-SHA256(chainKey, 0x01)
//	nextChainKey = HMAC-SHA256(chainKey, 0x02)
func (c *SymmetricChain) Step() (cipherKey []byte, err error) {
	cipherKey = hmacSHA256(c.RootKey, cipherKeyKDFInput[:])
	nextRoot := hmacSHA256(c.RootKey, rootKeyKDFInput[:])
	c.RootKey = nextRoot
	c.Counter++
	return cipherKey, nil
}

// ─── Message key derivation ──────────────────────────────────────────────────

// MessageKeys holds the per-message AES-GCM key, nonce, and outer HMAC key.
//
// All three fields are sub-slices of a single 76-byte allocation.
// Treat them as read-only: writing to any field modifies the shared
// backing array. To zero key material, zero all 76 bytes directly.
//
// Two levels of authentication per message:
//
//  1. GCM tag (16 bytes, internal to AESGCMEncrypt/Decrypt): authenticates the
//     plaintext and the session identity. The session AD (Encode(IK_A.ex) ||
//     Encode(IK_B.ex)) is passed as GCM additionalData, so the tag covers both
//     the ciphertext and the specific Alice↔Bob session. A ciphertext from one
//     session cannot be opened in a different session.
//
//  2. HMACKey (outer HMAC, used by MarshalSignedMessage): signs the entire
//     MessageProtocol wire frame plus AD and session role signing keys. This
//     covers fields GCM does not see — the EpochRatchetCT, counter, sender
//     ratchet pub, and role signing keys. The two layers are complementary:
//     GCM authenticates plaintext + session identity; the outer HMAC
//     authenticates the complete wire frame and role membership.
type MessageKeys struct {
	AESKey  []byte // 32 bytes — AES-256-GCM key
	Nonce   []byte // 12 bytes — AES-GCM nonce (KDF-derived, unique per message)
	HMACKey []byte // 32 bytes — outer session HMAC-SHA-256 key
}

// DeriveMessageKeys derives MessageKeys from a cipher key via HKDF.
//
// This is the message key derivation step of the FS-AEAD (Forward-Secure AEAD)
// component in the ACD19 modular framework [1]. FS-AEAD requires that each
// message use a fresh key and that past keys are deleted after use.
// SymmetricChain.Step() ensures both: it derives a fresh cipherKey from the
// current chain state and advances the chain, making the old key unreachable.
//
//	HKDF(cipherKey, salt=0×32, info="pqcratchet/v1/MessageKeys") → 76 bytes
//	aesKey  = bytes[0:32]   — AES-256-GCM key
//	nonce   = bytes[32:44]  — 12-byte GCM nonce
//	hmacKey = bytes[44:76]  — outer session HMAC-SHA-256 key
//
// Nonce uniqueness: each message derives its cipher key from a distinct
// symmetric chain Step(), so nonce reuse is impossible.
//
//	[1] Alwen, Coretti, Dodis. EUROCRYPT 2019. https://eprint.iacr.org/2018/1037
func DeriveMessageKeys(cipherKey []byte) (*MessageKeys, error) {
	// Zero salt, 32 bytes (SHA-256 output length).
	//
	// RFC 5869 §2.2 specifies: if salt is not provided, it is set to a string
	// of HashLen zeros. We follow this explicitly. The Double Ratchet spec §2.3
	// recommends zero-length (equivalently HashLen-zero) salt for message key
	// derivation because cipherKey is already pseudorandom — Extract's role is
	// key separation via the info label, not entropy extraction.
	// https://www.rfc-editor.org/rfc/rfc5869#section-2.2
	salt := make([]byte, 32)
	r := hkdf.New(sha256.New, cipherKey, salt, infoMessageKeys)

	// Derive all 76 bytes in a single read.
	buf := make([]byte, 76)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return &MessageKeys{
		AESKey:  buf[0:32],
		Nonce:   buf[32:44],
		HMACKey: buf[44:76],
	}, nil
}

// ─── KEM ratchet step ─────────────────────────────────────────────────────────

// KEMRatchetStep holds state for one step of the KEM ratchet.
//
// In the KEM ratchet:
//   - RemoteRatchetKey is the peer's current KEM encapsulation key.
//   - EpochRatchetCT is the ciphertext that initiates this sending epoch.
//     It is included in every message of the epoch (HasRatchetCT=1 in the
//     MessageProtocol wire format) so that any message can bootstrap the
//     receiver's chain regardless of arrival order. This enables out-of-order
//     delivery without requiring the first message to arrive first.
//
// Wire cost: EpochRatchetCT adds 1120 bytes to every message after the first
// in an epoch. This is the deliberate tradeoff for reliable out-of-order
// delivery. Applications with strict bandwidth constraints may wish to require
// in-order delivery and set EpochRatchetCT only on the first message.
type KEMRatchetStep struct {
	RemoteRatchetKey *HybridKEMPublicKey // peer's ratchet encapsulation key
	EpochRatchetCT   *HybridKEMCiphertext // CT that opened this sending epoch
	SendingChain     *SymmetricChain
	ReceivingChain   *SymmetricChain
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
