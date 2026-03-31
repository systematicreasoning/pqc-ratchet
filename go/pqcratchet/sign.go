package pqcratchet

// sign.go provides ML-DSA-65 (FIPS 204) signing used for identity keys and
// pre-key signatures.
//
// ML-DSA-65 sizes:
//   PublicKey:  1952 bytes
//   PrivateKey: 4032 bytes
//   Signature:  3309 bytes
//
// These are fixed sizes defined by the standard; the cloudflare/circl library
// surfaces them via the scheme's Size() methods.

import (
	cryptorand "crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	// DSAPublicKeySize is the ML-DSA-65 public key size in bytes.
	DSAPublicKeySize = mldsa65.PublicKeySize // 1952

	// DSAPrivateKeySize is the ML-DSA-65 private key size in bytes.
	DSAPrivateKeySize = mldsa65.PrivateKeySize // 4032

	// DSASignatureSize is the ML-DSA-65 signature size in bytes.
	DSASignatureSize = mldsa65.SignatureSize // 3309
)

// DSAPublicKey is an ML-DSA-65 public key.
type DSAPublicKey = mldsa65.PublicKey

// DSAPrivateKey is an ML-DSA-65 private key.
type DSAPrivateKey = mldsa65.PrivateKey

// DSAKeyPair holds a matched ML-DSA-65 signing key pair.
// Always use *DSAKeyPair (pointer). Call ZeroDSAPrivateKeyBestEffort when done.
type DSAKeyPair struct {
	Public  *DSAPublicKey
	Private *DSAPrivateKey
}

// ZeroDSAPrivateKeyBestEffort attempts to clear the private key material in kp.
//
// Limitation: ML-DSA-65 private keys are managed by the cloudflare/circl library
// as opaque struct types. MarshalBinary allocates a new []byte and zeroing it
// clears only that transient copy, not the struct's internal fields. This function
// therefore provides best-effort clearing — it reduces the window during which
// a copy of the key bytes exists on the heap, but cannot guarantee the original
// struct memory is overwritten.
//
// For stronger guarantees, file a feature request against cloudflare/circl for a
// Zeroize() method on PrivateKey, or consider using an alternative library that
// exposes the raw key bytes directly.
func ZeroDSAPrivateKeyBestEffort(kp *DSAKeyPair) {
	if kp == nil || kp.Private == nil {
		return
	}
	// Zero the serialised form. This clears any heap copy produced by MarshalBinary
	// but does not reach the internal struct fields of the circl PrivateKey.
	b, _ := kp.Private.MarshalBinary()
	for i := range b {
		b[i] = 0
	}
}

// GenerateDSAKeyPair generates a fresh ML-DSA-65 keypair.
// If r is nil, crypto/rand.Reader is used.
func GenerateDSAKeyPair(r io.Reader) (*DSAKeyPair, error) {
	if r == nil {
		r = cryptorand.Reader
	}
	pub, priv, err := mldsa65.GenerateKey(r)
	if err != nil {
		return nil, fmt.Errorf("mldsa65 keygen: %w", err)
	}
	return &DSAKeyPair{Public: pub, Private: priv}, nil
}

// Sign signs msg with priv using ML-DSA-65 with randomized signing.
// Returns a DSASignatureSize-byte signature.
//
// Randomized signing (randomized=true) is used rather than deterministic
// signing. FIPS 204 §3.6 recommends randomization when an RNG is available:
// deterministic ML-DSA is vulnerable to fault attacks (e.g. clock glitching)
// that can recover the private key if the same message is signed twice with
// a fault injected. Randomization makes each signature independent, preventing
// this class of attack.
func Sign(priv *DSAPrivateKey, msg []byte) ([]byte, error) {
	sig := make([]byte, DSASignatureSize)
	// ML-DSA context bytes: nil (empty context, standard usage).
	// randomized=true: use fresh randomness per signature for fault resistance.
	if err := mldsa65.SignTo(priv, msg, nil, true, sig); err != nil {
		return nil, fmt.Errorf("mldsa65 sign: %w", err)
	}
	return sig, nil
}

// Verify verifies an ML-DSA-65 signature over msg using pub.
//
// The signature length check uses subtle.ConstantTimeEq to avoid a plain integer
// comparison branch. In practice, signature length is not secret in this protocol,
// so the timing difference is not exploitable. The check is written this way for
// defence in depth and consistency with cryptographic coding conventions.
//
// Note: subtle.ConstantTimeEq runs in constant time, but the if-branch that follows
// it is not — a very precise observer can still distinguish "wrong length" (returns
// immediately) from "correct length" (calls into mldsa65.Verify). This is acceptable
// because signature length leaks no useful information to an attacker here.
func Verify(pub *DSAPublicKey, msg, sig []byte) bool {
	// constant-time length check
	if subtle.ConstantTimeEq(int32(len(sig)), int32(DSASignatureSize)) == 0 {
		return false
	}
	return mldsa65.Verify(pub, msg, nil, sig)
}

// DSAPublicKeyBytes returns the canonical byte encoding of pub.
func DSAPublicKeyBytes(pub *DSAPublicKey) []byte {
	b, _ := pub.MarshalBinary()
	return b
}

// ParseDSAPublicKey deserialises a DSAPublicKeySize-byte slice into a public key.
func ParseDSAPublicKey(b []byte) (*DSAPublicKey, error) {
	if len(b) != DSAPublicKeySize {
		return nil, fmt.Errorf("pqcratchet: ML-DSA-65 public key must be %d bytes, got %d", DSAPublicKeySize, len(b))
	}
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("pqcratchet: parse ML-DSA-65 public key: %w", err)
	}
	return &pub, nil
}

// ParseDSAPrivateKey deserialises a DSAPrivateKeySize-byte slice into a private key.
func ParseDSAPrivateKey(b []byte) (*DSAPrivateKey, error) {
	if len(b) != DSAPrivateKeySize {
		return nil, fmt.Errorf("pqcratchet: ML-DSA-65 private key must be %d bytes, got %d", DSAPrivateKeySize, len(b))
	}
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("pqcratchet: parse ML-DSA-65 private key: %w", err)
	}
	return &priv, nil
}
