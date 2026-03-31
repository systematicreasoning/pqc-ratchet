package pqcratchet

// crypto.go contains symmetric cryptographic primitives.
//
// AES-256-GCM with a KDF-derived nonce and session AD as additional data.
//
// Why GCM instead of CBC+HMAC:
//
//  1. Single AEAD primitive: GCM provides confidentiality and authentication in one
//     hardware-accelerated operation. CBC + HMAC requires two separate key derivations
//     and two passes over the data.
//
//  2. No padding: CBC requires PKCS7 padding, which adds 1–16 bytes and leaks
//     plaintext length at block granularity. GCM has no padding requirement.
//
//  3. Nonce uniqueness: the 12-byte nonce is derived from the message key KDF
//     alongside the AES key. Since each message uses a fresh cipher key from the
//     symmetric ratchet, nonce reuse is impossible — distinct messages → distinct
//     cipher keys → distinct nonces. The GCM safety boundary (2^32 encryptions
//     per key) is never approached.
//
//  4. Hardware acceleration: AES-GCM is accelerated via AES-NI + CLMUL on x86
//     and AES+PMULL on ARM. CBC encryption is sequential and cannot be parallelised.
//
// # GCM additional data
//
// The session AD (Encode(IK_A.ex) || Encode(IK_B.ex), per X3DH spec §3.3) is passed
// as GCM's additionalData parameter. This binds each ciphertext to the specific session
// identity at the AEAD layer itself, making the GCM tag self-sufficient:
//
//   - A ciphertext produced in Alice↔Bob session cannot be presented as valid in an
//     Alice↔Carol session, because the AD differs and GCM.Open will fail.
//   - The outer session HMAC (in MarshalSignedMessage) also covers AD, providing
//     defence in depth. The two layers are complementary.
//
// AES-256-GCM: key = 32 bytes, nonce = 12 bytes, tag = 16 bytes.

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	// AESGCMNonceSize is the standard AES-GCM nonce length.
	AESGCMNonceSize = 12
	// AESGCMTagSize is the AES-GCM authentication tag length.
	AESGCMTagSize = 16
)

// AESGCMEncrypt encrypts plaintext with AES-256-GCM using key and nonce.
// ad is the session associated data (AD = Encode(IK_A.ex) || Encode(IK_B.ex));
// it is authenticated but not encrypted. Pass the session's AD field — never nil.
// Returns ciphertext || tag (len = len(plaintext) + AESGCMTagSize).
func AESGCMEncrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("pqcratchet: nonce must be %d bytes, got %d", gcm.NonceSize(), len(nonce))
	}
	// Seal appends ciphertext + tag to dst. ad is authenticated but not encrypted.
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

// AESGCMDecrypt decrypts and authenticates ciphertext with AES-256-GCM.
// ad must be the same session associated data that was passed to AESGCMEncrypt.
// ciphertext is ciphertext_bytes || tag (tag is the last AESGCMTagSize bytes).
func AESGCMDecrypt(key, nonce, ad, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("pqcratchet: nonce must be %d bytes, got %d", gcm.NonceSize(), len(nonce))
	}
	if len(ciphertext) < AESGCMTagSize {
		return nil, ErrDecryptionFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
