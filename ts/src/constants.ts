/**
 * constants.ts — wire sizes and HKDF domain-separation labels.
 *
 * These values MUST match the Go implementation exactly.
 * Any change here breaks wire compatibility.
 */

// ML-KEM-768 sizes (FIPS 203)
export const MLKEM_PUBLIC_KEY_SIZE = 1184;
export const MLKEM_KEY_SEED_SIZE = 64;       // d || z seed stored instead of expanded key
export const MLKEM_CIPHERTEXT_SIZE = 1088;
export const MLKEM_ENCAP_SEED_SIZE = 32;
export const MLKEM_SHARED_KEY_SIZE = 32;

// X25519 sizes (RFC 7748)
export const X25519_KEY_SIZE = 32;

// Hybrid KEM wire sizes
export const HYBRID_PUBLIC_KEY_SIZE = MLKEM_PUBLIC_KEY_SIZE + X25519_KEY_SIZE;   // 1216
export const HYBRID_PRIVATE_KEY_SIZE = MLKEM_KEY_SEED_SIZE + X25519_KEY_SIZE;   // 96
export const HYBRID_CIPHERTEXT_SIZE = MLKEM_CIPHERTEXT_SIZE + X25519_KEY_SIZE;  // 1120

// ML-DSA-65 sizes (FIPS 204)
export const DSA_PUBLIC_KEY_SIZE = 1952;
export const DSA_PRIVATE_KEY_SIZE = 4032;
export const DSA_SIGNATURE_SIZE = 3309;

// Symmetric sizes
export const AES_GCM_NONCE_SIZE = 12;
export const AES_GCM_TAG_SIZE = 16;

// Session limits
export const MAX_SKIP = 1000;
export const MAX_RATCHET_STACK_SIZE = 20;
export const MAX_OLD_EPOCH_SKIP = 50;

// HKDF info labels — MUST match pqcratchet/v1/... strings in Go
export const INFO_KEM_INIT = new TextEncoder().encode("pqcratchet/v1/KEMInit");
export const INFO_RATCHET = new TextEncoder().encode("pqcratchet/v1/Ratchet");
export const INFO_MESSAGE_KEYS = new TextEncoder().encode("pqcratchet/v1/MessageKeys");
export const INFO_HYBRID_KEM = new TextEncoder().encode("pqcratchet/v1/HybridKEM");

// Chain KDF diversifiers
export const CIPHER_KEY_KDF_INPUT = new Uint8Array([0x01]);
export const ROOT_KEY_KDF_INPUT = new Uint8Array([0x02]);

// Wire protocol version
export const WIRE_VERSION = 0x01;

// Max ciphertext size (1 MiB)
export const MAX_CIPHERTEXT_SIZE = 1024 * 1024;
