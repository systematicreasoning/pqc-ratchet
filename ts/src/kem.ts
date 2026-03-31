/**
 * kem.ts — Hybrid KEM combining ML-KEM-768 (FIPS 203) and X25519.
 *
 * Wire layout for public key and ciphertext (must match Go exactly):
 *   HybridKEMPublicKey  = MLKEMPublicKey (1184 B)  || X25519PublicKey (32 B)           = 1216 B
 *   HybridKEMCiphertext = MLKEMCiphertext (1088 B)  || X25519EphemeralPublicKey (32 B)  = 1120 B
 *
 * Private key layout (in-memory only, never transmitted):
 *   HybridKEMPrivateKey = MLKEMSecretKey (2400 B)  || X25519PrivateScalar (32 B)       = 2432 B
 *
 * Note: the Go implementation stores a 64-byte ML-KEM seed and reconstructs
 * the expanded key on each operation. @noble/post-quantum requires the full
 * 2400-byte expanded secret key for decapsulation, so we store the expanded
 * form here. Both implementations are functionally equivalent and produce
 * identical wire output — the private key is never transmitted.
 *
 * Combined shared secret:
 *   SS = HKDF-SHA256(mlkem_ss || x25519_ss, salt=SHA256(recipientPub), info="pqcratchet/v1/HybridKEM")
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519";
import {
  HYBRID_PUBLIC_KEY_SIZE, HYBRID_CIPHERTEXT_SIZE,
  MLKEM_PUBLIC_KEY_SIZE, MLKEM_KEY_SEED_SIZE, MLKEM_CIPHERTEXT_SIZE,
  MLKEM_ENCAP_SEED_SIZE, X25519_KEY_SIZE, INFO_HYBRID_KEM,
} from "./constants.js";
import { sha256, hkdf, concat, randomBytes, zero } from "./crypto.js";

// ML-KEM-768 expanded secret key size (from noble)
const MLKEM_SECRET_KEY_SIZE = 2400;

// In-memory private key layout: MLKEMSecretKey (2400 B) || X25519PrivateScalar (32 B)
export const HYBRID_PRIVATE_KEY_SIZE_TS = MLKEM_SECRET_KEY_SIZE + X25519_KEY_SIZE; // 2432

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HybridKEMKeyPair {
  publicKey: Uint8Array;  // HYBRID_PUBLIC_KEY_SIZE (1216) bytes
  privateKey: Uint8Array; // HYBRID_PRIVATE_KEY_SIZE_TS (2432) bytes (in-memory expanded form)
}

// ─── Key generation ──────────────────────────────────────────────────────────

/**
 * generateKEMKeyPair generates a fresh hybrid KEM keypair.
 * If seed is provided (for deterministic tests), it must be 96 bytes:
 *   seed[0:64] = ML-KEM seed (d || z), seed[64:96] = X25519 private scalar.
 * In production, omit seed and crypto.getRandomValues is used.
 */
export function generateKEMKeyPair(seed?: Uint8Array): HybridKEMKeyPair {
  const mlkemSeed = seed ? seed.slice(0, MLKEM_KEY_SEED_SIZE) : randomBytes(MLKEM_KEY_SEED_SIZE);
  const x25519Priv = seed
    ? seed.slice(MLKEM_KEY_SEED_SIZE, MLKEM_KEY_SEED_SIZE + X25519_KEY_SIZE)
    : randomBytes(X25519_KEY_SIZE);

  // noble requires both calls to use the same seed to get matching pub/priv
  const { publicKey: mlkemPub, secretKey: mlkemPriv } = ml_kem768.keygen(mlkemSeed);
  const x25519Pub = x25519.getPublicKey(x25519Priv);

  const publicKey = new Uint8Array(HYBRID_PUBLIC_KEY_SIZE);
  publicKey.set(mlkemPub, 0);
  publicKey.set(x25519Pub, MLKEM_PUBLIC_KEY_SIZE);

  // Private key: expanded ML-KEM secret key || X25519 scalar
  const privateKey = new Uint8Array(HYBRID_PRIVATE_KEY_SIZE_TS);
  privateKey.set(mlkemPriv, 0);
  privateKey.set(x25519Priv, MLKEM_SECRET_KEY_SIZE);

  return { publicKey, privateKey };
}

export function zeroKEMKeyPair(kp: HybridKEMKeyPair): void {
  zero(kp.privateKey);
}

// ─── Encapsulate ─────────────────────────────────────────────────────────────

/**
 * encapsulate produces a ciphertext and shared secret against pub.
 * encapSeed is for deterministic testing (64+ bytes: 32 ML-KEM + 32 X25519).
 * In production, omit encapSeed.
 */
export async function encapsulate(
  pub: Uint8Array,
  encapSeed?: Uint8Array
): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
  if (pub.length !== HYBRID_PUBLIC_KEY_SIZE) {
    throw new Error(`pqcratchet: public key must be ${HYBRID_PUBLIC_KEY_SIZE} bytes`);
  }

  const mlkemPub = pub.slice(0, MLKEM_PUBLIC_KEY_SIZE);
  const x25519RecipientPub = pub.slice(MLKEM_PUBLIC_KEY_SIZE);

  // ML-KEM encapsulation
  const mlkemEncapSeed = encapSeed
    ? encapSeed.slice(0, MLKEM_ENCAP_SEED_SIZE)
    : randomBytes(MLKEM_ENCAP_SEED_SIZE);
  const { cipherText: mlkemCT, sharedSecret: mlkemSS } = ml_kem768.encapsulate(mlkemPub, mlkemEncapSeed);

  // X25519 ephemeral encapsulation
  const ephemeralPriv = encapSeed
    ? encapSeed.slice(MLKEM_ENCAP_SEED_SIZE, MLKEM_ENCAP_SEED_SIZE + X25519_KEY_SIZE)
    : randomBytes(X25519_KEY_SIZE);
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv);
  const x25519SS = x25519.getSharedSecret(ephemeralPriv, x25519RecipientPub);

  if (x25519SS.every(b => b === 0)) {
    throw new Error("pqcratchet: x25519 DH produced all-zero shared secret (low-order point)");
  }

  const ciphertext = new Uint8Array(HYBRID_CIPHERTEXT_SIZE);
  ciphertext.set(mlkemCT, 0);
  ciphertext.set(ephemeralPub, MLKEM_CIPHERTEXT_SIZE);

  const sharedSecret = await combineKEMSecrets(mlkemSS, x25519SS, pub);
  return { ciphertext, sharedSecret };
}

// ─── Decapsulate ─────────────────────────────────────────────────────────────

export async function decapsulate(
  priv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  if (priv.length !== HYBRID_PRIVATE_KEY_SIZE_TS) {
    throw new Error(`pqcratchet: private key must be ${HYBRID_PRIVATE_KEY_SIZE_TS} bytes`);
  }
  if (ciphertext.length !== HYBRID_CIPHERTEXT_SIZE) {
    throw new Error(`pqcratchet: ciphertext must be ${HYBRID_CIPHERTEXT_SIZE} bytes`);
  }

  const mlkemPriv = priv.slice(0, MLKEM_SECRET_KEY_SIZE);
  const x25519Priv = priv.slice(MLKEM_SECRET_KEY_SIZE);
  const mlkemCT = ciphertext.slice(0, MLKEM_CIPHERTEXT_SIZE);
  const ephemeralPub = ciphertext.slice(MLKEM_CIPHERTEXT_SIZE);

  // ML-KEM decapsulation using expanded secret key
  const mlkemSS = ml_kem768.decapsulate(mlkemCT, mlkemPriv);

  // X25519 decapsulation
  const x25519SS = x25519.getSharedSecret(x25519Priv, ephemeralPub);

  if (x25519SS.every(b => b === 0)) {
    throw new Error("pqcratchet: x25519 DH produced all-zero shared secret (low-order point)");
  }

  // Reconstruct recipient public key (same bytes the encapsulator used)
  const mlkemPub = ml_kem768.getPublicKey(mlkemPriv);
  const x25519Pub = x25519.getPublicKey(x25519Priv);
  const recipientPub = new Uint8Array(HYBRID_PUBLIC_KEY_SIZE);
  recipientPub.set(mlkemPub, 0);
  recipientPub.set(x25519Pub, MLKEM_PUBLIC_KEY_SIZE);

  return combineKEMSecrets(mlkemSS, x25519SS, recipientPub);
}

// ─── Secret combiner ─────────────────────────────────────────────────────────

/**
 * combineKEMSecrets derives a 32-byte combined shared secret.
 * SS = HKDF-SHA256(mlkemSS || x25519SS, salt=SHA256(recipientPub), info="pqcratchet/v1/HybridKEM")
 *
 * The SHA256(recipientPub) salt binds the output to the specific recipient,
 * preventing cross-key confusion attacks.
 */
async function combineKEMSecrets(
  mlkemSS: Uint8Array,
  x25519SS: Uint8Array,
  recipientPub: Uint8Array
): Promise<Uint8Array> {
  const ikm = concat(mlkemSS, x25519SS);
  const salt = await sha256(recipientPub);
  return hkdf(ikm, salt, INFO_HYBRID_KEM, 32);
}

/**
 * kemKeyPairFromGoSeed reconstructs a TS HybridKEMKeyPair from a Go-serialised
 * 96-byte private key (64-byte ML-KEM seed || 32-byte X25519 scalar).
 *
 * Go stores the compact seed form; TS decapsulate needs the 2400-byte expanded
 * ML-KEM secretKey. This function expands it via ml_kem768.keygen(seed).
 *
 * Use this when importing identities exported by the Go implementation.
 */
export function kemKeyPairFromGoSeed(goPriv: Uint8Array): HybridKEMKeyPair {
  if (goPriv.length !== MLKEM_KEY_SEED_SIZE + X25519_KEY_SIZE) {
    throw new Error(
      `pqcratchet: Go private key must be ${MLKEM_KEY_SEED_SIZE + X25519_KEY_SIZE} bytes, got ${goPriv.length}`
    );
  }
  const mlkemSeed = goPriv.slice(0, MLKEM_KEY_SEED_SIZE);
  const x25519Priv = goPriv.slice(MLKEM_KEY_SEED_SIZE);

  const { publicKey: mlkemPub, secretKey: mlkemPrivExpanded } = ml_kem768.keygen(mlkemSeed);
  const x25519Pub = x25519.getPublicKey(x25519Priv);

  const publicKey = new Uint8Array(HYBRID_PUBLIC_KEY_SIZE);
  publicKey.set(mlkemPub, 0);
  publicKey.set(x25519Pub, MLKEM_PUBLIC_KEY_SIZE);

  const privateKey = new Uint8Array(HYBRID_PRIVATE_KEY_SIZE_TS);
  privateKey.set(mlkemPrivExpanded, 0);
  privateKey.set(x25519Priv, MLKEM_SECRET_KEY_SIZE);

  return { publicKey, privateKey };
}
