/**
 * sign.ts — ML-DSA-65 (FIPS 204) signing.
 *
 * @noble/post-quantum provides ml_dsa65 with randomized signing,
 * matching the Go implementation's use of randomized=true in circl.
 *
 * Note on @noble/post-quantum argument order (differs from Go circl):
 *   sign(msg, secretKey)       — message first
 *   verify(sig, msg, publicKey) — signature first
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { DSA_PUBLIC_KEY_SIZE, DSA_PRIVATE_KEY_SIZE, DSA_SIGNATURE_SIZE } from "./constants.js";
import { randomBytes } from "./crypto.js";

export interface DSAKeyPair {
  publicKey: Uint8Array;  // DSA_PUBLIC_KEY_SIZE (1952) bytes
  privateKey: Uint8Array; // DSA_PRIVATE_KEY_SIZE (4032) bytes
}

/**
 * generateDSAKeyPair generates a fresh ML-DSA-65 signing key pair.
 * seed is 32 bytes for deterministic generation (tests only).
 */
export function generateDSAKeyPair(seed?: Uint8Array): DSAKeyPair {
  const s = seed ?? randomBytes(32);
  const { publicKey, secretKey } = ml_dsa65.keygen(s);
  return { publicKey, privateKey: secretKey };
}

/**
 * dsaSign signs msg with the private key using randomized ML-DSA-65.
 * Returns a DSA_SIGNATURE_SIZE (3309) byte signature.
 */
export function dsaSign(privateKey: Uint8Array, msg: Uint8Array): Uint8Array {
  if (privateKey.length !== DSA_PRIVATE_KEY_SIZE) {
    throw new Error(`pqcratchet: DSA private key must be ${DSA_PRIVATE_KEY_SIZE} bytes, got ${privateKey.length}`);
  }
  // @noble/post-quantum argument order: sign(msg, secretKey)
  return ml_dsa65.sign(msg, privateKey);
}

/**
 * dsaVerify verifies a ML-DSA-65 signature.
 * Returns true if valid, false on any failure.
 */
export function dsaVerify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (publicKey.length !== DSA_PUBLIC_KEY_SIZE) return false;
  if (sig.length !== DSA_SIGNATURE_SIZE) return false;
  try {
    // @noble/post-quantum argument order: verify(sig, msg, publicKey)
    return ml_dsa65.verify(sig, msg, publicKey);
  } catch {
    return false;
  }
}

export function zeroDSAKeyPair(kp: DSAKeyPair): void {
  kp.privateKey.fill(0);
}
