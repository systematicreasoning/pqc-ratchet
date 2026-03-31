/**
 * chain.ts — symmetric ratchet (sending/receiving chains) and message key derivation.
 *
 * Unchanged from classical Double Ratchet — symmetric layer is already quantum-safe.
 *
 *   cipherKey    = HMAC-SHA256(chainKey, 0x01)
 *   nextChainKey = HMAC-SHA256(chainKey, 0x02)
 *
 *   MessageKeys = HKDF(cipherKey, salt=0×32, info="pqcratchet/v1/MessageKeys") → 76 bytes
 *     aesKey  = bytes[0:32]
 *     nonce   = bytes[32:44]
 *     hmacKey = bytes[44:76]
 */

import {
  CIPHER_KEY_KDF_INPUT, ROOT_KEY_KDF_INPUT, INFO_MESSAGE_KEYS,
  HYBRID_PUBLIC_KEY_SIZE, HYBRID_CIPHERTEXT_SIZE,
} from "./constants.js";
import { hmacSHA256, hkdf, concat } from "./crypto.js";

// ─── MessageKeys ─────────────────────────────────────────────────────────────

export interface MessageKeys {
  aesKey: Uint8Array;  // 32 bytes
  nonce: Uint8Array;   // 12 bytes
  hmacKey: Uint8Array; // 32 bytes
}

export async function deriveMessageKeys(cipherKey: Uint8Array): Promise<MessageKeys> {
  const salt = new Uint8Array(32); // zero salt per DR spec §2.3
  const buf = await hkdf(cipherKey, salt, INFO_MESSAGE_KEYS, 76);
  return {
    aesKey: buf.slice(0, 32),
    nonce: buf.slice(32, 44),
    hmacKey: buf.slice(44, 76),
  };
}

// ─── SymmetricChain ──────────────────────────────────────────────────────────

export class SymmetricChain {
  rootKey: Uint8Array;
  counter: number;

  constructor(rootKey: Uint8Array, counter = 0) {
    this.rootKey = rootKey;
    this.counter = counter;
  }

  async step(): Promise<Uint8Array> {
    const cipherKey = await hmacSHA256(this.rootKey, CIPHER_KEY_KDF_INPUT);
    const nextRoot = await hmacSHA256(this.rootKey, ROOT_KEY_KDF_INPUT);
    this.rootKey = nextRoot;
    this.counter++;
    return cipherKey;
  }

  clone(): SymmetricChain {
    return new SymmetricChain(new Uint8Array(this.rootKey), this.counter);
  }
}

// ─── KEMRatchetStep ──────────────────────────────────────────────────────────

export interface KEMRatchetStep {
  remoteRatchetKey: Uint8Array;        // peer's ratchet encapsulation key
  epochRatchetCT: Uint8Array | null;   // CT that opened this sending epoch
  sendingChain: SymmetricChain | null;
  receivingChain: SymmetricChain | null;
}
