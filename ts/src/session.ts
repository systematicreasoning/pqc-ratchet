/**
 * session.ts — Double Ratchet session using the KEM ratchet (ACD19 CKA).
 *
 * ∆_CKA = 1: the receiving ratchet private key is retained until the next
 * send epoch, matching Signal's deployed DH ratchet and giving ∆_SM = 3.
 * Documented in comments at createReceivingChain.
 */

import {
  INFO_RATCHET, MAX_SKIP, MAX_OLD_EPOCH_SKIP, MAX_RATCHET_STACK_SIZE,
  HYBRID_PUBLIC_KEY_SIZE, HYBRID_CIPHERTEXT_SIZE,
  AES_GCM_TAG_SIZE,
} from "./constants.js";
import { hkdfExtract, hkdfExpand, hmacSHA256, aesGcmEncrypt, aesGcmDecrypt, concat, writeUint32BE, constantTimeEqual, zero } from "./crypto.js";
import { SymmetricChain, KEMRatchetStep, MessageKeys, deriveMessageKeys } from "./chain.js";
import { generateKEMKeyPair, encapsulate, decapsulate, zeroKEMKeyPair, HybridKEMKeyPair } from "./kem.js";
import { marshalMessageProtocol, buildHMACInput, marshalSignedMessage, unmarshalSignedMessage } from "./wire.js";

// ─── Errors ──────────────────────────────────────────────────────────────────

export const ERR_INVALID_SIGNATURE = "pqcratchet: invalid signature";
export const ERR_DECRYPTION_FAILED = "pqcratchet: decryption failed";
export const ERR_DUPLICATE_MESSAGE = "pqcratchet: duplicate message counter";
export const ERR_COUNTER_TOO_LARGE = "pqcratchet: message counter exceeds max skip";
export const ERR_HMAC_VERIFY_FAILED = "pqcratchet: HMAC verification failed";
export const ERR_SKIPPED_KEY_CAPACITY = "pqcratchet: skipped key cache full";

// ─── Session ──────────────────────────────────────────────────────────────────

export interface EncryptResult {
  counter: number;
  newRatchetPub: Uint8Array;
  ratchetCT: Uint8Array | null;
  ciphertext: Uint8Array;
  hmacKey: Uint8Array;
}

/**
 * An established Double Ratchet session between two parties.
 *
 * Obtain an instance via `createSessionInitiator` (Alice's side) or
 * `createSessionResponder` (Bob's side) after X3DH key agreement.
 *
 * **Recommended API:** `seal(plaintext)` / `open(wireBytes)` — these handle
 * wire marshalling and HMAC internally and are sufficient for most callers.
 *
 * **Low-level API:** `encryptMessage()` / `decryptMessage()` + the `marshal*`
 * functions from `wire.ts` — available for custom transports, batching, or audit.
 */
export class Session {
  rootKey: Uint8Array;
  ratchetKP: HybridKEMKeyPair;
  currentStep: KEMRatchetStep | null = null;
  skippedKeys: Map<string, Uint8Array> = new Map();

  // Session AD = Encode(IK_A.ex) || Encode(IK_B.ex)
  ad: Uint8Array;

  // Stable role signing keys for HMAC (initiator always first, responder second)
  initiatorSigningKeyBytes: Uint8Array;
  responderSigningKeyBytes: Uint8Array;

  constructor(
    rootKey: Uint8Array,
    ratchetKP: HybridKEMKeyPair,
    ad: Uint8Array,
    initiatorSigningKeyBytes: Uint8Array,
    responderSigningKeyBytes: Uint8Array,
  ) {
    this.rootKey = rootKey;
    this.ratchetKP = ratchetKP;
    this.ad = ad;
    this.initiatorSigningKeyBytes = initiatorSigningKeyBytes;
    this.responderSigningKeyBytes = responderSigningKeyBytes;
  }

  // ─── Encrypt ───────────────────────────────────────────────────────────────

  async encryptMessage(plaintext: Uint8Array): Promise<EncryptResult> {
    // Ratchet step: generate new keypair, encapsulate against remote ratchet key
    if (!this.currentStep || this.currentStep.sendingChain === null) {
      if (!this.currentStep?.remoteRatchetKey) {
        throw new Error("pqcratchet: no remote ratchet key set");
      }
      const { sendingChain, ratchetCT } = await this.createSendingChain(this.currentStep.remoteRatchetKey);
      if (!this.currentStep) throw new Error("unreachable");
      this.currentStep.sendingChain = sendingChain;
      this.currentStep.epochRatchetCT = ratchetCT;
    }

    const chain = this.currentStep.sendingChain!;
    const cipherKey = await chain.step();
    const keys = await deriveMessageKeys(cipherKey);

    const ciphertext = await aesGcmEncrypt(keys.aesKey, keys.nonce, this.ad, plaintext);

    return {
      counter: chain.counter - 1,
      newRatchetPub: this.ratchetKP.publicKey,
      ratchetCT: this.currentStep.epochRatchetCT,
      ciphertext,
      hmacKey: keys.hmacKey,
    };
  }

  // ─── High-level API ────────────────────────────────────────────────────────
  //
  // seal() and open() are the recommended API for most callers.
  // They handle wire marshalling, HMAC construction, and signing internally
  // so the caller only deals with plaintext bytes and opaque wire frames.
  //
  // The low-level encryptMessage / decryptMessage + marshal* functions remain
  // available for advanced use: custom transports, server-side batching, audit.

  /**
   * Encrypt plaintext and return a self-contained, authenticated wire frame.
   *
   * The returned bytes include the message counter, sender ratchet public key,
   * optional KEM ciphertext (on the first send of a new ratchet turn), the
   * AES-256-GCM ciphertext, and an outer HMAC-SHA-256 authentication tag.
   * Pass them directly to the recipient's open().
   */
  async seal(plaintext: Uint8Array): Promise<Uint8Array> {
    const enc   = await this.encryptMessage(plaintext);
    const inner = marshalMessageProtocol({
      counter:          enc.counter,
      senderRatchetPub: enc.newRatchetPub,
      ratchetCT:        enc.ratchetCT,
      ciphertext:       enc.ciphertext,
    });
    const hmacInput = buildHMACInput(
      this.ad,
      this.initiatorSigningKeyBytes,
      this.responderSigningKeyBytes,
      inner,
    );
    const sig = await hmacSHA256(enc.hmacKey, hmacInput);
    return marshalSignedMessage(inner, sig);
  }

  /**
   * Verify and decrypt a wire frame produced by the remote side's seal().
   * Throws if the HMAC is invalid, the ratchet state is inconsistent, or
   * the message is a duplicate.
   */
  async open(wireBytes: Uint8Array): Promise<Uint8Array> {
    const sm = unmarshalSignedMessage(wireBytes);
    return this.decryptMessage(
      sm.message.counter,
      sm.message.senderRatchetPub,
      sm.message.ratchetCT,
      sm.message.ciphertext,
      sm.hmacSig,
      sm.messageRaw,
    );
  }

  // ─── Decrypt ───────────────────────────────────────────────────────────────

  async decryptMessage(
    counter: number,
    senderRatchetPub: Uint8Array,
    ratchetCT: Uint8Array | null,
    ciphertext: Uint8Array,
    hmacSignature: Uint8Array,
    messageRaw: Uint8Array, // full inner wire bytes for HMAC verification
  ): Promise<Uint8Array> {
    // Snapshot state for rollback on failure
    const snap = this.snapshot();

    try {
      const result = await this.decryptInner(counter, senderRatchetPub, ratchetCT, ciphertext, hmacSignature, messageRaw);
      return result;
    } catch (e) {
      this.restore(snap);
      throw e;
    }
  }

  private async decryptInner(
    counter: number,
    senderRatchetPub: Uint8Array,
    ratchetCT: Uint8Array | null,
    ciphertext: Uint8Array,
    hmacSignature: Uint8Array,
    messageRaw: Uint8Array,
  ): Promise<Uint8Array> {
    // Check skipped key cache first
    const cacheKey = skippedKeyID(senderRatchetPub, counter);
    if (this.skippedKeys.has(cacheKey)) {
      const cipherKey = this.skippedKeys.get(cacheKey)!;
      this.skippedKeys.delete(cacheKey);
      return this.decryptWithKey(cipherKey, ciphertext, hmacSignature, messageRaw);
    }

    // New ratchet epoch?
    const isNewEpoch = !this.currentStep ||
      !equalBytes(senderRatchetPub, this.currentStep.remoteRatchetKey);

    if (isNewEpoch) {
      if (ratchetCT === null) throw new Error("pqcratchet: new ratchet epoch but no CT");

      // Cache remaining keys from current receiving chain
      if (this.currentStep?.receivingChain) {
        await this.skipKeys(this.currentStep.receivingChain, MAX_OLD_EPOCH_SKIP,
          this.currentStep.remoteRatchetKey);
      }

      // Create new receiving chain from the ratchet CT
      const receivingChain = await this.createReceivingChain(ratchetCT);

      // Zero old ratchet keypair and generate new one for next send epoch
      const oldKP = this.ratchetKP;
      this.ratchetKP = generateKEMKeyPair();
      zeroKEMKeyPair(oldKP);

      this.currentStep = {
        remoteRatchetKey: new Uint8Array(senderRatchetPub),
        epochRatchetCT: ratchetCT,
        sendingChain: null,
        receivingChain,
      };
    }

    const chain = this.currentStep!.receivingChain;
    if (chain === null) {
      // First message in this epoch — receiving chain not yet bootstrapped.
      // This happens when the responder hasn't received the epoch CT yet.
      // The ratchetCT must be present to bootstrap.
      if (ratchetCT === null) throw new Error("pqcratchet: no receiving chain and no ratchet CT");
      this.currentStep!.receivingChain = await this.createReceivingChain(ratchetCT);
    }
    const activeChain = this.currentStep!.receivingChain!;

    // Skip ahead to the right counter
    if (counter < activeChain.counter) {
      throw new Error(ERR_DUPLICATE_MESSAGE);
    }
    if (counter - activeChain.counter > MAX_SKIP) {
      throw new Error(ERR_COUNTER_TOO_LARGE);
    }
    while (activeChain.counter < counter) {
      if (this.skippedKeys.size >= MAX_SKIP) throw new Error(ERR_SKIPPED_KEY_CAPACITY);
      const skippedKey = await activeChain.step();
      this.skippedKeys.set(skippedKeyID(senderRatchetPub, activeChain.counter - 1), skippedKey);
    }

    const cipherKey = await activeChain.step();
    return this.decryptWithKey(cipherKey, ciphertext, hmacSignature, messageRaw);
  }

  private async decryptWithKey(
    cipherKey: Uint8Array,
    ciphertext: Uint8Array,
    hmacSignature: Uint8Array,
    messageRaw: Uint8Array,
  ): Promise<Uint8Array> {
    const keys = await deriveMessageKeys(cipherKey);

    // Verify outer HMAC first
    const hmacInput = concat(this.ad, this.initiatorSigningKeyBytes, this.responderSigningKeyBytes, messageRaw);
    const expectedHMAC = await hmacSHA256(keys.hmacKey, hmacInput);
    if (!constantTimeEqual(hmacSignature, expectedHMAC)) {
      throw new Error(ERR_HMAC_VERIFY_FAILED);
    }

    return aesGcmDecrypt(keys.aesKey, keys.nonce, this.ad, ciphertext);
  }

  // ─── KDF_RK ────────────────────────────────────────────────────────────────

  private async advanceRootKey(ss: Uint8Array): Promise<SymmetricChain> {
    // PRK = HMAC-SHA256(salt=RootKey, IKM=ss)
    // Note: hkdfExtract(salt, ikm) — salt=RootKey, ikm=ss
    const prk = await hkdfExtract(this.rootKey, ss);
    const out = await hkdfExpand(prk, INFO_RATCHET, 64);
    this.rootKey = out.slice(0, 32);
    return new SymmetricChain(out.slice(32, 64));
  }

  private async createSendingChain(remoteRatchetPub: Uint8Array): Promise<{ sendingChain: SymmetricChain; ratchetCT: Uint8Array }> {
    // Rotate our own ratchet keypair before each new sending epoch.
    //
    // This is the CKA-S (sender) step from ACD19: the sender generates a fresh
    // ML-KEM-768 + X25519 keypair on every direction change.  The new public key
    // (this.ratchetKP.publicKey) is sent to the recipient as newRatchetPub so they
    // can encapsulate against it in their own next sending epoch.
    //
    // Without this rotation both sides keep advertising the same ratchet pub
    // forever: the X3DH ephemeral key never changes, isNewEpoch never fires on
    // the recipient, and the ratchet is effectively stuck after the first exchange.
    const oldKP = this.ratchetKP;
    this.ratchetKP = generateKEMKeyPair();
    zeroKEMKeyPair(oldKP);

    // Encapsulate against the REMOTE's current ratchet public key.
    // The resulting ratchetCT is sent along with newRatchetPub so the recipient
    // can (a) derive the shared secret for the new receiving chain, and (b) know
    // our new public key to encapsulate against for their own next epoch.
    const { ciphertext: ratchetCT, sharedSecret: ss } = await encapsulate(remoteRatchetPub);
    const sendingChain = await this.advanceRootKey(ss);
    return { sendingChain, ratchetCT };
  }

  private async createReceivingChain(ratchetCT: Uint8Array): Promise<SymmetricChain> {
    // ∆_CKA = 1: ratchetKP.privateKey is retained here, zeroed only when the
    // next send epoch generates a new keypair. This matches Signal's deployed
    // DH ratchet behaviour and gives ∆_SM = 3 per ACD19 §3.3.
    const ss = await decapsulate(this.ratchetKP.privateKey, ratchetCT);
    return this.advanceRootKey(ss);
  }

  private async skipKeys(chain: SymmetricChain | null, max: number, ratchetPub: Uint8Array): Promise<void> {
    if (!chain) return;
    let skipped = 0;
    while (skipped < max && chain.counter < chain.counter + max) {
      if (this.skippedKeys.size >= MAX_SKIP) break;
      const key = await chain.step();
      this.skippedKeys.set(skippedKeyID(ratchetPub, chain.counter - 1), key);
      skipped++;
    }
  }

  // ─── Snapshot / restore ────────────────────────────────────────────────────

  private snapshot(): SessionSnapshot {
    return {
      rootKey: new Uint8Array(this.rootKey),
      ratchetKP: this.ratchetKP, // pointer snapshot — safe because we replace not mutate
      currentStep: this.currentStep ? cloneStep(this.currentStep) : null,
      skippedKeys: new Map(this.skippedKeys),
    };
  }

  private restore(snap: SessionSnapshot): void {
    this.rootKey = snap.rootKey;
    this.ratchetKP = snap.ratchetKP;
    this.currentStep = snap.currentStep;
    this.skippedKeys = snap.skippedKeys;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function skippedKeyID(ratchetPub: Uint8Array, counter: number): string {
  // Use first 32 bytes of ratchet pub as key (matches Go implementation)
  return `${hex(ratchetPub.slice(0, 32))}:${counter}`;
}

function hex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

interface SessionSnapshot {
  rootKey: Uint8Array;
  ratchetKP: HybridKEMKeyPair;
  currentStep: KEMRatchetStep | null;
  skippedKeys: Map<string, Uint8Array>;
}

function cloneStep(s: KEMRatchetStep): KEMRatchetStep {
  return {
    remoteRatchetKey: new Uint8Array(s.remoteRatchetKey),
    epochRatchetCT: s.epochRatchetCT ? new Uint8Array(s.epochRatchetCT) : null,
    sendingChain: s.sendingChain ? s.sendingChain.clone() : null,
    receivingChain: s.receivingChain ? s.receivingChain.clone() : null,
  };
}
