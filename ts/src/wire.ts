/**
 * wire.ts — binary wire format serialization/deserialization.
 *
 * Layout must match pqcratchet/wire.go exactly for Go↔TypeScript interop.
 *
 * Message protocol (inner):
 *   uint32 counter
 *   [1216]byte senderRatchetPub
 *   byte hasRatchetCT (0x00 or 0x01)
 *   [1120]byte ratchetCT  (only if hasRatchetCT == 0x01)
 *   uint32 ciphertextLen
 *   []byte ciphertext
 *
 * Signed message envelope:
 *   byte    wireVersion (0x01)
 *   [32]byte hmacSig
 *   uint32  innerLen
 *   []byte  inner
 *
 * PreKeyMessage:
 *   byte    wireVersion
 *   uint32  registrationID
 *   uint32  signedPreKeyIndex
 *   uint32  oneTimePreKeyIndex  (0xFFFFFFFF = none)
 *   [1952]byte signingPub
 *   [3309]byte exchangeKeySig
 *   [1216]byte exchangePub
 *   [1216]byte baseKey
 *   [1120]byte ct1
 *   [1120]byte ct2
 *   byte    hasCT4
 *   [1120]byte ct4             (only if hasCT4 == 0x01)
 *   [3309]byte initiatorSig
 *   uint32  signedMessageLen
 *   []byte  signedMessage
 */

import {
  HYBRID_PUBLIC_KEY_SIZE, HYBRID_CIPHERTEXT_SIZE,
  DSA_PUBLIC_KEY_SIZE, DSA_SIGNATURE_SIZE,
} from "./constants.js";
import { concat } from "./crypto.js";

export const WIRE_VERSION = 0x01;
export const NO_ONE_TIME_PRE_KEY = 0xFFFFFFFF;

// ─── uint32 helpers ──────────────────────────────────────────────────────────

function writeU32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false); // big-endian
  return b;
}

function readU32(buf: Uint8Array, offset: number): number {
  return new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, false);
}

// ─── Message protocol (inner) ────────────────────────────────────────────────

export interface MessageProtocol {
  counter: number;
  senderRatchetPub: Uint8Array;  // HYBRID_PUBLIC_KEY_SIZE bytes
  ratchetCT: Uint8Array | null;  // HYBRID_CIPHERTEXT_SIZE bytes or null
  ciphertext: Uint8Array;
}

export function marshalMessageProtocol(m: MessageProtocol): Uint8Array {
  const parts: Uint8Array[] = [
    writeU32(m.counter),
    m.senderRatchetPub,
  ];
  if (m.ratchetCT !== null) {
    parts.push(new Uint8Array([0x01]), m.ratchetCT);
  } else {
    parts.push(new Uint8Array([0x00]));
  }
  parts.push(writeU32(m.ciphertext.length), m.ciphertext);
  return concat(...parts);
}

export function unmarshalMessageProtocol(b: Uint8Array): MessageProtocol {
  let off = 0;

  if (b.length < 4) throw new Error("wire: message too short (counter)");
  const counter = readU32(b, off); off += 4;

  if (b.length < off + HYBRID_PUBLIC_KEY_SIZE) throw new Error("wire: message too short (ratchetPub)");
  const senderRatchetPub = b.slice(off, off + HYBRID_PUBLIC_KEY_SIZE); off += HYBRID_PUBLIC_KEY_SIZE;

  if (b.length < off + 1) throw new Error("wire: message too short (hasRatchetCT)");
  const hasRatchetCT = b[off]; off += 1;
  let ratchetCT: Uint8Array | null = null;
  if (hasRatchetCT === 0x01) {
    if (b.length < off + HYBRID_CIPHERTEXT_SIZE) throw new Error("wire: message too short (ratchetCT)");
    ratchetCT = b.slice(off, off + HYBRID_CIPHERTEXT_SIZE); off += HYBRID_CIPHERTEXT_SIZE;
  }

  if (b.length < off + 4) throw new Error("wire: message too short (ciphertextLen)");
  const ctLen = readU32(b, off); off += 4;

  if (b.length < off + ctLen) throw new Error("wire: message truncated (ciphertext)");
  const ciphertext = b.slice(off, off + ctLen); off += ctLen;

  if (off !== b.length) throw new Error(`wire: ${b.length - off} unexpected trailing bytes`);
  return { counter, senderRatchetPub, ratchetCT, ciphertext };
}

// ─── Signed message envelope ─────────────────────────────────────────────────

export interface SignedMessageEnvelope {
  hmacSig: Uint8Array;      // 32 bytes
  messageRaw: Uint8Array;   // inner bytes (for HMAC verification)
  message: MessageProtocol;
}

/** Build the HMAC input: AD || initiatorSigKey || responderSigKey || inner */
export function buildHMACInput(
  ad: Uint8Array,
  initiatorSigKey: Uint8Array,
  responderSigKey: Uint8Array,
  inner: Uint8Array,
): Uint8Array {
  return concat(ad, initiatorSigKey, responderSigKey, inner);
}

export function marshalSignedMessage(
  inner: Uint8Array,
  hmacSig: Uint8Array,
): Uint8Array {
  return concat(
    new Uint8Array([WIRE_VERSION]),
    hmacSig,
    writeU32(inner.length),
    inner,
  );
}

export function unmarshalSignedMessage(b: Uint8Array): SignedMessageEnvelope {
  if (b.length < 1 + 32 + 4) throw new Error("wire: signed message too short");
  if (b[0] !== WIRE_VERSION) throw new Error(`wire: unsupported version 0x${b[0].toString(16)}`);

  const hmacSig = b.slice(1, 33);
  const innerLen = readU32(b, 33);
  const innerStart = 37;
  if (b.length < innerStart + innerLen) throw new Error("wire: signed message truncated");
  if (b.length !== innerStart + innerLen) {
    throw new Error(`wire: ${b.length - innerStart - innerLen} unexpected trailing bytes`);
  }
  const messageRaw = b.slice(innerStart, innerStart + innerLen);
  const message = unmarshalMessageProtocol(messageRaw);
  return { hmacSig, messageRaw, message };
}

// ─── PreKeyMessage wire ───────────────────────────────────────────────────────

export interface PreKeyMessageWire {
  registrationID: number;
  signedPreKeyIndex: number;
  oneTimePreKeyIndex: number;  // NO_ONE_TIME_PRE_KEY if none
  signingPub: Uint8Array;      // DSA_PUBLIC_KEY_SIZE
  exchangeKeySig: Uint8Array;  // DSA_SIGNATURE_SIZE
  exchangePub: Uint8Array;     // HYBRID_PUBLIC_KEY_SIZE
  baseKey: Uint8Array;         // HYBRID_PUBLIC_KEY_SIZE
  ct1: Uint8Array;             // HYBRID_CIPHERTEXT_SIZE
  ct2: Uint8Array;             // HYBRID_CIPHERTEXT_SIZE
  ct4: Uint8Array | null;      // HYBRID_CIPHERTEXT_SIZE or null
  initiatorSig: Uint8Array;    // DSA_SIGNATURE_SIZE
  signedMessageBytes: Uint8Array; // may be empty
}

export function marshalPreKeyMessageWire(m: PreKeyMessageWire): Uint8Array {
  const parts: Uint8Array[] = [
    new Uint8Array([WIRE_VERSION]),
    writeU32(m.registrationID),
    writeU32(m.signedPreKeyIndex),
    writeU32(m.oneTimePreKeyIndex),
    m.signingPub,
    m.exchangeKeySig,
    m.exchangePub,
    m.baseKey,
    m.ct1,
    m.ct2,
  ];
  if (m.ct4 !== null) {
    parts.push(new Uint8Array([0x01]), m.ct4);
  } else {
    parts.push(new Uint8Array([0x00]));
  }
  parts.push(
    m.initiatorSig,
    writeU32(m.signedMessageBytes.length),
    m.signedMessageBytes,
  );
  return concat(...parts);
}

export function unmarshalPreKeyMessageWire(b: Uint8Array): PreKeyMessageWire {
  let off = 0;

  if (b.length < 1) throw new Error("wire: preKeyMsg too short");
  if (b[off] !== WIRE_VERSION) throw new Error(`wire: unsupported version 0x${b[off].toString(16)}`);
  off += 1;

  const registrationID = readU32(b, off); off += 4;
  const signedPreKeyIndex = readU32(b, off); off += 4;
  const oneTimePreKeyIndex = readU32(b, off); off += 4;

  const signingPub = b.slice(off, off + DSA_PUBLIC_KEY_SIZE); off += DSA_PUBLIC_KEY_SIZE;
  const exchangeKeySig = b.slice(off, off + DSA_SIGNATURE_SIZE); off += DSA_SIGNATURE_SIZE;
  const exchangePub = b.slice(off, off + HYBRID_PUBLIC_KEY_SIZE); off += HYBRID_PUBLIC_KEY_SIZE;
  const baseKey = b.slice(off, off + HYBRID_PUBLIC_KEY_SIZE); off += HYBRID_PUBLIC_KEY_SIZE;
  const ct1 = b.slice(off, off + HYBRID_CIPHERTEXT_SIZE); off += HYBRID_CIPHERTEXT_SIZE;
  const ct2 = b.slice(off, off + HYBRID_CIPHERTEXT_SIZE); off += HYBRID_CIPHERTEXT_SIZE;

  if (b.length < off + 1) throw new Error("wire: preKeyMsg too short (hasCT4)");
  const hasCT4 = b[off]; off += 1;
  let ct4: Uint8Array | null = null;
  if (hasCT4 === 0x01) {
    ct4 = b.slice(off, off + HYBRID_CIPHERTEXT_SIZE); off += HYBRID_CIPHERTEXT_SIZE;
  }

  const initiatorSig = b.slice(off, off + DSA_SIGNATURE_SIZE); off += DSA_SIGNATURE_SIZE;

  if (b.length < off + 4) throw new Error("wire: preKeyMsg too short (msgLen)");
  const msgLen = readU32(b, off); off += 4;
  const signedMessageBytes = msgLen > 0 ? b.slice(off, off + msgLen) : new Uint8Array(0);
  off += msgLen;

  if (off !== b.length) throw new Error(`wire: ${b.length - off} unexpected trailing bytes`);

  return {
    registrationID, signedPreKeyIndex, oneTimePreKeyIndex,
    signingPub, exchangeKeySig, exchangePub, baseKey,
    ct1, ct2, ct4, initiatorSig, signedMessageBytes,
  };
}
