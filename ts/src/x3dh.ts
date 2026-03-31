/**
 * x3dh.ts — KEM-based X3DH key agreement.
 *
 * Alice (initiator) — authenticateA:
 *   (ct1, ss1) = KEM.Encap(SPK_B)
 *   (ct2, ss2) = KEM.Encap(IK_B.ex)
 *   EK_A       = KEM.GenerateKeyPair()
 *   [ct4, ss3  = KEM.Encap(OPK_B)]
 *   SK = HKDF(0xFF×32 || ss1 || ss2 [|| ss3])
 *   transcript = IK_A.ex || CT1 || CT2 || EK_A.pub [|| CT4]
 *   InitiatorSig = ML-DSA-65.Sign(IK_A.sig.sk, transcript)
 *
 * Bob (responder) — authenticateB:
 *   verify InitiatorSig BEFORE decapsulating
 *   ss1 = KEM.Decap(SPK_B.sk, ct1)
 *   ss2 = KEM.Decap(IK_B.ex.sk, ct2)
 *   [ss3 = KEM.Decap(OPK_B.sk, ct4)]
 *   SK = HKDF(0xFF×32 || ss1 || ss2 [|| ss3])
 */

import {
  HYBRID_PUBLIC_KEY_SIZE, HYBRID_CIPHERTEXT_SIZE,
  HYBRID_PRIVATE_KEY_SIZE, INFO_KEM_INIT,
} from "./constants.js";
import { hkdf, concat } from "./crypto.js";
import { encapsulate, decapsulate, generateKEMKeyPair, HybridKEMKeyPair } from "./kem.js";
import { dsaSign, dsaVerify } from "./sign.js";

// ─── Initiator result ────────────────────────────────────────────────────────

export interface KEMInitiatorResult {
  rootKey: Uint8Array;
  ephemeralKP: HybridKEMKeyPair;
  ct1: Uint8Array;
  ct2: Uint8Array;
  ct4: Uint8Array | null;
  initiatorSig: Uint8Array;
}

// ─── AuthenticateA ───────────────────────────────────────────────────────────

export async function authenticateA(
  initiatorSigningKey: Uint8Array,
  initiatorExchangePub: Uint8Array,
  remoteIdentityExPub: Uint8Array,
  remoteSignedPreKeyPub: Uint8Array,
  remoteOneTimePreKeyPub: Uint8Array | null,
  encapSeed?: Uint8Array, // for deterministic tests only
): Promise<KEMInitiatorResult> {
  // KEM1 = Encap(SPK_B) → ss1
  const { ciphertext: ct1, sharedSecret: ss1 } = await encapsulate(remoteSignedPreKeyPub, encapSeed);

  // KEM2 = Encap(IK_B.ex) → ss2
  const seed2 = encapSeed ? encapSeed.slice(64) : undefined;
  const { ciphertext: ct2, sharedSecret: ss2 } = await encapsulate(remoteIdentityExPub, seed2);

  // Generate ephemeral keypair EK_A
  const seed3 = encapSeed ? encapSeed.slice(128, 224) : undefined;
  const ephemeralKP = generateKEMKeyPair(seed3);

  // Optional KEM3 = Encap(OPK_B) → ss3
  let ct4: Uint8Array | null = null;
  let ss3: Uint8Array | null = null;
  if (remoteOneTimePreKeyPub !== null) {
    const seed4 = encapSeed ? encapSeed.slice(224) : undefined;
    const r = await encapsulate(remoteOneTimePreKeyPub, seed4);
    ct4 = r.ciphertext;
    ss3 = r.sharedSecret;
  }

  const rootKey = await deriveKEMRootKey(ss1, ss2, ss3);

  // Build transcript: IK_A.ex || CT1 || CT2 || EK_A.pub [|| CT4]
  const transcript = buildInitiatorTranscript(initiatorExchangePub, ct1, ct2, ephemeralKP.publicKey, ct4);
  const initiatorSig = dsaSign(initiatorSigningKey, transcript);

  return { rootKey, ephemeralKP, ct1, ct2, ct4, initiatorSig };
}

// ─── AuthenticateB ───────────────────────────────────────────────────────────

export async function authenticateB(
  identityExchangePriv: Uint8Array,
  signedPreKeyPriv: Uint8Array,
  oneTimePreKeyPriv: Uint8Array | null,
  initiatorSigningPub: Uint8Array,
  initiatorExchangePub: Uint8Array,
  baseKey: Uint8Array,          // EK_A.pub
  ct1: Uint8Array,
  ct2: Uint8Array,
  ct4: Uint8Array | null,
  initiatorSig: Uint8Array,
): Promise<Uint8Array> {
  // Verify initiator signature BEFORE decapsulating.
  // This prevents Bob's decapsulation from being used as a chosen-ciphertext oracle.
  const transcript = buildInitiatorTranscript(initiatorExchangePub, ct1, ct2, baseKey, ct4);
  if (!dsaVerify(initiatorSigningPub, transcript, initiatorSig)) {
    throw new Error("pqcratchet: invalid signature");
  }

  // ss1 = Decap(SPK_B.sk, ct1)
  const ss1 = await decapsulate(signedPreKeyPriv, ct1);

  // ss2 = Decap(IK_B.ex.sk, ct2)
  const ss2 = await decapsulate(identityExchangePriv, ct2);

  // Optional ss3 = Decap(OPK_B.sk, ct4)
  let ss3: Uint8Array | null = null;
  if (oneTimePreKeyPriv !== null && ct4 !== null) {
    ss3 = await decapsulate(oneTimePreKeyPriv, ct4);
  } else if (oneTimePreKeyPriv !== null && ct4 === null) {
    throw new Error("pqcratchet: have OPK private key but initiator sent no CT4");
  } else if (oneTimePreKeyPriv === null && ct4 !== null) {
    throw new Error("pqcratchet: initiator sent CT4 but no OPK private key available");
  }

  return deriveKEMRootKey(ss1, ss2, ss3);
}

// ─── Transcript ──────────────────────────────────────────────────────────────

function buildInitiatorTranscript(
  initiatorExchangePub: Uint8Array,
  ct1: Uint8Array,
  ct2: Uint8Array,
  baseKey: Uint8Array,
  ct4: Uint8Array | null,
): Uint8Array {
  const parts: Uint8Array[] = [initiatorExchangePub, ct1, ct2, baseKey];
  if (ct4 !== null) parts.push(ct4);
  return concat(...parts);
}

// ─── Root key derivation ─────────────────────────────────────────────────────

async function deriveKEMRootKey(
  ss1: Uint8Array,
  ss2: Uint8Array,
  ss3: Uint8Array | null,
): Promise<Uint8Array> {
  if (ss1.length !== 32) throw new Error(`pqcratchet: x3dh ss1 must be 32 bytes, got ${ss1.length}`);
  if (ss2.length !== 32) throw new Error(`pqcratchet: x3dh ss2 must be 32 bytes, got ${ss2.length}`);
  if (ss3 !== null && ss3.length !== 32) throw new Error(`pqcratchet: x3dh ss3 must be 32 bytes, got ${ss3.length}`);

  const domainSep = new Uint8Array(32).fill(0xFF);
  const parts: Uint8Array[] = [domainSep, ss1, ss2];
  if (ss3 !== null) parts.push(ss3);
  const keyMaterial = concat(...parts);

  const salt = new Uint8Array(32); // zero salt per X3DH spec
  return hkdf(keyMaterial, salt, INFO_KEM_INIT, 32);
}
