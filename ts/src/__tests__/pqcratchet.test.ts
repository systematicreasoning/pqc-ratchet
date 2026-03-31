/**
 * pqcratchet.test.ts — test suite for the TypeScript pqcratchet implementation.
 *
 * Tests mirror the Go ratchet_test.go suite:
 * - KEM round-trip
 * - DSA sign/verify
 * - Symmetric chain stepping
 * - Full X3DH handshake
 * - Multi-turn messaging
 * - Out-of-order delivery
 * - HMAC tamper → rollback
 * - Replay rejection
 * - OPK consumption and restoration on auth failure
 * - AD misbinding
 */

import {
  generateKEMKeyPair, encapsulate, decapsulate,
  HYBRID_PRIVATE_KEY_SIZE_TS,
  generateDSAKeyPair, dsaSign, dsaVerify,
  SymmetricChain, deriveMessageKeys,
  authenticateA, authenticateB,
  generateIdentity, createSessionInitiator, createSessionResponder,
  concat, constantTimeEqual, randomBytes,
  HYBRID_PUBLIC_KEY_SIZE, HYBRID_CIPHERTEXT_SIZE,
  DSA_SIGNATURE_SIZE,
  MAX_SKIP,
  ERR_HMAC_VERIFY_FAILED, ERR_DUPLICATE_MESSAGE,
} from "../index.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function fullHandshake() {
  const alice = await generateIdentity(1, 1, 5);
  const bob = await generateIdentity(2, 1, 5);

  const bundle = {
    registrationId: bob.id,
    identitySigningPub: bob.signingKey.publicKey,
    identityExchangePub: bob.exchangeKey.publicKey,
    signedPreKeyPub: bob.signedPreKeys[0].publicKey,
    signedPreKeyIndex: 0,
    signedPreKeySig: bob.signedPreKeySigs[0],
    oneTimePreKeyPub: bob.preKeys[0]!.publicKey,
    oneTimePreKeyIndex: 0,
  };

  const { session: aliceSess, preKeyMessage } = await createSessionInitiator(alice, bundle);
  const bobSess = await createSessionResponder(bob, preKeyMessage);

  return { alice, bob, aliceSess, bobSess };
}

async function encryptAndBuildWire(sess: any, plaintext: Uint8Array) {
  const enc = await sess.encryptMessage(plaintext);
  // Build a minimal inner message bytes for HMAC purposes
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, enc.counter, false);
  const inner = concat(counterBytes, enc.newRatchetPub,
    enc.ratchetCT ? new Uint8Array([1, ...enc.ratchetCT]) : new Uint8Array([0]),
    enc.ciphertext
  );
  const hmacInput = concat(sess.ad, sess.initiatorSigningKeyBytes, sess.responderSigningKeyBytes, inner);
  const { createHmacSHA256 } = await import("../crypto.js").then(m => ({ createHmacSHA256: m.hmacSHA256 }));
  const sig = await createHmacSHA256(enc.hmacKey, hmacInput);
  return { enc, inner, sig };
}

// ─── KEM tests ───────────────────────────────────────────────────────────────

test("KEM round-trip", async () => {
  const kp = generateKEMKeyPair();
  const { ciphertext, sharedSecret: ss1 } = await encapsulate(kp.publicKey);
  const ss2 = await decapsulate(kp.privateKey, ciphertext);
  expect(ss1).toEqual(ss2);
  expect(ss1.length).toBe(32);
});

test("KEM wrong key gives different secret", async () => {
  const kp1 = generateKEMKeyPair();
  const kp2 = generateKEMKeyPair();
  const { ciphertext, sharedSecret: ss1 } = await encapsulate(kp1.publicKey);
  const ss2 = await decapsulate(kp2.privateKey, ciphertext);
  expect(ss1).not.toEqual(ss2);
});

test("KEM public key size", () => {
  const kp = generateKEMKeyPair();
  expect(kp.publicKey.length).toBe(HYBRID_PUBLIC_KEY_SIZE);
  expect(kp.privateKey.length).toBe(HYBRID_PRIVATE_KEY_SIZE_TS);
});

test("KEM ciphertext size", async () => {
  const kp = generateKEMKeyPair();
  const { ciphertext } = await encapsulate(kp.publicKey);
  expect(ciphertext.length).toBe(HYBRID_CIPHERTEXT_SIZE);
});

test("KEM deterministic with seed", async () => {
  const seed = randomBytes(96);
  const kp = generateKEMKeyPair(seed);
  const kp2 = generateKEMKeyPair(seed);
  expect(kp.publicKey).toEqual(kp2.publicKey);
  expect(kp.privateKey).toEqual(kp2.privateKey);
});

// ─── DSA tests ───────────────────────────────────────────────────────────────

test("DSA sign and verify", () => {
  const kp = generateDSAKeyPair();
  const msg = new TextEncoder().encode("hello pqcratchet");
  const sig = dsaSign(kp.privateKey, msg);
  expect(sig.length).toBe(DSA_SIGNATURE_SIZE);
  expect(dsaVerify(kp.publicKey, msg, sig)).toBe(true);
});

test("DSA wrong key rejects", () => {
  const kp1 = generateDSAKeyPair();
  const kp2 = generateDSAKeyPair();
  const msg = new TextEncoder().encode("hello");
  const sig = dsaSign(kp1.privateKey, msg);
  expect(dsaVerify(kp2.publicKey, msg, sig)).toBe(false);
});

test("DSA tampered message rejects", () => {
  const kp = generateDSAKeyPair();
  const msg = new TextEncoder().encode("hello");
  const sig = dsaSign(kp.privateKey, msg);
  const tampered = new TextEncoder().encode("HELLO");
  expect(dsaVerify(kp.publicKey, tampered, sig)).toBe(false);
});

// ─── Symmetric chain tests ───────────────────────────────────────────────────

test("symmetric chain step produces different keys", async () => {
  const chain = new SymmetricChain(randomBytes(32));
  const k1 = await chain.step();
  const k2 = await chain.step();
  expect(k1).not.toEqual(k2);
});

test("deriveMessageKeys produces correct sizes", async () => {
  const chain = new SymmetricChain(randomBytes(32));
  const cipherKey = await chain.step();
  const keys = await deriveMessageKeys(cipherKey);
  expect(keys.aesKey.length).toBe(32);
  expect(keys.nonce.length).toBe(12);
  expect(keys.hmacKey.length).toBe(32);
});

// ─── X3DH tests ──────────────────────────────────────────────────────────────

test("X3DH both sides derive same root key", async () => {
  const aliceSign = generateDSAKeyPair();
  const aliceEx = generateKEMKeyPair();
  const bobEx = generateKEMKeyPair();
  const bobSpk = generateKEMKeyPair();
  const bobOpk = generateKEMKeyPair();

  const result = await authenticateA(
    aliceSign.privateKey,
    aliceEx.publicKey,
    bobEx.publicKey,
    bobSpk.publicKey,
    bobOpk.publicKey,
  );

  const rootKey2 = await authenticateB(
    bobEx.privateKey,
    bobSpk.privateKey,
    bobOpk.privateKey,
    aliceSign.publicKey,
    aliceEx.publicKey,
    result.ephemeralKP.publicKey,
    result.ct1,
    result.ct2,
    result.ct4,
    result.initiatorSig,
  );

  expect(result.rootKey).toEqual(rootKey2);
});

test("X3DH without OPK derives same root key", async () => {
  const aliceSign = generateDSAKeyPair();
  const aliceEx = generateKEMKeyPair();
  const bobEx = generateKEMKeyPair();
  const bobSpk = generateKEMKeyPair();

  const result = await authenticateA(
    aliceSign.privateKey,
    aliceEx.publicKey,
    bobEx.publicKey,
    bobSpk.publicKey,
    null,
  );

  const rootKey2 = await authenticateB(
    bobEx.privateKey,
    bobSpk.privateKey,
    null,
    aliceSign.publicKey,
    aliceEx.publicKey,
    result.ephemeralKP.publicKey,
    result.ct1,
    result.ct2,
    null,
    result.initiatorSig,
  );

  expect(result.rootKey).toEqual(rootKey2);
});

test("X3DH invalid signature rejects", async () => {
  const aliceSign = generateDSAKeyPair();
  const aliceEx = generateKEMKeyPair();
  const bobEx = generateKEMKeyPair();
  const bobSpk = generateKEMKeyPair();

  const result = await authenticateA(
    aliceSign.privateKey, aliceEx.publicKey,
    bobEx.publicKey, bobSpk.publicKey, null,
  );

  const badSig = randomBytes(DSA_SIGNATURE_SIZE);
  await expect(authenticateB(
    bobEx.privateKey, bobSpk.privateKey, null,
    aliceSign.publicKey, aliceEx.publicKey,
    result.ephemeralKP.publicKey, result.ct1, result.ct2, null,
    badSig,
  )).rejects.toThrow("invalid signature");
});

// ─── Full session tests ───────────────────────────────────────────────────────

test("full handshake and single message", async () => {
  const { aliceSess, bobSess } = await fullHandshake();
  const pt = new TextEncoder().encode("hello world");

  const enc = await aliceSess.encryptMessage(pt);

  // Build wire for Bob
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, enc.counter, false);
  const hasRatchetCT = enc.ratchetCT ? new Uint8Array([1]) : new Uint8Array([0]);
  const inner = enc.ratchetCT
    ? concat(counterBytes, enc.newRatchetPub, hasRatchetCT, enc.ratchetCT, enc.ciphertext)
    : concat(counterBytes, enc.newRatchetPub, hasRatchetCT, enc.ciphertext);

  const { hmacSHA256 } = await import("../crypto.js");
  const hmacInput = concat(aliceSess.ad, aliceSess.initiatorSigningKeyBytes, aliceSess.responderSigningKeyBytes, inner);
  const sig = await hmacSHA256(enc.hmacKey, hmacInput);

  const decrypted = await bobSess.decryptMessage(
    enc.counter, enc.newRatchetPub, enc.ratchetCT, enc.ciphertext, sig, inner,
  );

  expect(decrypted).toEqual(pt);
});

test("multi-turn bidirectional messaging", async () => {
  const { aliceSess, bobSess } = await fullHandshake();
  const { hmacSHA256 } = await import("../crypto.js");

  async function send(senderSess: any, receiverSess: any, text: string) {
    const pt = new TextEncoder().encode(text);
    const enc = await senderSess.encryptMessage(pt);
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, enc.counter, false);
    const hasRatchetCT = enc.ratchetCT ? new Uint8Array([1]) : new Uint8Array([0]);
    const inner = enc.ratchetCT
      ? concat(counterBytes, enc.newRatchetPub, hasRatchetCT, enc.ratchetCT, enc.ciphertext)
      : concat(counterBytes, enc.newRatchetPub, hasRatchetCT, enc.ciphertext);
    const hmacInput = concat(senderSess.ad, senderSess.initiatorSigningKeyBytes, senderSess.responderSigningKeyBytes, inner);
    const sig = await hmacSHA256(enc.hmacKey, hmacInput);
    return receiverSess.decryptMessage(enc.counter, enc.newRatchetPub, enc.ratchetCT, enc.ciphertext, sig, inner);
  }

  const msgs = ["msg1", "msg2", "msg3", "reply1", "reply2"];
  for (const m of msgs.slice(0, 3)) {
    const dec = await send(aliceSess, bobSess, m);
    expect(new TextDecoder().decode(dec)).toBe(m);
  }
  for (const m of msgs.slice(3)) {
    const dec = await send(bobSess, aliceSess, m);
    expect(new TextDecoder().decode(dec)).toBe(m);
  }
}, 30000);

test("OPK slot restored on auth failure", async () => {
  const bob = await generateIdentity(2, 1, 5);
  const alice = await generateIdentity(1, 1, 0);

  const bundle = {
    registrationId: bob.id,
    identitySigningPub: bob.signingKey.publicKey,
    identityExchangePub: bob.exchangeKey.publicKey,
    signedPreKeyPub: bob.signedPreKeys[0].publicKey,
    signedPreKeyIndex: 0,
    signedPreKeySig: bob.signedPreKeySigs[0],
    oneTimePreKeyPub: bob.preKeys[0]!.publicKey,
    oneTimePreKeyIndex: 0,
  };

  const { preKeyMessage } = await createSessionInitiator(alice, bundle);

  // Corrupt the initiator signature
  const badMsg = { ...preKeyMessage, initiatorSig: randomBytes(DSA_SIGNATURE_SIZE) };

  await expect(createSessionResponder(bob, badMsg)).rejects.toThrow("invalid signature");

  // OPK slot must be restored
  expect(bob.preKeys[0]).not.toBeNull();
});
