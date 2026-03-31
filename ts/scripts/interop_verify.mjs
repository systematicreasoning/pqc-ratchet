#!/usr/bin/env node
/**
 * interop_verify.mjs — TypeScript (Bob) side of Go<->TS interop test.
 *
 * Reads a fixture produced by Go's interop_gen (Go=Alice, TS=Bob),
 * reconstructs Bob's session from the Go JSON identity + PreKeyMessage wire,
 * decrypts Go->TS messages, encrypts replies, writes a reply fixture.
 *
 * Usage: node scripts/interop_verify.mjs <fixture.json> <reply.json>
 * Requires: npx tsc (builds dist/)
 */

import { readFileSync, writeFileSync, existsSync } from "fs";

const distPath = new URL("../dist/index.js", import.meta.url).pathname;
if (!existsSync(distPath)) {
  console.error("dist/index.js not found — run: npx tsc");
  process.exit(1);
}
const mod = await import("../dist/index.js");
const {
  unmarshalPreKeyMessageWire, marshalSignedMessage, marshalMessageProtocol,
  unmarshalSignedMessage, buildHMACInput, createSessionResponder, hmacSHA256,
  kemKeyPairFromGoSeed,
} = mod;

const fromHex = s => new Uint8Array(Buffer.from(s, "hex"));
const toHex   = b => Buffer.from(b).toString("hex");

// ─── Args ─────────────────────────────────────────────────────────────────────
const [,, fixturePath, replyPath] = process.argv;
if (!fixturePath || !replyPath) {
  console.error("usage: interop_verify.mjs <fixture.json> <reply.json>");
  process.exit(1);
}
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

// ─── Reconstruct Bob's TS Identity from Go flat JSON ─────────────────────────
// Go serialises Identity with flat fields: signingPriv/signingPub,
// exchangePriv/exchangePub, signedPreKeyPrivs[], signedPreKeyPubs[],
// preKeyPrivs[], preKeyPubs[]

const bobRaw = JSON.parse(fixture.bobIdentityJSON);

// Go stores hybrid KEM private keys as 96-byte seeds (64B ML-KEM seed + 32B X25519).
// TS decapsulate requires 2432 bytes (2400B expanded ML-KEM + 32B X25519).
// kemKeyPairFromGoSeed expands the seed to the format TS needs.
const bobIdentity = {
  id:                   bobRaw.id,
  signingKey: {
    publicKey:  fromHex(bobRaw.signingPub),
    privateKey: fromHex(bobRaw.signingPriv),
  },
  exchangeKey:          kemKeyPairFromGoSeed(fromHex(bobRaw.exchangePriv)),
  exchangeKeySignature: fromHex(bobRaw.exchangeKeySig),
  signedPreKeys: (bobRaw.signedPreKeyPrivs || []).map(priv =>
    kemKeyPairFromGoSeed(fromHex(priv))
  ),
  signedPreKeySigs: (bobRaw.signedPreKeySigs || []).map(fromHex),
  preKeys: (bobRaw.preKeyPrivs || []).map(priv =>
    priv ? kemKeyPairFromGoSeed(fromHex(priv)) : null
  ),
};

// ─── Parse PreKeyMessage wire ─────────────────────────────────────────────────
const pkmBytes = fromHex(fixture.preKeyMessageHex);
const pkmWire  = unmarshalPreKeyMessageWire(pkmBytes);

const NO_OPK = 0xFFFFFFFF;
const preKeyMessage = {
  registrationId:      pkmWire.registrationID,
  identitySigningPub:  pkmWire.signingPub,
  identityExchangePub: pkmWire.exchangePub,
  exchangeKeySig:      pkmWire.exchangeKeySig,  // Alice's sig over her exchange key
  signedPreKeyIndex:   pkmWire.signedPreKeyIndex,
  oneTimePreKeyIndex:  pkmWire.oneTimePreKeyIndex === NO_OPK ? -1 : pkmWire.oneTimePreKeyIndex,
  baseKey:             pkmWire.baseKey,
  ct1:                 pkmWire.ct1,
  ct2:                 pkmWire.ct2,
  ct4:                 pkmWire.ct4,
  initiatorSig:        pkmWire.initiatorSig,
};

// ─── Establish Bob's session ──────────────────────────────────────────────────
let bobSess;
try {
  bobSess = await createSessionResponder(bobIdentity, preKeyMessage);
} catch (e) {
  console.error("FAIL createSessionResponder:", e.message);
  process.exit(1);
}
console.log("OK   Bob established session");

// ─── Decrypt Go->TS messages ──────────────────────────────────────────────────
async function decryptWireMessage(sess, wireHex) {
  const b = fromHex(wireHex);
  const { hmacSig, messageRaw, message } = unmarshalSignedMessage(b);
  return sess.decryptMessage(
    message.counter, message.senderRatchetPub, message.ratchetCT,
    message.ciphertext, hmacSig, messageRaw,
  );
}

for (let i = 0; i < fixture.goToTSMessages.length; i++) {
  let ptBytes;
  try {
    ptBytes = await decryptWireMessage(bobSess, fixture.goToTSMessages[i]);
  } catch (e) {
    console.error(`FAIL message ${i}: ${e.message}`);
    process.exit(1);
  }
  const got  = new TextDecoder().decode(ptBytes);
  const want = fixture.plaintexts[i];
  if (got !== want) {
    console.error(`FAIL message ${i}: got "${got}", want "${want}"`);
    process.exit(1);
  }
  console.log(`OK   message ${i}: "${got}"`);
}
console.log(`OK   decrypted ${fixture.goToTSMessages.length} Go->TS messages`);

// ─── Encrypt TS->Go replies ───────────────────────────────────────────────────
const replyPlaintexts = [
  "reply from TypeScript (1)",
  "second TS reply — ratchet advance",
  "third and final TS reply",
];

async function encryptToWire(sess, plaintext) {
  const enc  = await sess.encryptMessage(new TextEncoder().encode(plaintext));
  const inner = marshalMessageProtocol({
    counter: enc.counter, senderRatchetPub: enc.newRatchetPub,
    ratchetCT: enc.ratchetCT, ciphertext: enc.ciphertext,
  });
  const hmacInput = buildHMACInput(
    sess.ad, sess.initiatorSigningKeyBytes, sess.responderSigningKeyBytes, inner,
  );
  const sig  = await hmacSHA256(enc.hmacKey, hmacInput);
  return toHex(marshalSignedMessage(inner, sig));
}

const replyWires = [];
for (const pt of replyPlaintexts) {
  replyWires.push(await encryptToWire(bobSess, pt));
  console.log(`OK   encrypted reply: "${pt}"`);
}

writeFileSync(replyPath, JSON.stringify({ tsToGoMessages: replyWires, replyPlaintexts }, null, 2));
console.log(`OK   wrote reply: ${replyPath}`);
