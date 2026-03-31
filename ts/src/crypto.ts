/**
 * crypto.ts — symmetric cryptographic primitives using the WebCrypto API.
 *
 * Available in browsers, Node >= 18, Deno, and Bun.
 *
 * WebCrypto importKey/sign/encrypt require ArrayBuffer, not Uint8Array<ArrayBufferLike>.
 * We use toBuffer() to extract a clean ArrayBuffer regardless of how the
 * Uint8Array was allocated (handles sliced typed arrays).
 */

const subtle = globalThis.crypto.subtle;

/** Extract a clean ArrayBuffer from any Uint8Array (handles sliced buffers). */
function toBuffer(u: Uint8Array): ArrayBuffer {
  if (u.byteOffset === 0 && u.byteLength === u.buffer.byteLength) {
    return u.buffer as ArrayBuffer;
  }
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

// --- HKDF ------------------------------------------------------------------

/**
 * hkdfExtract: PRK = HMAC-SHA256(salt, ikm)  (RFC 5869 §2.2)
 */
export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  const saltKey = await subtle.importKey(
    "raw", toBuffer(salt),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const prk = await subtle.sign("HMAC", saltKey, toBuffer(ikm));
  return new Uint8Array(prk);
}

/**
 * hkdfExpand: OKM = T(1) || T(2) || ...  (RFC 5869 §2.3)
 */
export async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const prkKey = await subtle.importKey(
    "raw", toBuffer(prk),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const okm = new Uint8Array(length);
  let t = new Uint8Array(0);
  let pos = 0;
  for (let i = 1; pos < length; i++) {
    const input = concat(t, info, new Uint8Array([i]));
    const tBuf = await subtle.sign("HMAC", prkKey, toBuffer(input));
    t = new Uint8Array(tBuf);
    const take = Math.min(t.length, length - pos);
    okm.set(t.subarray(0, take), pos);
    pos += take;
  }
  return okm;
}

/**
 * hkdf: Extract-then-Expand.
 * Equivalent to Go's hkdf.New(sha256, ikm, salt, info) read to `length` bytes.
 */
export async function hkdf(
  ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number
): Promise<Uint8Array> {
  const prk = await hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

// --- HMAC-SHA-256 ----------------------------------------------------------

export async function hmacSHA256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey(
    "raw", toBuffer(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await subtle.sign("HMAC", k, toBuffer(data));
  return new Uint8Array(sig);
}

export async function hmacSHA256Verify(
  key: Uint8Array, data: Uint8Array, expected: Uint8Array
): Promise<boolean> {
  const k = await subtle.importKey(
    "raw", toBuffer(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  return subtle.verify("HMAC", k, toBuffer(expected), toBuffer(data));
}

// --- SHA-256 ---------------------------------------------------------------

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await subtle.digest("SHA-256", toBuffer(data));
  return new Uint8Array(hash);
}

// --- AES-256-GCM -----------------------------------------------------------

/**
 * aesGcmEncrypt encrypts plaintext with AES-256-GCM.
 * ad is the session associated data: Encode(IK_A.ex) || Encode(IK_B.ex).
 * Returns ciphertext || 16-byte tag.
 */
export async function aesGcmEncrypt(
  key: Uint8Array, nonce: Uint8Array, ad: Uint8Array, plaintext: Uint8Array
): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", toBuffer(key), { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: toBuffer(nonce), additionalData: toBuffer(ad), tagLength: 128 },
    k, toBuffer(plaintext)
  );
  return new Uint8Array(ct);
}

/**
 * aesGcmDecrypt decrypts and authenticates with AES-256-GCM.
 * Throws "pqcratchet: decryption failed" on authentication failure.
 */
export async function aesGcmDecrypt(
  key: Uint8Array, nonce: Uint8Array, ad: Uint8Array, ciphertext: Uint8Array
): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", toBuffer(key), { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: toBuffer(nonce), additionalData: toBuffer(ad), tagLength: 128 },
      k, toBuffer(ciphertext)
    );
    return new Uint8Array(pt);
  } catch {
    throw new Error("pqcratchet: decryption failed");
  }
}

// --- Helpers ---------------------------------------------------------------

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) { out.set(a, pos); pos += a.length; }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** Constant-time comparison. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Zero a Uint8Array in place. */
export function zero(buf: Uint8Array): void {
  buf.fill(0);
}

export function writeUint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, false);
  return buf;
}

export function readUint32BE(buf: Uint8Array, offset = 0): number {
  return new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, false);
}
