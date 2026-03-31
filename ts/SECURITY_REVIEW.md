# TypeScript Security Review

**Version reviewed:** initial v0 implementation  
**Review date:** 2025  
**Reviewer:** internal + LLM-assisted (GPT-4, Gemini, Grok cross-checked)  
**Go implementation review:** separate document — all findings fixed in `dcb9357`

---

## Summary

The TypeScript implementation is a port of the Go `pqcratchet` library. Two
**critical** bugs were found that affected all TS sessions, plus several
low/informational findings. All are resolved in the current codebase.

---

## Critical findings — fixed

### C1 — Wrong initial ratchet keypair in session establishment (both sides)

**Severity:** Critical — broke all cross-implementation sessions and silently
produced incorrect ratchet state in TS-only sessions.

**Files:** `src/identity.ts` (`createSessionInitiator`, `createSessionResponder`)

**Description:**

In `createSessionResponder`, Bob's initial ratchet keypair was set to
`responderIdentity.exchangeKey` (his long-term identity exchange key) instead of
`responderIdentity.signedPreKeys[msg.signedPreKeyIndex]` (the signed pre-key used
in the X3DH handshake).

In `createSessionInitiator`, Alice's initial remote ratchet key was set to
`bundle.identityExchangePub` (Bob's long-term identity exchange key) instead of
`bundle.signedPreKeyPub` (Bob's signed pre-key).

These two mistakes are mirror images of each other. In the Go implementation,
`CreateSessionResponder` explicitly sets `RatchetKP = signedPreKP` and
`CreateSessionInitiator` sets `CurrentStep.RemoteRatchetKey = bundle.SignedPreKeyPub`.

**Impact:**

In TS-only sessions, both Alice and Bob used the same wrong key, so each side
derived the same (incorrect) ratchet state. Sessions appeared to work internally
because the error was symmetric, but:

- Any message encrypted by a TS initiator could not be decrypted by a Go responder.
- Any message encrypted by a Go initiator could not be decrypted by a TS responder.
- The ratchet advanced through a different chain than the protocol specifies,
  differing from the formal security proof's assumptions.

**Detection:** Caught by the Go↔TS interop test (`TestInteropGoTS`), which fails
immediately when the HMAC of the first message does not verify.

**Fix:** `createSessionResponder` now uses `signedPreKP` (already computed above
for `authenticateB`) as Bob's ratchet KP. `createSessionInitiator` now sets
`remoteRatchetKey: bundle.signedPreKeyPub`. Both match Go exactly.

**Lesson:** Interop tests between implementations of the same protocol are
necessary even when all internal tests pass. The TS test suite was accidentally
self-consistent because both initiator and responder ran in the same process with
matching wrong values.

---

## Medium findings — fixed

### M1 — `buildHMACInput` and `WIRE_VERSION` exported from two modules

**Severity:** Medium — causes TypeScript compilation errors and ambiguous re-exports.

**File:** `src/index.ts`, `src/constants.ts`, `src/session.ts`, `src/wire.ts`

**Description:** When `wire.ts` was added as the canonical wire format module, it
exported `buildHMACInput` and `WIRE_VERSION`, both of which were already exported
from `session.ts` and `constants.ts` respectively. TypeScript's `export *` from
`index.ts` raised TS2308 (duplicate export name).

**Fix:** `buildHMACInput` removed from `session.ts` (definition moved to `wire.ts`;
internal call site inlined as `concat(...)`). `WIRE_VERSION` removed from
`constants.ts` (now only in `wire.ts`).

---

## Low / informational findings

### L1 — No mutex on OPK slot reservation (acceptable in single-threaded JS)

**Severity:** Low / informational

The Go implementation required a `sync.Mutex` fix (finding C1 in the Go review)
to prevent a TOCTOU race on OPK consumption under concurrent goroutines.
JavaScript/Node.js is single-threaded with a cooperative event loop: two `async`
function calls cannot interleave during synchronous code. The OPK slot
read-then-nil in `createSessionResponder` is executed synchronously before the
first `await`, so no concurrent access is possible.

**No fix required.** A comment documents this explicitly in `identity.ts`.

### L2 — ML-KEM private key format mismatch between Go and TypeScript

**Severity:** Low / informational (no security impact; documented)

Go stores hybrid KEM private keys as 96 bytes (64-byte ML-KEM seed + 32-byte
X25519 scalar). TypeScript stores the expanded 2432-byte form (2400-byte
ML-KEM `secretKey` + 32-byte X25519 scalar) because `@noble/post-quantum`'s
`ml_kem768.decapsulate` requires the expanded key, not the seed.

Wire formats (public keys, ciphertexts) are identical. Private key format
divergence is internal-only; private keys are never transmitted.

A `kemKeyPairFromGoSeed(goPriv: Uint8Array)` helper in `kem.ts` expands a
Go-serialised seed to the TS format. It is used by the interop test script when
loading Go-generated identity JSON.

### L3 — `constantTimeEqual` length check leaks lengths via early return

**Severity:** Low (negligible in practice for HMAC comparison)

`constantTimeEqual` returns `false` immediately if `a.length !== b.length`.
For HMAC comparison (fixed 32-byte lengths) this is a non-issue: both sides
always produce 32-byte outputs and the length will always match. If this function
were ever called to compare variable-length secrets, the early return could leak
length. The call site in `session.ts` only compares two HMAC-SHA-256 outputs,
both always 32 bytes.

No fix required given the single call site. Documented here for completeness.

### L4 — `@noble/post-quantum` argument order differs from Go circl

**Severity:** Low (fixed during initial implementation; documented for future maintainers)

`@noble/post-quantum` uses `sign(msg, secretKey)` and `verify(sig, msg, publicKey)`,
the reverse of Go's `circl` which uses `Sign(privateKey, msg)` and
`Verify(publicKey, msg, sig)`. This was corrected in `sign.ts` and is documented
in the source file header.

### L5 — `toBuffer()` for sliced TypedArrays

**Severity:** Low (correctly handled; documented)

WebCrypto APIs require `ArrayBuffer`, not `Uint8Array<ArrayBufferLike>`. When a
`Uint8Array` is created via `.slice()` or `.subarray()`, its `byteOffset` may be
non-zero and `byteLength` may differ from `buffer.byteLength`, causing WebCrypto
to silently process the wrong bytes in some environments.

`crypto.ts` implements `toBuffer()` which extracts a clean `ArrayBuffer` via
`buffer.slice(byteOffset, byteOffset + byteLength)` for non-contiguous buffers.
All WebCrypto calls use `toBuffer()`.

---

## Scope: what was not reviewed

- **No ProVerif / CryptoVerif machine-checked verification** of the X3DH
  transcript or Double Ratchet. This mirrors the Go implementation's known gap
  (documented in `DESIGN.md §What is not implemented`).
- **No audit of `@noble/post-quantum` internals.** Trail of Bits has audited this
  library; we rely on that audit. The library is not CMVP-validated.
- **No review of WebCrypto implementation quality** in any specific runtime
  (Node.js, browsers, Deno, Bun). We assume the runtime's WebCrypto is correct.

---

## Test coverage

| Category | Tests |
|----------|-------|
| KEM round-trip, wrong key, sizes, determinism | 5 |
| DSA sign/verify, wrong key, tamper | 3 |
| Symmetric chain, message key derivation | 2 |
| X3DH both sides, no OPK, invalid sig | 3 |
| Full handshake + encrypt/decrypt | 1 |
| Multi-turn bidirectional messaging | 1 |
| OPK restoration on auth failure | 1 |
| **Total** | **16** |

The interop test (`TestInteropGoTS` in the Go repo) adds cross-implementation
validation: 5 Go→TS messages and 3 TS→Go replies, all decrypted correctly.
