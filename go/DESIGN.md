# pqcratchet design notes

## What this is

`pqcratchet` is a post-quantum variant of the Signal Double Ratchet and X3DH key agreement
protocols. It replaces every classical asymmetric primitive with NIST-standardised post-quantum
cryptography, while keeping the symmetric layer (now AES-256-GCM, HMAC-SHA-256, HKDF-SHA-256)
unchanged — those are already quantum-safe.

This document explains the design decisions, how the construction differs from the classical
Signal protocol, and why each choice was made.

---

## Algorithm choices

| Role | Algorithm | Standard | Replaces |
|------|-----------|----------|---------|
| Signing (identity keys, pre-key signatures) | ML-DSA-65 | FIPS 204 | Ed25519 |
| Key exchange (X3DH, KEM ratchet) | ML-KEM-768 + X25519 (hybrid) | FIPS 203 + RFC 7748 | X25519 |
| Symmetric encryption | AES-256-GCM | FIPS 197 | AES-256-CBC |
| Session MAC | HMAC-SHA-256 | FIPS 198 | HMAC-SHA-256 (unchanged) |
| KDF | HKDF-SHA-256 | RFC 5869 | HKDF-SHA-256 (unchanged) |

**Why ML-KEM-768?** It is the NIST-standardised KEM (FIPS 203) at the 128-bit post-quantum
security level. It is the closest PQC analogue to X25519 in role — both establish a shared
secret from a public key. The 768 variant balances key size and security margin.

**Why ML-DSA-65?** It is the NIST-standardised signature scheme (FIPS 204) at the 128-bit
post-quantum security level. It replaces Ed25519 for identity keys, pre-key signatures, and
the X3DH transcript signature.

**Why X25519 in a hybrid?** Neither ML-KEM-768 nor any other PQC algorithm has accumulated
the years of cryptanalytic scrutiny that Curve25519 has. The hybrid construction requires an
attacker to break *both* ML-KEM-768 *and* X25519 to compromise a shared secret. Classical
security is preserved while adding PQC protection.

### Assumption diversity: ML-DSA and ML-KEM share the same hard problem

Both ML-KEM-768 and ML-DSA-65 rest on the Module Learning With Errors (MLWE) problem over
structured lattices. This means a breakthrough against lattice cryptography would affect both
simultaneously. The hybrid KEM (ML-KEM-768 + X25519) addresses this for the key exchange
layer — X25519 provides a fallback if ML-KEM fails. No equivalent fallback exists for the
signing layer.

**SLH-DSA (FIPS 205) as a signing alternative.** SLH-DSA (standardised from SPHINCS+) is
purely hash-based: its security reduces to collision resistance of SHA-2 or SHA-3 with no
algebraic structure to attack. It is immune to a lattice breakthrough and is therefore the
natural candidate if ML-DSA-65 were ever broken or distrusted.

**Nothing in the protocol design prevents substituting SLH-DSA for ML-DSA-65.** Signing
occurs only at session establishment — never per message — specifically at three points:

1. Once at identity generation (sign the exchange public key)
2. Once per signed pre-key (sign each pre-key public key)
3. Once at session initiation (Alice signs the X3DH transcript)

Per-message authentication uses HMAC-SHA-256, not DSA. Signing speed is therefore not
critical: even SLH-DSA-128s (the slow/small variant at ~1–2 ms sign time) is negligible
at session setup frequency. The `Sign` and `Verify` abstraction in `sign.go` is a thin
wrapper that centralises all key type and constant definitions, so the substitution is a
one-file change.

**The cost of SLH-DSA is wire size.** Three signatures appear during session establishment:

| Signature | ML-DSA-65 | SLH-DSA-128s | SLH-DSA-128f |
|-----------|-----------|--------------|--------------|
| `ExchangeKeySig` in PreKeyBundle | 3,309 B | 7,856 B | 17,088 B |
| `SignedPreKeySig` in PreKeyBundle | 3,309 B | 7,856 B | 17,088 B |
| `InitiatorSig` in PreKeyMessage | 3,309 B | 7,856 B | 17,088 B |
| Public key per identity | 1,952 B | 32 B | 32 B |

SLH-DSA-128s roughly doubles session establishment message size. SLH-DSA-128f roughly
quintuples it. The public key savings (32 B vs 1,952 B) do not offset the signature growth.

SLH-DSA is a viable substitution if the threat model specifically requires independence from
lattice assumptions at the signing layer. For most deployments, ML-DSA-65 is the correct
choice: it is faster, produces smaller signatures, and its security has been extensively
analysed through the NIST standardisation process.

---

## Hybrid KEM construction

Every encapsulation and decapsulation combines ML-KEM-768 and X25519:

```
mlkemSS  = ML-KEM-768.Encap(recipientPub)
x25519SS = X25519(ephemeralPriv, recipientPub)
SS       = HKDF(mlkemSS ‖ x25519SS, salt=SHA256(recipientPub), info="pqcratchet/v1/HybridKEM")
```

The salt is SHA-256 of the recipient's full hybrid public key. This binds the combined secret
to the specific key pair, preventing cross-key confusion attacks where an attacker substitutes
a different public key to force a predictable combined secret.

Both component secrets flow through HKDF before any use. The IKM is `mlkemSS ‖ x25519SS`;
`append(mlkemSS, x25519SS...)` is safe because `mlkemSS` is a fresh allocation with
`cap == len`, so append allocates a new backing array and the two slices are independent.

The private key is stored as its 64-byte ML-KEM seed (`d ‖ z`, `KeySeedSize`) rather than
the 2400-byte expanded decapsulation key. `NewKeyFromSeed` reconstructs the full key on each
operation. This makes zeroing complete and trivial: the 64 seed bytes are the entire secret.

---

## X3DH with KEMs: what changed and why

The original X3DH protocol uses four DH computations to establish a shared secret. ML-KEM is
a KEM — you encapsulate against a public key and get a ciphertext plus a shared secret. The
decapsulator uses their private key to recover the same secret from the ciphertext. There is
no direct analogue to DH's property that either party can compute the same value.

### The construction

Alice (initiator) performs three encapsulations against Bob's public keys:

```
(ct1, ss1) = Encap(SPK_B)    // signed pre-key
(ct2, ss2) = Encap(IK_B.ex)  // Bob's identity exchange key
EK_A       = GenerateKEMKeyPair()   // ephemeral keypair (becomes initial ratchet key)
SK = HKDF(0xFF×32 ‖ ss1 ‖ ss2)

// with one-time pre-key:
(ct4, ss3) = Encap(OPK_B)
SK = HKDF(0xFF×32 ‖ ss1 ‖ ss2 ‖ ss3)
```

Alice sends to Bob: `{IK_A.ex, EK_A.pub, ct1, ct2, [ct4], InitiatorSig}`

Bob verifies `InitiatorSig` *before* decapsulating, then recovers `ss1`, `ss2`, `[ss3]`
and derives the same `SK`.

### Deniability is lost — this is intentional

In classical X3DH, DH computations are symmetric: given the public keys, anyone could have
computed the same shared secret. No transcript proves which party was the initiator. This is
cryptographic deniability — a desirable property for messaging.

In the KEM construction, anyone can encapsulate against Bob's public keys to produce `ct1`
and `ct2`. But there is no implicit proof of who encapsulated. Without additional authentication,
either party could claim the other sent the message. This is why `InitiatorSig` is required:
Alice must sign the transcript to prove she was the initiator, not just a passive observer.

The signature is non-repudiable: `InitiatorSig = Sign(IK_A.sig.sk, IK_A.ex ‖ ct1 ‖ ct2 ‖ EK_A.pub [‖ ct4])`.
This is a deliberate tradeoff. The X3DH spec §4.5 explicitly warns against replacing DH-based
mutual authentication with signatures. Applications with strong deniability requirements
should note this constraint.

### Why `IK_A.ex` is in the transcript

The transcript Alice signs is `IK_A.ex ‖ CT1 ‖ CT2 ‖ EK_A.pub [‖ CT4]`. Including `IK_A.ex`
explicitly binds Alice's identity exchange key into the signed statement. Without it, the
binding is indirect (via the separate `ExchangeKeySig` field in the wire format, which signs
`IK_A.ex` with `IK_A.sig`). Including it directly provides a single unforgeable statement:
"Alice, holding `IK_A.sig.sk`, produced these ciphertexts using `IK_A.ex`."

### Sig-before-decap prevents a decapsulation oracle

`AuthenticateB` verifies `InitiatorSig` before calling `Decapsulate` on any of the
ciphertexts. If this order were reversed, an attacker could send arbitrary ciphertexts
and observe whether Bob's session establishment succeeded, effectively turning Bob's
decapsulation into an oracle for testing ciphertexts against Bob's private keys.

### OPK mismatch is now an explicit error

Previously, if one side had an OPK private key but the other sent no CT4 (or vice versa),
the OPK contribution was silently skipped. Both sides would derive different root keys,
causing session establishment to fail at the first message decryption with no indication
of what went wrong. `AuthenticateB` now returns distinct errors for both mismatch cases,
surfacing the problem at the point it occurs.

---

## Double Ratchet: the KEM ratchet step

The Signal Double Ratchet alternates DH ratchet steps with symmetric chain steps. Each DH
ratchet step is:

```
dh_out = DH(ourRatchetPriv, theirRatchetPub)
RK, CK = KDF_RK(RK, dh_out)
```

Both parties can compute the same `dh_out` because DH is symmetric. With KEMs this is not
possible. Instead:

**Sender (KEM encapsulator):**
```
(ct, ss) = KEM.Encap(theirRatchetPub)
RK, CK   = KDF_RK(RK, ss)
// ct goes in the message header
```

**Receiver (KEM decapsulator):**
```
ss     = KEM.Decap(ourRatchetPriv, ct)
RK, CK = KDF_RK(RK, ss)
```

The sender generates a fresh ratchet keypair on each sending epoch. The old private key is
zeroed immediately before replacement, providing forward secrecy: a compromise of the current
state cannot recover keys from before the last ratchet step.

### `EpochRatchetCT` on every message

In the classical Double Ratchet, the ratchet public key in the message header is enough for
the receiver — they compute `DH(theirPriv, newRatchetPub)` locally without needing anything
from the sender. In the KEM ratchet, the receiver cannot compute the shared secret without
the ciphertext. The ciphertext is only generated once per epoch (on the first message).

If only the first message of an epoch carries the ciphertext, out-of-order delivery breaks:
a later message arriving before the first cannot initialise the receiving chain. To enable
out-of-order delivery, every message in a sending epoch carries `EpochRatchetCT` — the
ciphertext that opened the epoch. This adds 1,120 bytes per non-first message in an epoch.
That is the cost of out-of-order delivery in a KEM ratchet; there is no cheaper option that
preserves the same delivery guarantee without a `PN` (previous chain length) field or
buffering.

### `KDF_RK` implementation

```
PRK      = HKDF-Extract(ss, RootKey)   // RootKey as salt, ss as IKM
RK, CK   = HKDF-Expand(PRK, "pqcratchet/v1/Ratchet")[0:64]
```

This matches the Double Ratchet spec: `RK` is the HKDF key. In RFC 5869 terms, the key maps
to the `salt` parameter of Extract, and the shared secret is the IKM.

---

## Symmetric layer: AES-256-GCM replaces AES-256-CBC

The original 2key-ratchet used AES-256-CBC + HMAC-SHA-256 in Encrypt-then-MAC order. This
is a secure construction when the HMAC is verified before decryption, which prevents padding
oracle attacks. It was inherited unchanged in early versions of this library.

AES-256-GCM was substituted for several concrete reasons:

**Single AEAD primitive.** GCM provides confidentiality and authentication in one hardware-
accelerated operation. CBC + HMAC requires two key derivations and two passes over the data.

**No padding.** CBC requires PKCS7 padding (1–16 bytes), which leaks plaintext length at
block granularity and has been a persistent source of implementation bugs (`ErrBadPadding`
and the PKCS7 unpadding code are eliminated entirely).

**KDF-derived nonce, uniqueness guaranteed.** The 12-byte GCM nonce is derived from the
same HKDF step as the AES key. Since each message uses a fresh cipher key from the symmetric
ratchet, nonce reuse is impossible: distinct messages produce distinct cipher keys which
produce distinct nonces. The GCM safety boundary (2^32 encryptions per key) is unreachable.

**Hardware acceleration.** AES-GCM uses AES-NI + CLMUL on x86 and AES + PMULL on ARM.
CBC encryption is inherently sequential (each block depends on the previous ciphertext
block) and cannot be parallelised at the SIMD level; GCM counter mode can be.

### Two-layer authentication

Per-message key derivation produces 76 bytes: 32 (AES key) + 12 (GCM nonce) + 32 (outer HMAC key).

**Layer 1 — GCM tag (16 bytes, internal):** Authenticates the plaintext and binds it to the
session identity. The session AD (`Encode(IK_A.ex) ‖ Encode(IK_B.ex)`) is passed as GCM's
`additionalData` parameter to `Seal`/`Open`. The GCM tag therefore covers both the plaintext
and the session identity: a ciphertext produced in an Alice↔Bob session cannot be opened in
an Alice↔Carol session because the AD differs. Stripped and verified automatically by
`AESGCMDecrypt`.

**Layer 2 — outer HMAC-SHA-256:** Signs the entire serialised `MessageProtocol` wire frame
(which includes the GCM ciphertext+tag, `EpochRatchetCT`, counter, and sender ratchet pub)
plus the session AD and stable role signing keys:

```
HMAC(HMACKey, AD ‖ InitiatorSigningKeyBytes ‖ ResponderSigningKeyBytes ‖ messageRaw)
```

The outer HMAC is defence in depth: it covers fields that GCM does not see (the ratchet
ciphertext, counter, ratchet public key, and role signing keys). An attacker who could
somehow bypass the GCM tag would still need to forge the outer HMAC to make the receiver
accept a tampered message and advance its ratchet state. The two layers are complementary
rather than redundant — GCM authenticates the plaintext and session identity; the outer
HMAC authenticates the complete wire frame and role membership.

---

## HMAC input uses stable session roles, not local/remote perspective

The outer HMAC input is:

```
AD ‖ InitiatorSigningKeyBytes ‖ ResponderSigningKeyBytes ‖ messageRaw
```

`InitiatorSigningKeyBytes` is always Alice's signing key. `ResponderSigningKeyBytes` is
always Bob's. Neither flips when the conversation direction changes. Both sides set these
fields at session creation with the same values, so both sides compute the same HMAC input
regardless of who is currently encrypting.

An earlier version of this library used `LocalSigningKeyBytes` and `RemoteSigningKeyBytes`,
which flipped perspective between sender and receiver. From Alice's side as sender, `Local`
was Alice's key; from Bob's side as receiver, `Local` was Bob's key. The HMAC inputs were
different strings, so every message failed verification.

---

## Session snapshot and rollback

`DecryptSignedMessage` follows snapshot → speculate → verify → commit/rollback:

1. Take a full snapshot of session state (including `RatchetKP`).
2. Speculatively derive message keys, mutating the session.
3. Compute and verify the outer HMAC.
4. On success: commit (discard snapshot). On failure: `restore(snap)` and return `ErrHMACVerifyFailed`.

`RatchetKP` is included in the snapshot even though `deriveMessageKeysLocked` does not
directly modify it. The reason: `createReceivingChain` reads `s.RatchetKP.Private`, and
`encryptMessage` can zero and replace `RatchetKP` when taking a ratchet step. If these
operations were ever allowed to interleave (they currently cannot, due to the session mutex),
a rollback without restoring `RatchetKP` would leave the session with a zeroed private key
it can no longer use. Snapshotting the pointer makes the invariant explicit and enforced
rather than dependent on an implicit ordering assumption.

Note: the snapshot copies the `RatchetKP` pointer, not the struct. This is correct because
`encryptMessage` replaces `s.RatchetKP` with a new allocation (rather than mutating the
struct in place), so restoring the pointer correctly restores the old keypair.

---

## Skipped key cache

Out-of-order delivery is handled by caching message keys ahead of the current chain counter.
Two limits apply:

`MaxSkip = 1000` — the maximum number of keys cached across all ratchet epochs. When full,
`cacheSkippedKeys` returns `ErrSkippedKeyCapacity` (a named sentinel, not `nil`). Messages
whose keys were not cached cannot be decrypted later. This is a deliberate DoS defence: an
unbounded cache is exploitable by a sender who forces the receiver to store millions of keys.

`maxOldEpochSkip = 50` — when a new ratchet epoch arrives, the old epoch's chain is drained
forward by at most 50 keys, caching any messages from the old epoch that might arrive late.
This limit prevents a new epoch from exhausting the global cache by speculatively caching
1,000 keys that were never sent.

---

## Wire size implications

The switch from classical to PQC increases message sizes substantially:

| Component | Classical | PQC |
|-----------|-----------|-----|
| Public key (ratchet) | 32 B (X25519) | 1,216 B (hybrid) |
| KEM ciphertext | 32 B (X25519) | 1,120 B (hybrid) |
| Signing key | 32 B (Ed25519) | 1,952 B (ML-DSA-65) |
| Signature | 64 B (Ed25519) | 3,309 B (ML-DSA-65) |

Every message header carries `SenderRatchetPub` (1,216 B) and `EpochRatchetCT` (1,120 B),
for a baseline of 2,336 bytes of PQC overhead per message before any plaintext. The
PreKeyMessage (session establishment) additionally carries the X3DH ciphertexts and the
initiator signature, totalling approximately 9–10 KB depending on OPK usage.

These sizes are a direct consequence of the NIST PQC standards and cannot be reduced
without switching to smaller parameter sets (which reduce security margins) or using
lattice-based compression schemes outside the current standards.

---

## Relationship to PQXDH and other PQ X3DH constructions

Signal deployed PQXDH (Kret, Schmidt 2023) as its production PQ X3DH replacement in September 2023. The question of why pqcratchet does not follow PQXDH has a direct answer: **FIPS compliance**.

### Why pqcratchet does not use PQXDH

PQXDH's authentication mechanism is XEdDSA, Signal's own construction for turning Curve25519
keys into EdDSA-compatible signatures. Its key agreement uses X25519. Neither algorithm is
FIPS-approved: NIST SP 800-186 approves the NIST curves (P-256, P-384, P-521) for key
agreement, and FIPS 186-5 approves ECDSA and EdDSA over those curves — not Curve25519 and
not XEdDSA. Signal does not target FIPS environments and explicitly prioritises deniability
and Signal-client compatibility over compliance.

pqcratchet targets environments where FIPS compliance matters. Every asymmetric primitive
it uses is NIST-standardised:

- ML-KEM-768 for key encapsulation (FIPS 203)
- ML-DSA-65 for signing and authentication (FIPS 204)
- AES-256-GCM for symmetric encryption (FIPS 197)
- HMAC-SHA-256 for message authentication (FIPS 198)
- HKDF-SHA-256 for key derivation (SP 800-56C)

The tradeoff relative to PQXDH is explicit: pqcratchet provides post-quantum mutual
authentication (a quantum adversary cannot forge identity keys), at the cost of deniability
(ML-DSA-65 signatures are non-repudiable). PQXDH preserves deniability and Signal
compatibility, but authentication remains classically vulnerable — its identity keys are
still X25519/XEdDSA, which a sufficiently powerful quantum computer can attack.

**Note on X25519 in the hybrid KEM combiner.** X25519 appears inside `combineKEMSecrets`
as a conservative defence-in-depth measure: if ML-KEM-768 were ever broken, the X25519
component would still protect the combined secret. This is the only non-FIPS primitive in
the construction. For deployments requiring strict FIPS primitives-only, X25519 can be
removed and the combiner reduced to pure ML-KEM-768 — the ACD19 security proof applies
directly. Alternatively, X25519 can be replaced with P-256 (SP 800-186 approved) to
preserve the hybrid property with only approved algorithms.

### PQXDH: hybrid injection

PQXDH keeps the entire classical X3DH protocol unchanged and injects one KEM shared secret alongside the four DH outputs:

```
SK = KDF(DH1 || DH2 || DH3 || [DH4] || SS_KEM)
```

Bob publishes a signed post-quantum prekey (ML-KEM-1024 in Signal's instantiation) in addition to his classical prekeys. Alice encapsulates against this key and includes the ciphertext in her initial message. The DH computations (X25519) remain, and authentication still relies on classical hardness (discrete logarithm). The spec explicitly states it "still relies on the hardness of the discrete log problem for mutual authentication in this revision."

**What PQXDH achieves:** post-quantum *forward secrecy* (a passive quantum adversary recording traffic today cannot decrypt it later). Classical deniability is preserved because the DH transcript remains. PQXDH is backward-compatible with X3DH infrastructure.

**What PQXDH does not achieve:** post-quantum mutual *authentication*. If a quantum adversary can forge classical identity keys, PQXDH sessions can be impersonated.

### pqcratchet: clean break

pqcratchet replaces all classical asymmetric primitives:

```
SK = HKDF(0xFF×32 || ss1 || ss2 [|| ss3])
```

where `ss1`, `ss2`, `ss3` are all from ML-KEM-768 encapsulations. Authentication uses ML-DSA-65, providing post-quantum mutual authentication. There are no X25519 DH computations in the handshake (X25519 appears only inside the hybrid KEM combiner, where it is a defence in depth against ML-KEM weakness, not the primary authentication mechanism).

**What pqcratchet achieves:** post-quantum forward secrecy *and* post-quantum mutual authentication. An adversary with a quantum computer cannot decrypt past traffic (FS) or forge new sessions (authentication).

**What pqcratchet does not achieve:** deniability. ML-DSA-65 is non-repudiable — Alice's signature over the transcript proves she initiated. PQXDH preserves deniability because the DH component remains.

### The deniability tradeoff in the research literature

The tension between PQ authentication and deniability has been studied extensively:

**Brendel et al. 2019/2020** (SAC 2020, ePrint 2019/1356) identified the fundamental problem: KEMs cannot provide the symmetric shared-secret computation that gives DH its implicit authentication and deniability. They introduced the *split KEM* abstraction but could not instantiate it securely from PQ assumptions under active adversaries.

**Hashimoto et al. 2022** (PKC 2022, ePrint 2021/616, the paper pqcratchet follows) solved this by adding an explicit signature, giving the first proven-secure PQ X3DH replacement under standard assumptions. They show how to restore deniability progressively using ring signatures or NIZKs, at the cost of complexity. This package implements their basic (weakly deniable) construction.

**Brendel, Fiedler, Günther, Janson, Stebila 2022** (PKC 2022, ePrint 2021/769) — SPQR — achieves deniability using designated-verifier signatures. No efficient PQ DVS scheme was available at the time; they use ring signatures as a substitute.

**Collins, Huguenin-Dumittan, Nguyen, Rolin, Vaudenay 2024** (ASIACCS 2025, ePrint 2024/120) — K-Waay — achieves efficient deniable PQ X3DH using a split-KEM without ring signatures, and is currently the most efficient deniable construction.

### Formal verification of PQXDH

Bhargavan et al. (USENIX Security 2024) formally verified PQXDH using ProVerif and CryptoVerif. Their analysis found two issues addressed in PQXDH Revision 2:

1. A public-key encoding confusion attack: if EC and KEM keys are the same byte length, an attacker can substitute one for the other. Mitigated in PQXDH by requiring all encoding function ranges to be pairwise disjoint. In pqcratchet this cannot arise structurally — `HybridKEMPublicKey` (1216 B) and `DSAPublicKey` (1952 B) are different types with different sizes.

2. A KEM re-encapsulation attack: an attacker re-encapsulates the same shared secret under a different public key if the KEM does not bind its ciphertext to the specific key. ML-KEM-768 is IND-CCA2 and binds the ciphertext to the public key, so pqcratchet is not vulnerable. The `combineKEMSecrets` HKDF call additionally uses `SHA256(recipientPub)` as salt, providing a second binding.

### Which to use

| Property | PQXDH | pqcratchet |
|----------|--------|-----------|
| PQ forward secrecy | ✓ | ✓ |
| PQ mutual authentication | ✗ (classical) | ✓ |
| Deniability | ✓ (classical) | ✗ |
| Wire-compatible with Signal | ✓ | ✗ |
| Formally verified | ✓ (Bhargavan et al. 2024) | ✗ (X3DH component) |

pqcratchet is the right choice for new systems that want full PQ security and can accept non-deniability. PQXDH is the right choice for Signal-compatible deployments or applications where deniability is a requirement.

---

## Formal security

### Framework

This construction is an instantiation of the modular Double Ratchet framework
of Alwen, Coretti, and Dodis (ACD19) [1]. ACD19 decomposes a secure messaging
scheme into three abstract components and proves their composition secure (Theorem 1):

**CKA (Continuous Key Agreement)** — the public-key ratchet. `createSendingChain`
implements CKA-S (sender step) and `createReceivingChain` implements CKA-R
(receiver step). In each epoch the sender generates a fresh ratchet keypair and
encapsulates against the remote ratchet key; the receiver decapsulates once and
both parties advance the root key with the same shared secret. ACD19 Theorem 2
proves this KEM-based CKA is secure if the KEM is IND-CCA2 secure. ML-KEM-768
is IND-CCA2 secure under the Module Learning With Errors assumption (FIPS 203).

**FS-AEAD (Forward-Secure AEAD)** — the symmetric ratchet. `SymmetricChain.Step()`
and `DeriveMessageKeys()` implement FS-AEAD: each step derives a fresh message key
from the current chain state and advances the chain, making past keys unreachable.
AES-256-GCM satisfies the AEAD requirement. The session AD is passed as GCM
additional data, binding each ciphertext to the specific session identity at the
AEAD layer.

**PRF-PRNG** — the root key advancement function. `advanceRootKey()` implements
KDF_RK from the Double Ratchet spec [5] §2.2. ACD19 requires a two-input function
that is a PRF in the KEM shared secret and a PRG in the root key. HKDF-SHA-256
satisfies this in the random oracle model.

### Security properties

The ACD19 composition theorem gives the following properties:

**Forward security:** compromise of the current session state cannot recover
message keys from before the most recent ratchet step. The ratchet keypair private
key is zeroed when replaced, and old symmetric chain keys are unreachable after
`Step()` advances the chain.

**Post-compromise security (PCS):** after a state compromise, security is restored
within `∆_SM` rounds. For this implementation `∆_SM = 3` because the ratchet
keypair private key (`RatchetKP.Private`) is held in session state from the time
a receiving chain is initialised until the next sending epoch generates a new
keypair. This gives `∆_CKA = 1`, and `∆_SM = ∆_CKA + 2 = 3`.

This matches Signal's deployed DH ratchet (also `∆_CKA = 1`, `∆_SM = 3`).
The theoretical minimum `∆_SM = 2` (ACD19 KEM-CKA with `∆_CKA = 0`) would
require zeroing `RatchetKP.Private` immediately after `createReceivingChain()`
decapsulates and bootstrapping the next sending epoch from a different source.
That optimisation is not implemented.

**Immediate decryption / out-of-order delivery:** `EpochRatchetCT` is carried in
every message of a sending epoch, so any message can bootstrap the receiver's chain
regardless of arrival order. The skipped-key cache (`MaxSkip = 1000`) handles
messages arriving out of sequence within an epoch.

### Tight multi-session security

Collins, Riepel, and Tran (CRT24) [2] show that KEM-based Double Ratchet admits a
tight security reduction in the multi-session setting. Concretely, CRT24 Corollary
6.3 states that for any adversary against SMKEM (the KEM-based scheme), there exists
an adversary against the KEM with essentially the same advantage — no polynomial
loss in the number of sessions or epochs. Because pqcratchet uses a KEM-based CKA
with ML-KEM-768, this tight bound applies: security holds without degradation even
with large numbers of concurrent sessions.

### X3DH authentication

The KEM-based X3DH follows the structure of Hashimoto et al. [3], which provides
the first post-quantum secure replacement of the X3DH protocol under standard
assumptions. This implementation uses ML-DSA-65 direct signatures rather than the
designated-verifier signature approach in [3]; the security model is therefore
non-deniable (Alice cannot deny having initiated the session) rather than achieving
the weak deniability of [3]. See X3DH spec [4] §4.4–4.5 for the original deniability
analysis.

### References

[1] Alwen, Coretti, Dodis. "The Double Ratchet: Security Notions, Proofs, and
Modularization for the Signal Protocol." EUROCRYPT 2019.
https://eprint.iacr.org/2018/1037

[2] Collins, Riepel, Tran. "On the Tight Security of the Double Ratchet."
ACM CCS 2024.
https://eprint.iacr.org/2024/1625

[3] Hashimoto, Katsumata, Kwiatkowski, Prest. "An Efficient and Generic
Construction for Signal's Handshake (X3DH): Post-Quantum, State Leakage
Secure, and Deniable." PKC 2022.
https://eprint.iacr.org/2021/616

[4] Marlinspike, Perrin. "The X3DH Key Agreement Protocol." Signal, 2016.
https://signal.org/docs/specifications/x3dh/

[5] Marlinspike, Perrin. "The Double Ratchet Algorithm." Signal, 2016.
https://signal.org/docs/specifications/doubleratchet/ An
observer can correlate messages to the same session and determine message ordering. The
Double Ratchet spec §4 describes header encryption; it is not implemented here.

**Session persistence.** `Identity.MarshalJSON` / `UnmarshalJSON` are provided for identity
keys. Session state (`RootKey`, chains, skipped keys) is in-memory only. Persistent sessions
require serialising `Session` to stable storage; the field layout is exported for this purpose
but no serialiser is provided.

**Sparse ratchet / Triple Ratchet.** Signal's 2025 spec introduces a sparse post-quantum
ratchet (§5) and a Triple Ratchet (§6) that reduce the per-message PQC overhead by not taking
a KEM step on every message. This implementation takes a full KEM step on every sending epoch,
which provides maximum post-compromise security at the cost of higher bandwidth. The sparse
approach is appropriate for bandwidth-constrained deployments; the full-step approach is
correct for any deployment.

**Formal security proof.** No formal security proof exists that this 2-KEM X3DH construction
achieves Signal-conforming AKE security. The closest published work is Hashimoto et al. (2022),
"An Efficient and Generic Construction for Signal's Handshake (X3DH): Post-Quantum, State
Leakage Secure, and Deniable," which covers a different but related construction.

---

## What is not implemented

**Header encryption.** The sender's ratchet public key is transmitted in cleartext.

All HKDF operations use SHA-256. The info strings are:

| Usage | Info string |
|-------|-------------|
| X3DH session key derivation | `pqcratchet/v1/KEMInit` |
| KEM ratchet step KDF | `pqcratchet/v1/Ratchet` |
| Per-message key derivation | `pqcratchet/v1/MessageKeys` |
| Hybrid KEM secret combiner | `pqcratchet/v1/HybridKEM` |

The hybrid KEM info string is used inside every `Encapsulate` and `Decapsulate` call.
Interop implementations must use the same strings.

---

## Why not MLS (Messaging Layer Security)?

This question comes up when comparing pqcratchet against RFC 9420. The honest answer is
that MLS and pqcratchet solve different problems, and the right way to see that is through
protocol shape rather than feature lists.

### What MLS actually is

MLS is a group key agreement protocol. Its central abstraction is a *group* — a membership
set with an authenticated roster. Members can be added, removed, and updated. The whole
group shares a common encryption epoch and advances that epoch together. The ratchet tree
(a binary tree of key material) is the mechanism that makes this efficient at scale. Group
state and membership semantics are the point; the encrypted transport that sits on top is
secondary.

MLS is the right answer when these questions matter:

- Who is currently in the group?
- Did this message come from a current member?
- When Alice is removed, does she lose access to future messages?
- How do we efficiently re-key 500 members without doing 500 individual key exchanges?

### What pqcratchet actually is

pqcratchet is a **point-to-point, store-and-forward encrypted transport with async
setup**. There is no group. There is no membership roster. There is no shared group
epoch. The unit of communication is a session between exactly two identities. Bob can
be offline when Alice sends the initial message — that is what X3DH pre-keys are for.

The Double Ratchet gives each session its own forward-secret, post-compromise-secure
symmetric ratchet. That ratchet is personal to the two parties; there is nothing to
synchronise with a third party.

If your use case is:

- Two parties communicating asynchronously
- One or both parties may be offline at session setup time
- Each session is independent (no shared group state)
- You need forward secrecy and post-compromise security per session

then pqcratchet is the right shape and MLS would be overengineering. MLS requires all
group members to participate in epoch advances; that synchronisation cost is the price
you pay for group membership semantics, and it is not free.

### When MLS would be the right choice instead

If your use case is:

- A set of parties that collectively share a conversation
- Membership changes (add/remove) need to be reflected cryptographically
- You need to revoke a removed member's access to future messages
- You are encrypting to a role or device set, not a fixed pair of identities

then pqcratchet is the wrong shape and MLS is correct. GoodKey's group scenarios —
multiple devices, shared org keys, device onboarding and offboarding — are cases where
MLS semantics matter and the synchronisation cost is justified.

### Can you run pqcratchet sessions inside an MLS group?

Yes. MLS defines the group epoch and the shared symmetric key material. pqcratchet
could sit on top, using the MLS epoch key as the initial root key for a Double Ratchet
session between two specific members within the group. This gives per-session forward
secrecy on top of MLS group membership semantics. It is not a common pattern because
MLS already provides forward secrecy at the group level, but it is architecturally
valid.

### The short version

pqcratchet is the right choice when the question is "how do two parties communicate
securely and asynchronously." MLS is the right choice when the question is "how does
this group of parties share a secure channel with cryptographically enforced
membership." These are different questions. Choosing between them is not about which
protocol is newer or more sophisticated — it is about which problem shape matches your
use case.

---

## Compatibility

This implementation is not wire-compatible with `2key-ratchet` (the classical TypeScript
reference). It is a clean-break redesign sharing the same protocol structure but with
entirely different wire formats and key types. Both endpoints must use this library.
