# pqc-ratchet

> **v0 — no API or wire stability guarantees.** Interfaces, wire formats, and key
> derivation constants may change without notice and without a migration path.

A post-quantum variant of the [Double Ratchet][dr] and [X3DH][x3dh] key agreement
protocols, implemented in Go.

This is a clean-break redesign of [2key-ratchet][2kr] that replaces all classical
asymmetric primitives with NIST PQC standards, while keeping the symmetric ratchet
(AES-256-GCM, HMAC-SHA-256, HKDF-SHA-256) unchanged.

> **Not wire-compatible with 2key-ratchet or Signal.** Both endpoints must use this
> library.

## Algorithm choices

| Role | Algorithm | Standard |
|------|-----------|----------|
| Signing (identity keys, pre-key sigs) | ML-DSA-65 | FIPS 204 |
| Key exchange (X3DH + KEM ratchet) | ML-KEM-768 + X25519 (hybrid) | FIPS 203 + RFC 7748 |
| Message encryption | AES-256-GCM | FIPS 197 |
| Message authentication | HMAC-SHA-256 | FIPS 198 |
| KDF | HKDF-SHA-256 | SP 800-56C |

## Why not Signal's PQXDH?

Signal deployed [PQXDH][pqxdh] in 2023 as their production PQ handshake. pqcratchet
intentionally does not follow PQXDH, for one reason: **FIPS compliance**.

PQXDH's authentication uses XEdDSA over X25519. Neither is FIPS-approved — NIST SP 800-186
approves the NIST curves (P-256, P-384, P-521) for key agreement, not Curve25519, and
XEdDSA is Signal's own construction with no FIPS standing. Signal targets consumer
messaging where deniability and client compatibility matter; it does not target FIPS
environments.

pqcratchet uses ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) throughout. The result:

| Property | pqcratchet | PQXDH |
|----------|-----------|-------|
| FIPS-approved algorithms | ✓ | ✗ (XEdDSA, X25519) |
| PQ forward secrecy | ✓ | ✓ |
| PQ mutual authentication | ✓ | ✗ (classical only) |
| Deniability | ✗ | ✓ |
| Signal client interop | ✗ | ✓ |

The tradeoff: pqcratchet provides full PQ security (including authentication) at the cost
of deniability. PQXDH preserves deniability and Signal compatibility, but authentication
remains vulnerable to a quantum adversary. For FIPS-controlled environments,
pqcratchet's column is the right one.

One note: X25519 appears inside the hybrid KEM combiner as defence-in-depth against
ML-KEM failure. It is not used for authentication. For strict FIPS-primitives-only
deployments, X25519 can be removed (pure ML-KEM-768) or replaced with P-256.

See [DESIGN.md](DESIGN.md) for the full comparison, security proofs, and design rationale.

## Key and message sizes

```
Hybrid KEM public key:   1,216 bytes  (ML-KEM-768 1184 + X25519 32)
Hybrid KEM ciphertext:   1,120 bytes  (ML-KEM-768 1088 + X25519 ephemeral 32)
ML-DSA-65 public key:    1,952 bytes
ML-DSA-65 signature:     3,309 bytes

PreKeyBundle:            ~10 KB       (vs ~500 bytes classically)
Per-message overhead:    ~2.3 KB      (ratchet pub + epoch ciphertext)
```

## Why not MLS?

MLS (RFC 9420) solves a different problem. MLS is a *group* key agreement protocol — its
central abstraction is a membership roster with cryptographically enforced add/remove
semantics and a shared group epoch. You want MLS when the questions are "who is in this
group?" and "does removing Alice revoke her access to future messages?"

pqcratchet is a **point-to-point, store-and-forward encrypted transport**. There is no
group, no membership roster, no shared epoch. Two parties. One or both can be offline at
session setup. Each session is independent.

If your use case is two parties communicating asynchronously, pqcratchet is the right
shape and MLS is overengineering. If your use case is a set of parties sharing a channel
with cryptographically enforced membership — device sets, org keys, multi-party
conversations — MLS is the right tool and pqcratchet is the wrong shape.

See [DESIGN.md](DESIGN.md) for the full analysis.



```go
import pqc "github.com/PeculiarVentures/pqc-ratchet/pqcratchet"

// Bob: generate identity, publish bundle
bobID, _  := pqc.GenerateIdentity(1, 10, 50)
aliceID, _ := pqc.GenerateIdentity(2, 10, 50)

bundle := &pqc.PreKeyBundle{
    RegistrationID:     bobID.ID,
    IdentitySigningPub: bobID.SigningKey.Public,
    IdentityExchangePub: &bobID.ExchangeKey.Public,
    SignedPreKeyPub:    &bobID.SignedPreKeys[0].Public,
    SignedPreKeyIndex:  0,
    SignedPreKeySig:    bobID.SignedPreKeySigs[0],
}

// Alice: create session from bundle
aliceSess, result, _ := pqc.CreateSessionInitiator(aliceID, bundle)
defer pqc.ZeroKEMKeyPair(result.EphemeralKP)

// Build and send PreKeyMessage to Bob...

// Bob: create session from PreKeyMessage
bobSess, _ := pqc.CreateSessionResponder(bobID, pkm)

// Alice: encrypt
enc, _ := aliceSess.EncryptMessage([]byte("hello"))

// Bob: decrypt
plaintext, _ := bobSess.DecryptSignedMessage(signedMsg)
```

## Running tests

```bash
go test ./pqcratchet/...
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/cloudflare/circl/kem/mlkem/mlkem768` | ML-KEM-768 (FIPS 203) |
| `github.com/cloudflare/circl/sign/mldsa/mldsa65` | ML-DSA-65 (FIPS 204) |
| `golang.org/x/crypto/curve25519` | X25519 (hybrid KEM classical component) |
| `golang.org/x/crypto/hkdf` | HKDF-SHA-256 |

No CGo. No code generation.

## Security notes

This implementation has not been independently audited.

The X3DH construction follows Hashimoto et al. (PKC 2022), the first proven PQ-secure
X3DH replacement under standard assumptions. The Double Ratchet follows Alwen, Coretti,
Dodis (EUROCRYPT 2019) using a KEM-based CKA, with tight multi-session security bounds
per Collins, Riepel, Tran (ACM CCS 2024).

## Acknowledgements

- Original Double Ratchet and X3DH: Trevor Perrin and Moxie Marlinspike
- [2key-ratchet][2kr]: the classical implementation this derives from
- [cloudflare/circl][circl]: ML-KEM-768 and ML-DSA-65

[dr]: https://signal.org/docs/specifications/doubleratchet/
[x3dh]: https://signal.org/docs/specifications/x3dh/
[pqxdh]: https://signal.org/docs/specifications/pqxdh/
[2kr]: https://github.com/PeculiarVentures/2key-ratchet
[circl]: https://github.com/cloudflare/circl
