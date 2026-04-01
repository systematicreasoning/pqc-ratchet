# pqc-ratchet

Post-quantum Double Ratchet + X3DH in Go and TypeScript.

```
go/   — Go implementation (FIPS 203/204, circl, standard library)
ts/   — TypeScript implementation (WebCrypto, @noble/post-quantum)
```

Both implementations share the same binary wire format and are verified by a
cross-language interop test (`go/pqcratchet/interop_test.go`).

## Algorithms

| Role | Algorithm | Standard |
|------|-----------|----------|
| Signing | ML-DSA-65 | FIPS 204 |
| Key exchange | ML-KEM-768 + X25519 (hybrid) | FIPS 203 + RFC 7748 |
| Message encryption | AES-256-GCM | FIPS 197 |
| Message authentication | HMAC-SHA-256 | FIPS 198 |
| KDF | HKDF-SHA-256 | SP 800-56C |

## Quick start

```bash
# Go
cd go && go test ./pqcratchet/...

# TypeScript
cd ts && npm install && npm test

# Cross-language interop test (Go ↔ TypeScript on the same wire format)
cd ts && npx tsc && cd ..
cd go && go test ./pqcratchet/... -run TestInteropGoTS -v
```

### Sending a message (TypeScript)

```typescript
import { generateIdentity, createSessionInitiator, createSessionResponder }
  from "@peculiarventures/pqc-ratchet";

const alice = await generateIdentity(1, 2, 10);
const bob   = await generateIdentity(2, 2, 10);

const bundle = {
  registrationId:      bob.id,
  identitySigningPub:  bob.signingKey.publicKey,
  identityExchangePub: bob.exchangeKey.publicKey,
  signedPreKeyPub:     bob.signedPreKeys[0].publicKey,
  signedPreKeyIndex:   0,
  signedPreKeySig:     bob.signedPreKeySigs[0],
  oneTimePreKeyPub:    bob.preKeys[0]!.publicKey,
  oneTimePreKeyIndex:  0,
};

const { session: aliceSess, preKeyMessage } = await createSessionInitiator(alice, bundle);
const bobSess = await createSessionResponder(bob, preKeyMessage);

// seal() and open() handle marshalling, HMAC, and signing internally
const wire = await aliceSess.seal(new TextEncoder().encode("hello"));
const pt   = await bobSess.open(wire);
console.log(new TextDecoder().decode(pt)); // "hello"
```

### Sending a message (Go)

```go
import pqc "github.com/PeculiarVentures/pqc-ratchet/pqcratchet"

aliceID, _ := pqc.GenerateIdentity(1, 2, 10)
bobID, _   := pqc.GenerateIdentity(2, 2, 10)

bundleWire, _ := pqc.MakeBundleWire(bobID, 0, 0)
bundle, _      := pqc.ParseBundleWire(bundleWire)
aliceSess, result, _ := pqc.CreateSessionInitiator(aliceID, bundle)
pkmBytes  := pqc.MarshalPreKeyMessageWire(result.ToPreKeyMessageWire(aliceID, bundle))
raw, _    := pqc.UnmarshalPreKeyMessageWire(bytes.NewReader(pkmBytes))
pkm, _    := pqc.ParsePreKeyMessageWire(raw)
bobSess, _ := pqc.CreateSessionResponder(bobID, pkm)

wire, _      := aliceSess.Seal([]byte("hello"))
plaintext, _ := bobSess.Open(wire)
fmt.Println(string(plaintext)) // "hello"
```

## Repository layout

```
go/
  pqcratchet/        core library
  cmd/interop_gen/   standalone fixture generator
  DESIGN.md          full design rationale and security analysis
  README.md

ts/
  src/               TypeScript source
  scripts/           interop_verify.mjs
  SECURITY_REVIEW.md TS-specific security review
  README.md
```

## v0 stability

No API or wire format stability guarantees. Not production-ready.
