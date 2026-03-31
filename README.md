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
cd go
go test ./pqcratchet/...

# TypeScript
cd ts
npm install
npm test

# Interop test (requires Node ≥18 in PATH and ts/dist/ compiled)
cd ts && npx tsc && cd ..
cd go && go test ./pqcratchet/... -run TestInteropGoTS -v
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
