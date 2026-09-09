# Tink KMS Provider Stub

> 14 nodes · cohesion 0.25

## Key Concepts

- **TinkProvider** (11 connections) — `pkg/encryption/keyencryption/tink.go`
- **NewTinkProviderFromConfig()** (8 connections) — `pkg/encryption/keyencryption/tink.go`
- **tink.go** (5 connections) — `pkg/encryption/keyencryption/tink.go`
- **NewTinkProvider()** (5 connections) — `pkg/encryption/keyencryption/tink.go`
- **github.com/google/tink/go/keyset.Handle** (3 connections)
- **TinkConfig** (3 connections) — `pkg/encryption/keyencryption/tink.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/keyencryption/tink.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/keyencryption/tink.go`
- **.Fingerprint()** (3 connections) — `pkg/encryption/keyencryption/tink.go`
- **loadKEKHandle()** (3 connections) — `pkg/encryption/keyencryption/tink.go`
- **.Validate()** (2 connections) — `pkg/encryption/keyencryption/tink.go`
- **.RotateKEK()** (2 connections) — `pkg/encryption/keyencryption/tink.go`
- **github.com/google/tink/go/tink.AEAD** (1 connections)
- **.Name()** (1 connections) — `pkg/encryption/keyencryption/tink.go`

## Relationships

- [None Provider Pass-Through](None_Provider_Pass-Through.md) (4 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)

## Source Files

- `pkg/encryption/keyencryption/tink.go`

## Audit Trail

- EXTRACTED: 27 (90%)
- INFERRED: 3 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*