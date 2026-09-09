# RSA KEK Provider

> 6 nodes · cohesion 0.47

## Key Concepts

- **RSAProvider** (8 connections) — `pkg/encryption/keyencryption/rsa.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/keyencryption/rsa.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/keyencryption/rsa.go`
- **.Fingerprint()** (3 connections) — `pkg/encryption/keyencryption/rsa.go`
- **.RotateKEK()** (2 connections) — `pkg/encryption/keyencryption/rsa.go`
- **.Name()** (1 connections) — `pkg/encryption/keyencryption/rsa.go`

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [RSA Provider Implementation](RSA_Provider_Implementation.md) (2 shared connections)
- [RSA KEK Provider Tests](RSA_KEK_Provider_Tests.md) (1 shared connections)

## Source Files

- `pkg/encryption/keyencryption/rsa.go`

## Audit Trail

- EXTRACTED: 13 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*