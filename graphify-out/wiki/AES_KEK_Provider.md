# AES KEK Provider

> 7 nodes · cohesion 0.38

## Key Concepts

- **AESProvider** (8 connections) — `pkg/encryption/keyencryption/aes.go`
- **.DecryptDEK()** (3 connections) — `pkg/encryption/keyencryption/aes.go`
- **.EncryptDEK()** (3 connections) — `pkg/encryption/keyencryption/aes.go`
- **.Fingerprint()** (3 connections) — `pkg/encryption/keyencryption/aes.go`
- **.RotateKEK()** (2 connections) — `pkg/encryption/keyencryption/aes.go`
- **crypto/cipher.Block** (1 connections)
- **.Name()** (1 connections) — `pkg/encryption/keyencryption/aes.go`

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [AES KEK Provider Tests](AES_KEK_Provider_Tests.md) (2 shared connections)

## Source Files

- `pkg/encryption/keyencryption/aes.go`

## Audit Trail

- EXTRACTED: 13 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*