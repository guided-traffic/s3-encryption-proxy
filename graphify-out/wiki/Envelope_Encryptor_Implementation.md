# Envelope Encryptor Implementation

> 17 nodes · cohesion 0.14

## Key Concepts

- **EnvelopeEncryptor** (9 connections) — `pkg/encryption/envelope/envelope.go`
- **DataEncryptor** (7 connections) — `pkg/encryption/interfaces.go`
- **.CreateEnvelopeEncryptor()** (6 connections) — `pkg/encryption/factory/factory.go`
- **interfaces.go** (6 connections) — `pkg/encryption/interfaces.go`
- **.DecryptDataStream()** (4 connections) — `pkg/encryption/envelope/envelope.go`
- **.EncryptDataStream()** (4 connections) — `pkg/encryption/envelope/envelope.go`
- **EnvelopeEncryptor** (4 connections) — `pkg/encryption/interfaces.go`
- **.Fingerprint()** (3 connections) — `pkg/encryption/envelope/envelope.go`
- **.CreateEnvelopeEncryptor()** (3 connections) — `internal/orchestration/providers.go`
- **.GetDataEncryptor()** (2 connections) — `pkg/encryption/envelope/envelope.go`
- **.GetKeyEncryptor()** (2 connections) — `pkg/encryption/envelope/envelope.go`
- **.RotateKEK()** (2 connections) — `pkg/encryption/envelope/envelope.go`
- **.GetProvider()** (2 connections) — `internal/orchestration/manager.go`
- **envelope.go** (2 connections) — `pkg/encryption/envelope/envelope.go`
- **EncryptionProvider** (2 connections) — `pkg/encryption/interfaces.go`
- **EncryptionType** (1 connections) — `pkg/encryption/interfaces.go`
- **IVProvider** (1 connections) — `pkg/encryption/interfaces.go`

## Relationships

- [KEK Provider Factory](KEK_Provider_Factory.md) (4 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (4 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (2 shared connections)
- [AES-CTR Data Encryption Tests](AES-CTR_Data_Encryption_Tests.md) (2 shared connections)
- [AES-GCM Encryption Tests](AES-GCM_Encryption_Tests.md) (2 shared connections)
- [Content Type Factory Selection](Content_Type_Factory_Selection.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Provider Manager DEK Cache](Provider_Manager_DEK_Cache.md) (1 shared connections)
- [Ciphertext Size Arithmetic](Ciphertext_Size_Arithmetic.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `pkg/encryption/envelope/envelope.go`
- `pkg/encryption/factory/factory.go`
- `pkg/encryption/interfaces.go`

## Audit Trail

- EXTRACTED: 41 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*