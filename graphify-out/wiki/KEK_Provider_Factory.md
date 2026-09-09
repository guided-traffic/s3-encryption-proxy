# KEK Provider Factory

> 9 nodes · cohesion 0.47

## Key Concepts

- **KeyEncryptor** (22 connections) — `pkg/encryption/interfaces.go`
- **Factory** (15 connections) — `pkg/encryption/factory/factory.go`
- **.CreateKeyEncryptorFromConfig()** (6 connections) — `pkg/encryption/factory/factory.go`
- **.createAESKeyEncryptor()** (5 connections) — `pkg/encryption/factory/factory.go`
- **.createNoneKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.createRSAKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.GetKeyEncryptor()** (2 connections) — `pkg/encryption/factory/factory.go`
- **.RegisterKeyEncryptor()** (2 connections) — `pkg/encryption/factory/factory.go`
- **.GetRegisteredKeyEncryptors()** (1 connections) — `pkg/encryption/factory/factory.go`

## Relationships

- [AES KEK Provider Tests](AES_KEK_Provider_Tests.md) (5 shared connections)
- [Provider Manager DEK Cache](Provider_Manager_DEK_Cache.md) (4 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (4 shared connections)
- [Content Type Factory Selection](Content_Type_Factory_Selection.md) (3 shared connections)
- [RSA Provider Implementation](RSA_Provider_Implementation.md) (3 shared connections)
- [Encryption Factory Tests](Encryption_Factory_Tests.md) (3 shared connections)
- [None Provider Pass-Through](None_Provider_Pass-Through.md) (2 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (2 shared connections)
- [RSA KEK Provider Tests](RSA_KEK_Provider_Tests.md) (1 shared connections)

## Source Files

- `pkg/encryption/factory/factory.go`
- `pkg/encryption/interfaces.go`

## Audit Trail

- EXTRACTED: 44 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*