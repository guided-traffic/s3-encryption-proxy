# Content Type Factory Selection

> 16 nodes · cohesion 0.16

## Key Concepts

- **ContentType** (11 connections) — `pkg/encryption/factory/factory.go`
- **factory.go** (6 connections) — `pkg/encryption/factory/factory.go`
- **DetermineContentTypeFromHTTPContentType()** (6 connections) — `pkg/encryption/factory/factory.go`
- **KeyEncryptionType** (5 connections) — `pkg/encryption/factory/factory.go`
- **TestFacKeyEncryptionTypeConstants()** (5 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFactory_CreateEnvelopeEncryptor()** (4 connections) — `pkg/encryption/factory/factory_test.go`
- **TestFactory_CreateKeyEncryptorFromConfig()** (4 connections) — `pkg/encryption/factory/factory_test.go`
- **content_type_test.go** (3 connections) — `pkg/encryption/factory/content_type_test.go`
- **TestAutomaticThresholdAccuracy()** (3 connections) — `pkg/encryption/factory/content_type_test.go`
- **TestDetermineContentTypeFromHTTPContentType()** (3 connections) — `pkg/encryption/factory/content_type_test.go`
- **TestFacDetermineContentTypeBoundaries()** (3 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **factory_test.go** (3 connections) — `pkg/encryption/factory/factory_test.go`
- **TestFactory_GetRegisteredKeyEncryptors()** (3 connections) — `pkg/encryption/factory/factory_test.go`
- **.GetRegisteredProviderInfo()** (2 connections) — `pkg/encryption/factory/factory.go`
- **ProviderInfo** (2 connections) — `pkg/encryption/factory/factory.go`
- **TestContentTypeConstants()** (2 connections) — `pkg/encryption/factory/content_type_test.go`

## Relationships

- [Encryption Factory Tests](Encryption_Factory_Tests.md) (10 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (8 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (3 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (2 shared connections)
- [Orchestration Manager Tests](Orchestration_Manager_Tests.md) (1 shared connections)
- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (1 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (1 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)

## Source Files

- `pkg/encryption/factory/content_type_test.go`
- `pkg/encryption/factory/factory.go`
- `pkg/encryption/factory/factory_coverage_test.go`
- `pkg/encryption/factory/factory_test.go`

## Audit Trail

- EXTRACTED: 33 (72%)
- INFERRED: 13 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*