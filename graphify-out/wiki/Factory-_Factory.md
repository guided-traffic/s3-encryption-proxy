# Factory: Factory

> 20 nodes · cohesion 0.18

## Key Concepts

- **KeyEncryptor** (21 connections) — `pkg/encryption/interfaces.go`
- **Factory** (10 connections) — `pkg/encryption/factory/factory.go`
- **NewFactory()** (9 connections) — `pkg/encryption/factory/factory.go`
- **NewAESProvider()** (9 connections) — `pkg/encryption/keyencryption/aes.go`
- **.Fingerprint()** (7 connections) — `pkg/encryption/interfaces.go`
- **FacFactoryWithAES()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.CreateKeyEncryptorFromConfig()** (5 connections) — `pkg/encryption/factory/factory.go`
- **.GetKeyEncryptor()** (5 connections) — `pkg/encryption/factory/factory.go`
- **KeyEncryptionType** (5 connections) — `pkg/encryption/factory/factory.go`
- **.createAESKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.createExitKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.ActiveKeyEncryptor()** (4 connections) — `internal/orchestration/providers.go`
- **TestFacAESFingerprintIsDerivedFromTheKeyNotHashedFromIt()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateKeyEncryptorFromConfigTypes()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFactory_CreateKeyEncryptorFromConfig()** (4 connections) — `pkg/encryption/factory/factory_test.go`
- **.RegisterKeyEncryptor()** (3 connections) — `pkg/encryption/factory/factory.go`
- **TestFacRegisterKeyEncryptorKeysByFingerprint()** (3 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestAESProviderRejectsAnythingButBase64Of32Bytes()** (3 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **.GetActiveProviderAlgorithm()** (2 connections) — `internal/orchestration/providers.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (13 shared connections)
- [Keyencryption: Aes Test](Keyencryption-_Aes_Test.md) (7 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (7 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (5 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (5 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (2 shared connections)
- [Config: Config](Config-_Config.md) (2 shared connections)
- [S3Enc: Client](S3Enc-_Client.md) (1 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers.go`
- `pkg/encryption/factory/factory.go`
- `pkg/encryption/factory/factory_coverage_test.go`
- `pkg/encryption/factory/factory_test.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/aes_test.go`

## Audit Trail

- EXTRACTED: 58 (71%)
- INFERRED: 24 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*