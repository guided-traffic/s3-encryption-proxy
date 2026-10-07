# Keygen and KEK Factory

> 45 nodes · cohesion 0.09

## Key Concepts

- **NewAESKeyEncryptor()** (16 connections) — `pkg/encryption/keyencryption/aes.go`
- **KeyEncryptor** (12 connections) — `pkg/encryption/interfaces.go`
- **aes_test.go** (11 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **Factory** (10 connections) — `pkg/encryption/factory/factory.go`
- **NewFactory()** (9 connections) — `pkg/encryption/factory/factory.go`
- **KekNewAES()** (9 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **testKEK()** (9 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **NewAESProvider()** (8 connections) — `pkg/encryption/keyencryption/aes.go`
- **aes_coverage_test.go** (7 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **factory_coverage_test.go** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacFactoryWithAES()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.CreateKeyEncryptorFromConfig()** (5 connections) — `pkg/encryption/factory/factory.go`
- **KeyEncryptionType** (5 connections) — `pkg/encryption/factory/factory.go`
- **NewExitProvider()** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **.createAESKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.createExitKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **TestFacAESFingerprintIsDerivedFromTheKeyNotHashedFromIt()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateKeyEncryptorFromConfigTypes()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFactory_CreateKeyEncryptorFromConfig()** (4 connections) — `pkg/encryption/factory/factory_test.go`
- **TestKekAESDEKRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNewProviderFromConfigMap()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestAESKeyEncryptorFingerprintDiffersPerKey()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorFingerprintVector()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsForeignWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- *... and 20 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (25 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (3 shared connections)
- [Hostile Backend and Key Material ADRs](Hostile_Backend_and_Key_Material_ADRs.md) (3 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Readme](Readme.md) (1 shared connections)
- [AES KEK Vector Tests](AES_KEK_Vector_Tests.md) (1 shared connections)
- [Keygen Command](Keygen_Command.md) (1 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (1 shared connections)

## Source Files

- `pkg/encryption/factory/factory.go`
- `pkg/encryption/factory/factory_coverage_test.go`
- `pkg/encryption/factory/factory_test.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/aes_coverage_test.go`
- `pkg/encryption/keyencryption/aes_test.go`
- `pkg/encryption/keyencryption/exit.go`
- `pkg/encryption/keyencryption/exit_coverage_test.go`

## Audit Trail

- EXTRACTED: 103 (79%)
- INFERRED: 27 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*