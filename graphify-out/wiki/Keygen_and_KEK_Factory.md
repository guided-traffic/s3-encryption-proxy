# Keygen and KEK Factory

> 70 nodes · cohesion 0.05

## Key Concepts

- **NewAESKeyEncryptor()** (16 connections) — `pkg/encryption/keyencryption/aes.go`
- **KeyEncryptor** (12 connections) — `pkg/encryption/interfaces.go`
- **aes_test.go** (11 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **Factory** (10 connections) — `pkg/encryption/factory/factory.go`
- **NewFactory()** (9 connections) — `pkg/encryption/factory/factory.go`
- **KekNewAES()** (9 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **testKEK()** (9 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **AESProvider** (8 connections) — `pkg/encryption/keyencryption/aes.go`
- **NewAESProvider()** (8 connections) — `pkg/encryption/keyencryption/aes.go`
- **aes_coverage_test.go** (7 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **aesVecProvider()** (7 connections) — `pkg/encryption/keyencryption/aes_vector_test.go`
- **factory_coverage_test.go** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacFactoryWithAES()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **printKey()** (5 connections) — `cmd/keygen/main.go`
- **.CreateKeyEncryptorFromConfig()** (5 connections) — `pkg/encryption/factory/factory.go`
- **KeyEncryptionType** (5 connections) — `pkg/encryption/factory/factory.go`
- **ExitProvider** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **NewExitProvider()** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **TestKeygenOutput()** (4 connections) — `cmd/keygen/main_test.go`
- **.createAESKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.createExitKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.wrapAEAD()** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **TestFacAESFingerprintIsDerivedFromTheKeyNotHashedFromIt()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateKeyEncryptorFromConfigTypes()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- *... and 45 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (31 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (4 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (3 shared connections)
- [Segmented GCM Reader and Writer](Segmented_GCM_Reader_and_Writer.md) (1 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Readme](Readme.md) (1 shared connections)

## Source Files

- `cmd/keygen/main.go`
- `cmd/keygen/main_test.go`
- `pkg/encryption/factory/factory.go`
- `pkg/encryption/factory/factory_coverage_test.go`
- `pkg/encryption/factory/factory_test.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/aes_coverage_test.go`
- `pkg/encryption/keyencryption/aes_test.go`
- `pkg/encryption/keyencryption/aes_vector_test.go`
- `pkg/encryption/keyencryption/exit.go`
- `pkg/encryption/keyencryption/exit_coverage_test.go`

## Audit Trail

- EXTRACTED: 141 (83%)
- INFERRED: 29 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*