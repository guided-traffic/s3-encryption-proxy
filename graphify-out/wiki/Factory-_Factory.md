# Factory: Factory

> 31 nodes · cohesion 0.11

## Key Concepts

- **KeyEncryptor** (21 connections) — `pkg/encryption/interfaces.go`
- **NewAESKeyEncryptor()** (18 connections) — `pkg/encryption/keyencryption/aes.go`
- **Factory** (10 connections) — `pkg/encryption/factory/factory.go`
- **NewFactory()** (9 connections) — `pkg/encryption/factory/factory.go`
- **NewAESProvider()** (9 connections) — `pkg/encryption/keyencryption/aes.go`
- **testKEK()** (9 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **FacFactoryWithAES()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.CreateKeyEncryptorFromConfig()** (5 connections) — `pkg/encryption/factory/factory.go`
- **KeyEncryptionType** (5 connections) — `pkg/encryption/factory/factory.go`
- **DecodeAESKey()** (5 connections) — `pkg/encryption/keyencryption/aes.go`
- **parseKey()** (5 connections) — `pkg/s3enc/client.go`
- **.createAESKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.createExitKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **TestFacAESFingerprintIsDerivedFromTheKeyNotHashedFromIt()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacCreateKeyEncryptorFromConfigTypes()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacKeyEncryptionTypeConstants()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFactory_CreateKeyEncryptorFromConfig()** (4 connections) — `pkg/encryption/factory/factory_test.go`
- **TestAESKeyEncryptorFingerprintDiffersPerKey()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorFingerprintVector()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsForeignWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsShortWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsTamperedWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorWrapIsNotDeterministic()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorWrapRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- *... and 6 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (28 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (23 shared connections)
- [Tampering Harness](Tampering_Harness.md) (6 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (5 shared connections)
- [S3Enc: Client](S3Enc-_Client.md) (2 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (1 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)

## Source Files

- `pkg/encryption/factory/factory.go`
- `pkg/encryption/factory/factory_coverage_test.go`
- `pkg/encryption/factory/factory_test.go`
- `pkg/encryption/interfaces.go`
- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/aes_coverage_test.go`
- `pkg/encryption/keyencryption/aes_test.go`
- `pkg/s3enc/client.go`

## Audit Trail

- EXTRACTED: 97 (78%)
- INFERRED: 27 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*