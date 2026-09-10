# AES KEK Provider

> 59 nodes · cohesion 0.07

## Key Concepts

- **NewAESKeyEncryptor()** (15 connections) — `pkg/encryption/keyencryption/aes.go`
- **KeyEncryptor** (12 connections) — `pkg/encryption/interfaces.go`
- **aes_test.go** (11 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **Factory** (10 connections) — `pkg/encryption/factory/factory.go`
- **NewFactory()** (9 connections) — `pkg/encryption/factory/factory.go`
- **KekNewAES()** (9 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **testKEK()** (9 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **AESProvider** (7 connections) — `pkg/encryption/keyencryption/aes.go`
- **aes_coverage_test.go** (7 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **NewAESProvider()** (7 connections) — `pkg/encryption/keyencryption/aes.go`
- **factory_coverage_test.go** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **FacFactoryWithAES()** (6 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **.createAESKeyEncryptor()** (5 connections) — `pkg/encryption/factory/factory.go`
- **.CreateKeyEncryptorFromConfig()** (5 connections) — `pkg/encryption/factory/factory.go`
- **KeyEncryptionType** (5 connections) — `pkg/encryption/factory/factory.go`
- **ExitProvider** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **NewExitProvider()** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **.createExitKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory.go`
- **.wrapAEAD()** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **TestFacCreateKeyEncryptorFromConfigTypes()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFacGetKeyEncryptor()** (4 connections) — `pkg/encryption/factory/factory_coverage_test.go`
- **TestFactory_CreateKeyEncryptorFromConfig()** (4 connections) — `pkg/encryption/factory/factory_test.go`
- **TestKekAESDEKRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNewProviderFromConfigMap()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestAESKeyEncryptorFingerprintDiffersPerKey()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- *... and 34 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (25 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (4 shared connections)
- [Provider Manager](Provider_Manager.md) (3 shared connections)
- [Performance Harness](Performance_Harness.md) (2 shared connections)

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

- EXTRACTED: 120 (82%)
- INFERRED: 26 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*