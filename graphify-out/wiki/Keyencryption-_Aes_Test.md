# Keyencryption: Aes Test

> 21 nodes · cohesion 0.13

## Key Concepts

- **NewAESKeyEncryptor()** (18 connections) — `pkg/encryption/keyencryption/aes.go`
- **KekNewAES()** (9 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **testKEK()** (9 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestKekAESNewProviderFromConfigMap()** (5 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **NewExitProvider()** (5 connections) — `pkg/encryption/keyencryption/exit.go`
- **KekBytePattern()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESDEKRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestAESKeyEncryptorFingerprintDiffersPerKey()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorFingerprintVector()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsForeignWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsShortWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorRejectsTamperedWrap()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorWrapIsNotDeterministic()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptorWrapRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESProviderFromConfig()** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestKekExitProviderIdentity()** (4 connections) — `pkg/encryption/keyencryption/exit_coverage_test.go`
- **TestKekExitProviderRefusesEveryKeyUse()** (4 connections) — `pkg/encryption/keyencryption/exit_coverage_test.go`
- **TestKekAESEncryptDEKUsesFreshSalt()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESFingerprintStabilityAndUniqueness()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNewFromRawKEK()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestAESKeyEncryptorRejectsWrongKEKSize()** (3 connections) — `pkg/encryption/keyencryption/aes_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (21 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (18 shared connections)
- [Factory: Factory](Factory-_Factory.md) (7 shared connections)
- [Tampering Harness](Tampering_Harness.md) (1 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (1 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)

## Source Files

- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/aes_coverage_test.go`
- `pkg/encryption/keyencryption/aes_test.go`
- `pkg/encryption/keyencryption/exit.go`
- `pkg/encryption/keyencryption/exit_coverage_test.go`

## Audit Trail

- EXTRACTED: 61 (78%)
- INFERRED: 17 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*