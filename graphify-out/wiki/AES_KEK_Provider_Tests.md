# AES KEK Provider Tests

> 21 nodes · cohesion 0.16

## Key Concepts

- **KekNewAES()** (13 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **aes_coverage_test.go** (12 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **NewAESKeyEncryptor()** (9 connections) — `pkg/encryption/keyencryption/aes.go`
- **NewAESProvider()** (5 connections) — `pkg/encryption/keyencryption/aes.go`
- **aes.go** (4 connections) — `pkg/encryption/keyencryption/aes.go`
- **TestKekAESDEKRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNewProviderFromBase64()** (4 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **aes_test.go** (4 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestKekAESDecryptDEKRejectsForeignKeyID()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESDecryptDEKTooShort()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESEncryptDEKUsesFreshIV()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESFingerprintStabilityAndUniqueness()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNameAndRotateKEK()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNewFromRawKEK()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESNewProviderFromConfigMap()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **TestKekAESWrapIsUnauthenticated()** (3 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **NewAESProviderFromBase64()** (3 connections) — `pkg/encryption/keyencryption/aes.go`
- **TestAESKeyEncryptor_Algorithm()** (3 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESKeyEncryptor_Basic()** (3 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESProvider_InvalidKEK()** (3 connections) — `pkg/encryption/keyencryption/aes_test.go`
- **TestAESProviderFromConfig()** (3 connections) — `pkg/encryption/keyencryption/aes_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (15 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (5 shared connections)
- [None Provider Pass-Through](None_Provider_Pass-Through.md) (3 shared connections)
- [AES KEK Provider](AES_KEK_Provider.md) (2 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (1 shared connections)

## Source Files

- `pkg/encryption/keyencryption/aes.go`
- `pkg/encryption/keyencryption/aes_coverage_test.go`
- `pkg/encryption/keyencryption/aes_test.go`

## Audit Trail

- EXTRACTED: 51 (85%)
- INFERRED: 9 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*