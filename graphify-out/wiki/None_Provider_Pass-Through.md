# None Provider Pass-Through

> 16 nodes · cohesion 0.20

## Key Concepts

- **KekBytePattern()** (12 connections) — `pkg/encryption/keyencryption/aes_coverage_test.go`
- **tink_coverage_test.go** (8 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **KekNewTink()** (8 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **NewNoneProvider()** (7 connections) — `pkg/encryption/keyencryption/none.go`
- **TestKekNoneProviderIdentity()** (4 connections) — `pkg/encryption/keyencryption/none_coverage_test.go`
- **TestKekNoneProviderIgnoresKeyID()** (4 connections) — `pkg/encryption/keyencryption/none_coverage_test.go`
- **TestKekNoneProviderPassThrough()** (4 connections) — `pkg/encryption/keyencryption/none_coverage_test.go`
- **TestKekTinkDecryptDEKFailures()** (4 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **TestKekTinkDEKRoundTrip()** (4 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **TestKekTinkFingerprintDerivesFromURIOnly()** (4 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **none_coverage_test.go** (3 connections) — `pkg/encryption/keyencryption/none_coverage_test.go`
- **TestKekTinkNameAndRotateKEK()** (3 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **TestKekTinkProviderConstruction()** (3 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **TestKekTinkProviderFromConfigRejectsInvalidConfig()** (3 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`
- **none.go** (2 connections) — `pkg/encryption/keyencryption/none.go`
- **TestKekTinkConfigValidate()** (2 connections) — `pkg/encryption/keyencryption/tink_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (11 shared connections)
- [RSA KEK Provider Tests](RSA_KEK_Provider_Tests.md) (5 shared connections)
- [Tink KMS Provider Stub](Tink_KMS_Provider_Stub.md) (4 shared connections)
- [AES KEK Provider Tests](AES_KEK_Provider_Tests.md) (3 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (2 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (1 shared connections)
- [Envelope Encryption Coverage](Envelope_Encryption_Coverage.md) (1 shared connections)

## Source Files

- `pkg/encryption/keyencryption/aes_coverage_test.go`
- `pkg/encryption/keyencryption/none.go`
- `pkg/encryption/keyencryption/none_coverage_test.go`
- `pkg/encryption/keyencryption/tink_coverage_test.go`

## Audit Trail

- EXTRACTED: 34 (67%)
- INFERRED: 17 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*