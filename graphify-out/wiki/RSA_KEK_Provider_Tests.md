# RSA KEK Provider Tests

> 20 nodes · cohesion 0.28

## Key Concepts

- **NewRSAProvider()** (19 connections) — `pkg/encryption/keyencryption/rsa.go`
- **rsa_coverage_test.go** (17 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekSharedRSAKey()** (13 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **crypto/rsa.PrivateKey** (12 connections)
- **TestKekRSAProviderFromPEMFormats()** (11 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekPEM()** (7 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAProviderFromConfig()** (7 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekPKCS8PrivatePEM()** (6 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekPKIXPublicPEM()** (6 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSADecryptDEKFailures()** (5 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSADEKRoundTrip()** (5 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAEncryptDEKIsRandomized()** (5 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAEncryptDEKTooLarge()** (5 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekECDSAKeyPEMs()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekPKCS1PrivatePEM()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **KekPKCS1PublicPEM()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAFingerprintStabilityAndUniqueness()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAKeyPairValidationBranches()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSAKeySizeBoundary()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`
- **TestKekRSANameAndRotateKEK()** (4 connections) — `pkg/encryption/keyencryption/rsa_coverage_test.go`

## Relationships

- [RSA Provider Implementation](RSA_Provider_Implementation.md) (15 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (14 shared connections)
- [None Provider Pass-Through](None_Provider_Pass-Through.md) (5 shared connections)
- [License Tool CLI](License_Tool_CLI.md) (3 shared connections)
- [RSA KEK Provider](RSA_KEK_Provider.md) (1 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (1 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (1 shared connections)

## Source Files

- `pkg/encryption/keyencryption/rsa.go`
- `pkg/encryption/keyencryption/rsa_coverage_test.go`

## Audit Trail

- EXTRACTED: 73 (78%)
- INFERRED: 20 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*