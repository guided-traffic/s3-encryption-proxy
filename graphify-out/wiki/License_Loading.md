# License Loading

> 14 nodes · cohesion 0.19

## Key Concepts

- **validator.go** (9 connections) — `internal/license/validator.go`
- **LoadLicense()** (6 connections) — `internal/license/validator.go`
- **LoadLicenseFromFile()** (5 connections) — `internal/license/validator.go`
- **parseEmbeddedPublicKey()** (5 connections) — `internal/license/validator.go`
- **LicclearLicenseEnv()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLoadLicenseFromEnvIsOneName()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLoadLicensePrefersEnvironment()** (4 connections) — `internal/license/validator_coverage_test.go`
- **LoadLicenseFromEnv()** (4 connections) — `internal/license/validator.go`
- **TestLicLoadLicenseFromFile()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLoadLicenseFromFileBinding()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLoadLicenseFromEnv()** (3 connections) — `internal/license/validator_test.go`
- **TestParseEmbeddedPublicKey()** (3 connections) — `internal/license/validator_test.go`
- **readLicenseFile()** (2 connections) — `internal/license/validator.go`
- **crypto/rsa.PublicKey** (1 connections)

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Validator](Validator.md) (6 shared connections)
- [Types](Types.md) (3 shared connections)
- [License Expiry Handling](License_Expiry_Handling.md) (3 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Validation](Validation.md) (1 shared connections)

## Source Files

- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 32 (82%)
- INFERRED: 7 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*