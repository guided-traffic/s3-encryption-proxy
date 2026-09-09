# License Claim Checks

> 12 nodes · cohesion 0.21

## Key Concepts

- **validator.go** (7 connections) — `internal/license/validator.go`
- **checkClaims()** (6 connections) — `internal/license/validator.go`
- **LoadLicense()** (6 connections) — `internal/license/validator.go`
- **LicclearLicenseEnv()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLoadLicenseFromEnvPrecedence()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLoadLicensePrefersEnvironment()** (4 connections) — `internal/license/validator_coverage_test.go`
- **LoadLicenseFromEnv()** (4 connections) — `internal/license/validator.go`
- **TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLoadLicenseFromFile()** (3 connections) — `internal/license/validator_coverage_test.go`
- **LoadLicenseFromFile()** (3 connections) — `internal/license/validator.go`
- **TestLoadLicenseFromEnv()** (3 connections) — `internal/license/validator_test.go`
- **LicenseClaims** (1 connections)

## Relationships

- [License Validator Tests](License_Validator_Tests.md) (7 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (6 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (4 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (1 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [Config Validation Tests](Config_Validation_Tests.md) (1 shared connections)

## Source Files

- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 29 (85%)
- INFERRED: 5 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*