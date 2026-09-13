# License Loading

> 9 nodes · cohesion 0.28

## Key Concepts

- **validator.go** (7 connections) — `internal/license/validator.go`
- **LoadLicense()** (6 connections) — `internal/license/validator.go`
- **parseEmbeddedPublicKey()** (5 connections) — `internal/license/validator.go`
- **LoadLicenseFromEnv()** (4 connections) — `internal/license/validator.go`
- **TestLicLoadLicenseFromFile()** (3 connections) — `internal/license/validator_coverage_test.go`
- **LoadLicenseFromFile()** (3 connections) — `internal/license/validator.go`
- **TestLoadLicenseFromEnv()** (3 connections) — `internal/license/validator_test.go`
- **TestParseEmbeddedPublicKey()** (3 connections) — `internal/license/validator_test.go`
- **crypto/rsa.PublicKey** (1 connections)

## Relationships

- [License Validator Tests](License_Validator_Tests.md) (4 shared connections)
- [License Types](License_Types.md) (3 shared connections)
- [License Validation](License_Validation.md) (3 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (3 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (1 shared connections)
- [Config Structure](Config_Structure.md) (1 shared connections)

## Source Files

- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 19 (76%)
- INFERRED: 6 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*