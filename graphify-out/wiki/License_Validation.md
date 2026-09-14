# License Validation

> 9 nodes · cohesion 0.33

## Key Concepts

- **NewValidator()** (18 connections) — `internal/license/validator.go`
- **validator_test.go** (10 connections) — `internal/license/validator_test.go`
- **TestNewValidator()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateLicense_EmptyToken()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateLicense_InvalidToken()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateProviderType_NoLicense()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateProviderType_WithLicense()** (3 connections) — `internal/license/validator_test.go`
- **TestLicenseClaims()** (2 connections) — `internal/license/validator_test.go`
- **LicenseValidator** (1 connections)

## Relationships

- [License Validator Tests](License_Validator_Tests.md) (7 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (6 shared connections)
- [License Loading](License_Loading.md) (3 shared connections)
- [License Logging](License_Logging.md) (3 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (1 shared connections)
- [Config Structure](Config_Structure.md) (1 shared connections)
- [License Types](License_Types.md) (1 shared connections)

## Source Files

- `internal/license/validator.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 20 (59%)
- INFERRED: 14 (41%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*