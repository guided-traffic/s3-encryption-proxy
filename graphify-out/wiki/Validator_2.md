# Validator

> 13 nodes · cohesion 0.21

## Key Concepts

- **NewValidator()** (19 connections) — `internal/license/validator.go`
- **validator_test.go** (10 connections) — `internal/license/validator_test.go`
- **TestLicExpiryHandlerReplacesTheExit()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicGracefulShutdownExitsWithRestartCode()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicValidateLicenseWhitespaceTokenIsRejected()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicValidateProviderTypeMessage()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestNewValidator()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateLicense_EmptyToken()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateLicense_InvalidToken()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateProviderType_NoLicense()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateProviderType_WithLicense()** (3 connections) — `internal/license/validator_test.go`
- **TestLicenseClaims()** (2 connections) — `internal/license/validator_test.go`
- **LicenseValidator** (1 connections)

## Relationships

- [Validator](Validator.md) (11 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (10 shared connections)
- [Logger](Logger.md) (3 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [Types](Types.md) (1 shared connections)

## Source Files

- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 28 (65%)
- INFERRED: 15 (35%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*