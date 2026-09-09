# License Validator Tests

> 28 nodes · cohesion 0.12

## Key Concepts

- **validator_coverage_test.go** (24 connections) — `internal/license/validator_coverage_test.go`
- **NewValidator()** (19 connections) — `internal/license/validator.go`
- **validator_test.go** (10 connections) — `internal/license/validator_test.go`
- **TestLicValidateLicenseRejectsUntrustedTokens()** (7 connections) — `internal/license/validator_coverage_test.go`
- **LicrequireStopReturns()** (6 connections) — `internal/license/validator_coverage_test.go`
- **TestLicStartRuntimeMonitoringIsStartedOnlyOnce()** (6 connections) — `internal/license/validator_coverage_test.go`
- **LicforeignKey()** (5 connections) — `internal/license/validator_coverage_test.go`
- **LicsignWith()** (5 connections) — `internal/license/validator_coverage_test.go`
- **LicclaimsFor()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicParseEmbeddedPublicKey()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicStopIsIdempotent()** (4 connections) — `internal/license/validator_coverage_test.go`
- **TestLicStopReturnsWhenMonitoringNeverStarted()** (4 connections) — `internal/license/validator_coverage_test.go`
- **LictamperPayload()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicGetLicenseInfo()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicGracefulShutdownExitsWithRestartCode()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicValidateLicenseWhitespaceTokenIsRejected()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicValidateProviderTypeMessage()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestNewValidator()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateLicense_EmptyToken()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateLicense_InvalidToken()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateProviderType_NoLicense()** (3 connections) — `internal/license/validator_test.go`
- **TestValidateProviderType_WithLicense()** (3 connections) — `internal/license/validator_test.go`
- **TestLicenseClaims()** (2 connections) — `internal/license/validator_test.go`
- **LicenseClaims** (1 connections)
- **LicenseValidator** (1 connections)
- *... and 3 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (19 shared connections)
- [License Logging](License_Logging.md) (9 shared connections)
- [License Claim Checks](License_Claim_Checks.md) (7 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (4 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)
- [RSA KEK Provider Tests](RSA_KEK_Provider_Tests.md) (1 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [Config Validation Tests](Config_Validation_Tests.md) (1 shared connections)

## Source Files

- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 73 (82%)
- INFERRED: 16 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*