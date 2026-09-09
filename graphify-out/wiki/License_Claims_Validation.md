# License Claims Validation

> 21 nodes · cohesion 0.14

## Key Concepts

- **calculateTimeRemaining()** (7 connections) — `internal/license/validator.go`
- **LicenseInfo** (7 connections) — `internal/license/types.go`
- **LicenseValidator** (6 connections) — `internal/license/validator.go`
- **license/types.go** (5 connections) — `internal/license/types.go`
- **LicenseValidator** (5 connections) — `internal/license/types.go`
- **parseEmbeddedPublicKey()** (5 connections) — `internal/license/validator.go`
- **.ValidateLicense()** (5 connections) — `internal/license/validator.go`
- **TimeRemaining** (5 connections) — `internal/license/types.go`
- **ValidationResult** (5 connections) — `internal/license/types.go`
- **.StartRuntimeMonitoring()** (4 connections) — `internal/license/validator.go`
- **TestLicCalculateTimeRemainingBoundaries()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestCalculateTimeRemaining()** (3 connections) — `internal/license/validator_test.go`
- **TestParseEmbeddedPublicKey()** (3 connections) — `internal/license/validator_test.go`
- **LicenseClaims** (3 connections) — `internal/license/types.go`
- **sync/atomic.Bool** (2 connections)
- **sync.Once** (2 connections)
- **.GetLicenseInfo()** (2 connections) — `internal/license/validator.go`
- **.gracefulShutdown()** (2 connections) — `internal/license/validator.go`
- **.Stop()** (2 connections) — `internal/license/validator.go`
- **jwt.RegisteredClaims** (1 connections)
- **.ValidateProviderType()** (1 connections) — `internal/license/validator.go`

## Relationships

- [License Claim Checks](License_Claim_Checks.md) (4 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (4 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (3 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (2 shared connections)
- [License Logging](License_Logging.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Failing Listener Test Fake](Failing_Listener_Test_Fake.md) (1 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [RSA Provider Implementation](RSA_Provider_Implementation.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `internal/license/types.go`
- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 45 (92%)
- INFERRED: 4 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*