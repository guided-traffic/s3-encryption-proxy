# Types

> 16 nodes · cohesion 0.17

## Key Concepts

- **calculateTimeRemaining()** (7 connections) — `internal/license/validator.go`
- **checkClaims()** (7 connections) — `internal/license/validator.go`
- **LicenseInfo** (6 connections) — `internal/license/types.go`
- **types.go** (5 connections) — `internal/license/types.go`
- **LicenseValidator** (5 connections) — `internal/license/types.go`
- **.ValidateLicense()** (5 connections) — `internal/license/validator.go`
- **TimeRemaining** (5 connections) — `internal/license/types.go`
- **ValidationResult** (5 connections) — `internal/license/types.go`
- **TestLicCalculateTimeRemainingBoundaries()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim()** (3 connections) — `internal/license/validator_coverage_test.go`
- **TestCalculateTimeRemaining()** (3 connections) — `internal/license/validator_test.go`
- **LicenseClaims** (3 connections) — `internal/license/types.go`
- **sync/atomic.Bool** (2 connections)
- **sync.Once** (2 connections)
- **jwt.RegisteredClaims** (1 connections)
- **LicenseClaims** (1 connections)

## Relationships

- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (3 shared connections)
- [License Loading](License_Loading.md) (3 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (3 shared connections)
- [License Validator Runtime](License_Validator_Runtime.md) (2 shared connections)
- [Validator](Validator.md) (2 shared connections)
- [Logger](Logger.md) (2 shared connections)
- [Monitoring Test Imports](Monitoring_Test_Imports.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (1 shared connections)
- [License Expiry Handling](License_Expiry_Handling.md) (1 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (1 shared connections)

## Source Files

- `internal/license/types.go`
- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 39 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*