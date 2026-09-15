# Types

> 14 nodes · cohesion 0.21

## Key Concepts

- **calculateTimeRemaining()** (7 connections) — `internal/license/validator.go`
- **checkClaims()** (6 connections) — `internal/license/validator.go`
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
- **jwt.RegisteredClaims** (1 connections)
- **LicenseClaims** (1 connections)

## Relationships

- [Validator](Validator.md) (8 shared connections)
- [S3 Signing Helper](S3_Signing_Helper.md) (3 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (3 shared connections)
- [Logger](Logger.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Server](Server.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Shutdown](Shutdown.md) (1 shared connections)

## Source Files

- `internal/license/types.go`
- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 36 (92%)
- INFERRED: 3 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*