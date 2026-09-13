# License Types

> 16 nodes · cohesion 0.17

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
- **sync/atomic.Bool** (2 connections)
- **sync.Once** (2 connections)
- **jwt.RegisteredClaims** (1 connections)
- **LicenseClaims** (1 connections)

## Relationships

- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (3 shared connections)
- [License Loading](License_Loading.md) (3 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (3 shared connections)
- [License Runtime Monitor](License_Runtime_Monitor.md) (2 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (2 shared connections)
- [License Logging](License_Logging.md) (2 shared connections)
- [Monitoring Server](Monitoring_Server.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (1 shared connections)
- [License Validation](License_Validation.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `internal/license/types.go`
- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 38 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*