# License Logging

> 21 nodes · cohesion 0.20

## Key Concepts

- **LiccaptureLogs()** (13 connections) — `internal/license/validator_coverage_test.go`
- **LogLicenseInfo()** (10 connections) — `internal/license/logger.go`
- **Liclogged()** (10 connections) — `internal/license/validator_coverage_test.go`
- **logger_coverage_test.go** (9 connections) — `internal/license/logger_coverage_test.go`
- **github.com/sirupsen/logrus/hooks/test.Hook** (7 connections)
- **TestLicLogLicenseInfoExpiringSoon()** (6 connections) — `internal/license/logger_coverage_test.go`
- **LiclevelOf()** (5 connections) — `internal/license/logger_coverage_test.go`
- **TestLicLogLicenseInfoExhaustedTimeRemaining()** (5 connections) — `internal/license/logger_coverage_test.go`
- **TestLicLogLicenseInfoFullDetails()** (5 connections) — `internal/license/logger_coverage_test.go`
- **TestLicLogLicenseInfoInvalidResult()** (5 connections) — `internal/license/logger_coverage_test.go`
- **TestLicLogLicenseInfoMinimalClaims()** (5 connections) — `internal/license/logger_coverage_test.go`
- **formatTimeRemaining()** (5 connections) — `internal/license/logger.go`
- **TestLicStartRuntimeMonitoringStops()** (5 connections) — `internal/license/validator_coverage_test.go`
- **TestLicStartRuntimeMonitoringWithoutLicense()** (5 connections) — `internal/license/validator_coverage_test.go`
- **TestLicLogLicenseInfoWithoutClaims()** (4 connections) — `internal/license/logger_coverage_test.go`
- **TestLicLogProviderRestriction()** (4 connections) — `internal/license/logger_coverage_test.go`
- **logger.go** (3 connections) — `internal/license/logger.go`
- **TestLicFormatTimeRemainingSubHour()** (3 connections) — `internal/license/logger_coverage_test.go`
- **LogProviderRestriction()** (3 connections) — `internal/license/logger.go`
- **TestFormatTimeRemaining()** (3 connections) — `internal/license/validator_test.go`
- **github.com/sirupsen/logrus.Level** (2 connections)

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (13 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (6 shared connections)
- [License Validation](License_Validation.md) (3 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (2 shared connections)
- [License Types](License_Types.md) (2 shared connections)
- [Config Structure](Config_Structure.md) (2 shared connections)
- [Health Handler](Health_Handler.md) (1 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (1 shared connections)
- [SigV4 Coverage Tests](SigV4_Coverage_Tests.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Multipart Handler](Multipart_Handler.md) (1 shared connections)

## Source Files

- `internal/license/logger.go`
- `internal/license/logger_coverage_test.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`

## Audit Trail

- EXTRACTED: 52 (69%)
- INFERRED: 23 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*