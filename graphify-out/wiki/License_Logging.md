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

- [Config Accessor Tests](Config_Accessor_Tests.md) (13 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (9 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (2 shared connections)
- [License Claims Validation](License_Claims_Validation.md) (2 shared connections)
- [Config Validation Tests](Config_Validation_Tests.md) (2 shared connections)
- [Health Handler Tests](Health_Handler_Tests.md) (1 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (1 shared connections)
- [SigV4 Auth Service Tests](SigV4_Auth_Service_Tests.md) (1 shared connections)
- [Proxy Utils Tests](Proxy_Utils_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)

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