# License Validation and Startup

> 134 nodes · cohesion 0.03

## Key Concepts

- **runProxy()** (54 connections) — `cmd/s3-encryption-proxy/main.go`
- **validator_coverage_test.go** (24 connections) — `internal/license/validator_coverage_test.go`
- **NewValidator()** (18 connections) — `internal/license/validator.go`
- **.StartRuntimeMonitoring()** (13 connections) — `internal/license/validator.go`
- **TestLicValidateLicenseRejectsUntrustedTokens()** (13 connections) — `internal/license/validator_coverage_test.go`
- **LoadAndStartLicense()** (12 connections) — `internal/config/config.go`
- **validateLicenseAndEncryption()** (12 connections) — `internal/config/config.go`
- **.ValidateLicense()** (12 connections) — `internal/license/validator.go`
- **LiccaptureLogs()** (12 connections) — `internal/license/validator_coverage_test.go`
- **LogLicenseInfo()** (11 connections) — `internal/license/logger.go`
- **validator_test.go** (10 connections) — `internal/license/validator_test.go`
- **Liclogged()** (10 connections) — `internal/license/validator_coverage_test.go`
- **logger_coverage_test.go** (9 connections) — `internal/license/logger_coverage_test.go`
- **runProxy closure 6 (shutdown drain loop)** (9 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **TestLicStartRuntimeMonitoringIsStartedOnlyOnce()** (9 connections) — `internal/license/validator_coverage_test.go`
- **LicenseValidator.ValidateLicense** (9 connections) — `internal/license/validator.go`
- **Main Entrypoint Call Graph (diagram)** (8 connections) — `docs/architecture/callgraph_main_entrypoint.svg`
- **Call graph: proxy/HTTP layer (gocallvis; 64 functions, 57 calls; hubs setupRoutes, utils.HandleS3Error, setupMiddleware)** (8 connections) — `docs/architecture/callgraph_proxy_layer.svg`
- **calculateTimeRemaining()** (8 connections) — `internal/license/validator.go`
- **TestLicStartRuntimeMonitoringStops()** (8 connections) — `internal/license/validator_coverage_test.go`
- **validator.go** (7 connections) — `internal/license/validator.go`
- **LicenseValidator** (7 connections) — `internal/license/types.go`
- **.ValidateProviderType()** (7 connections) — `internal/license/validator.go`
- **TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim()** (7 connections) — `internal/license/validator_coverage_test.go`
- **TestLicGracefulShutdownExitsWithRestartCode()** (7 connections) — `internal/license/validator_coverage_test.go`
- *... and 109 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `docs/architecture/callgraph_main_entrypoint.svg`
- `docs/architecture/callgraph_proxy_layer.svg`
- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/024-coverage-round-findings.md`
- `internal/config/config.go`
- `internal/license/logger.go`
- `internal/license/logger_coverage_test.go`
- `internal/license/types.go`
- `internal/license/validator.go`
- `internal/license/validator_coverage_test.go`
- `internal/license/validator_test.go`
- `internal/monitoring/metrics.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 408 (65%)
- INFERRED: 219 (35%)
- AMBIGUOUS: 3 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*