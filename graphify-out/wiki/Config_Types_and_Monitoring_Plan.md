# Config Types and Monitoring Plan

> 40 nodes · cohesion 0.07

## Key Concepts

- **Config** (53 connections) — `internal/config/config.go`
- **validate()** (14 connections) — `internal/config/config.go`
- **CfgExitProviderConfig()** (12 connections) — `internal/config/validation_coverage_test.go`
- **validateEncryption()** (9 connections) — `internal/config/config.go`
- **validateS3Clients()** (6 connections) — `internal/config/config.go`
- **BktnewHandlerWithConfig()** (6 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **S3BackendConfig** (5 connections) — `internal/config/config.go`
- **validateBackendTransport()** (5 connections) — `internal/config/config.go`
- **monitoringPlan()** (4 connections) — `cmd/s3-encryption-proxy/main.go`
- **S3ClientCredentials** (4 connections) — `internal/config/config.go`
- **resolveBackends()** (4 connections) — `internal/config/config.go`
- **validateListenerBudgets()** (4 connections) — `internal/config/config.go`
- **validateMonitoring()** (4 connections) — `internal/config/config.go`
- **validateS3Security()** (4 connections) — `internal/config/config.go`
- **TestCfgValidateBackendTransport()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateEncryptionProviderList()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateMonitoringPprofBindAddress()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateNeedsNoLicense()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidatePropagatesSubValidatorErrors()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateRequiresTargetEndpoint()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3Clients()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3ClientsPropagatesSecurityError()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateTLSRequirements()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestMainMonitoringPlanKeepsPprofIndependent()** (3 connections) — `cmd/s3-encryption-proxy/shutdown_test.go`
- **.Backend()** (3 connections) — `internal/config/config.go`
- *... and 15 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (37 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (18 shared connections)
- [Configuration Loading](Configuration_Loading.md) (6 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (5 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (5 shared connections)
- [Config: Config](Config-_Config.md) (4 shared connections)
- [Manager Tests](Manager_Tests.md) (4 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Middleware: S3Auth Robust](Middleware-_S3Auth_Robust.md) (2 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (2 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `cmd/s3-encryption-proxy/shutdown_test.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/validation_coverage_test.go`
- `internal/proxy/handlers/bucket/operations_coverage_test.go`

## Audit Trail

- EXTRACTED: 138 (88%)
- INFERRED: 18 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*