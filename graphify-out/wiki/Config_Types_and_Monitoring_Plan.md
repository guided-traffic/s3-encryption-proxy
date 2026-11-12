# Config Types and Monitoring Plan

> 38 nodes · cohesion 0.08

## Key Concepts

- **Config** (27 connections) — `internal/config/config.go`
- **validate()** (15 connections) — `internal/config/config.go`
- **CfgExitProviderConfig()** (12 connections) — `internal/config/validation_coverage_test.go`
- **validateEncryption()** (9 connections) — `internal/config/config.go`
- **backendClientOptions()** (8 connections) — `internal/proxy/server.go`
- **validateBackendTransport()** (7 connections) — `internal/config/config.go`
- **validateS3Clients()** (6 connections) — `internal/config/config.go`
- **.Backend()** (5 connections) — `internal/config/config.go`
- **S3BackendConfig** (5 connections) — `internal/config/config.go`
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
- **.MetadataPrefix()** (3 connections) — `internal/config/config.go`
- **S3ClientCredentials** (3 connections) — `internal/config/config.go`
- **TestValidateEncryption_MissingActiveProvider()** (3 connections) — `internal/config/config_test.go`
- *... and 13 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (35 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (17 shared connections)
- [Config: Config](Config-_Config.md) (5 shared connections)
- [Tickets: 036 High Availability](Tickets-_036_High_Availability.md) (3 shared connections)
- [Misc (41)](Misc_41.md) (3 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (3 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (1 shared connections)
- [Backend HTTP Client TLS](Backend_HTTP_Client_TLS.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/validation_coverage_test.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 108 (83%)
- INFERRED: 22 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*