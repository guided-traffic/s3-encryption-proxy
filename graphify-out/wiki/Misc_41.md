# Misc (41)

> 11 nodes · cohesion 0.29

## Key Concepts

- **Load()** (41 connections) — `internal/config/config.go`
- **setDefaults()** (15 connections) — `internal/config/config.go`
- **TestCfgDefaultConfigLoads()** (5 connections) — `internal/config/default_config_test.go`
- **TestCfgLoadFailsOnUnmarshalError()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnValidationError()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestLoad_MissingTargetEndpoint()** (4 connections) — `internal/config/config_test.go`
- **TestLoad_ValidExitConfig()** (4 connections) — `internal/config/config_test.go`
- **TestTLSConfig()** (4 connections) — `internal/config/tls_test.go`
- **TestTLSDefaults()** (4 connections) — `internal/config/tls_test.go`
- **TestTLSEnvironmentVariables()** (4 connections) — `internal/config/tls_test.go`
- **TestListenerBudgetDefaults()** (3 connections) — `internal/config/config_test.go`

## Relationships

- [Configuration Loading](Configuration_Loading.md) (30 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (9 shared connections)
- [Tickets: 036 High Availability](Tickets-_036_High_Availability.md) (4 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (3 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Io](Dataencryption-_Segmented_Gcm_Io.md) (1 shared connections)
- [Exit Provider Config Tests](Exit_Provider_Config_Tests.md) (1 shared connections)
- [Shipped Config Loading Tests](Shipped_Config_Loading_Tests.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/default_config_test.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/tls_test.go`

## Audit Trail

- EXTRACTED: 33 (42%)
- INFERRED: 45 (58%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*