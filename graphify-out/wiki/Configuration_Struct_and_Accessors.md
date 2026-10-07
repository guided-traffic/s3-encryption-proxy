# Configuration Struct and Accessors

> 33 nodes · cohesion 0.12

## Key Concepts

- **Config** (58 connections) — `internal/config/config.go`
- **config.go** (41 connections) — `internal/config/config.go`
- **LoadAndStartLicense()** (10 connections) — `internal/config/config.go`
- **EncryptionProvider** (9 connections) — `internal/config/config.go`
- **validateOptimizations()** (7 connections) — `internal/config/config.go`
- **createProviderFromProviderMap()** (6 connections) — `internal/config/config.go`
- **validateProvider()** (6 connections) — `internal/config/config.go`
- **TestCfgLoadAndStartLicensePropagatesLoadError()** (6 connections) — `internal/config/loading_coverage_test.go`
- **S3BackendConfig** (5 connections) — `internal/config/config.go`
- **Defaults Written Into Viper Before the File Is Read** (5 connections) — `docs/developer/configuration.md`
- **validateMonitoring()** (5 connections) — `internal/config/config.go`
- **.GetActiveProvider()** (4 connections) — `internal/config/config.go`
- **S3ClientCredentials** (4 connections) — `internal/config/config.go`
- **loadProvidersFromInterfaceSlice()** (4 connections) — `internal/config/config.go`
- **loadProvidersFromMapSlice()** (4 connections) — `internal/config/config.go`
- **resolveBackends()** (4 connections) — `internal/config/config.go`
- **validateAESKey()** (4 connections) — `internal/config/config.go`
- **validateListenerBudgets()** (4 connections) — `internal/config/config.go`
- **validateProviderConfig()** (4 connections) — `internal/config/config.go`
- **EncryptionConfig** (3 connections) — `internal/config/config.go`
- **A Provider Block Swallows Its Own Parameters (the ErrorUnused Boundary)** (3 connections) — `docs/developer/configuration.md`
- **isValidProviderType()** (3 connections) — `internal/config/config.go`
- **licenseFileIsBinding()** (3 connections) — `internal/config/config.go`
- **TestCfgCreateProviderFromProviderMap()** (3 connections) — `internal/config/loading_coverage_test.go`
- **.GetAllProviders()** (2 connections) — `internal/config/config.go`
- *... and 8 more nodes in this community*

## Relationships

- [Validation](Validation.md) (21 shared connections)
- [Config Defaults and Provider Loading](Config_Defaults_and_Provider_Loading.md) (11 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (10 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (8 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (4 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (4 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Backend Client](Backend_Client.md) (3 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (3 shared connections)
- [Main](Main.md) (3 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (3 shared connections)
- [Strict Configuration Loading](Strict_Configuration_Loading.md) (2 shared connections)

## Source Files

- `docs/developer/configuration.md`
- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`

## Audit Trail

- EXTRACTED: 150 (94%)
- INFERRED: 9 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*