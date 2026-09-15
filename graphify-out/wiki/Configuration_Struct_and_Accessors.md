# Configuration Struct and Accessors

> 38 nodes · cohesion 0.12

## Key Concepts

- **Config** (58 connections) — `internal/config/config.go`
- **config.go** (35 connections) — `internal/config/config.go`
- **validate()** (15 connections) — `internal/config/config.go`
- **LoadAndStartLicense()** (10 connections) — `internal/config/config.go`
- **validateLicenseAndEncryption()** (10 connections) — `internal/config/config.go`
- **EncryptionProvider** (9 connections) — `internal/config/config.go`
- **validateBackendTransport()** (7 connections) — `internal/config/config.go`
- **validateOptimizations()** (7 connections) — `internal/config/config.go`
- **createProviderFromProviderMap()** (6 connections) — `internal/config/config.go`
- **validateProvider()** (6 connections) — `internal/config/config.go`
- **validateS3Clients()** (6 connections) — `internal/config/config.go`
- **S3BackendConfig** (5 connections) — `internal/config/config.go`
- **.Backend()** (4 connections) — `internal/config/config.go`
- **.GetActiveProvider()** (4 connections) — `internal/config/config.go`
- **S3ClientCredentials** (4 connections) — `internal/config/config.go`
- **loadProvidersFromInterfaceSlice()** (4 connections) — `internal/config/config.go`
- **loadProvidersFromMapSlice()** (4 connections) — `internal/config/config.go`
- **resolveBackends()** (4 connections) — `internal/config/config.go`
- **validateAESKey()** (4 connections) — `internal/config/config.go`
- **validateListenerBudgets()** (4 connections) — `internal/config/config.go`
- **validateMonitoring()** (4 connections) — `internal/config/config.go`
- **validateS3Security()** (4 connections) — `internal/config/config.go`
- **EncryptionConfig** (3 connections) — `internal/config/config.go`
- **A Provider Block Swallows Its Own Parameters (the ErrorUnused Boundary)** (3 connections) — `docs/developer/configuration.md`
- **isValidProviderType()** (3 connections) — `internal/config/config.go`
- *... and 13 more nodes in this community*

## Relationships

- [Validation](Validation.md) (12 shared connections)
- [Config Defaults and Provider Loading](Config_Defaults_and_Provider_Loading.md) (10 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (9 shared connections)
- [Metadata Manager Coverage](Metadata_Manager_Coverage.md) (5 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (4 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Validator](Validator.md) (4 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (3 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (3 shared connections)
- [Main](Main.md) (3 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (3 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (3 shared connections)

## Source Files

- `docs/developer/configuration.md`
- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/validation_coverage_test.go`

## Audit Trail

- EXTRACTED: 151 (90%)
- INFERRED: 17 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*