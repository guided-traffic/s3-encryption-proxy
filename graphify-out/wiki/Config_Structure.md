# Config Structure

> 30 nodes · cohesion 0.14

## Key Concepts

- **Config** (51 connections) — `internal/config/config.go`
- **config.go** (29 connections) — `internal/config/config.go`
- **validate()** (11 connections) — `internal/config/config.go`
- **validateLicenseAndEncryption()** (9 connections) — `internal/config/config.go`
- **EncryptionProvider** (8 connections) — `internal/config/config.go`
- **loadProviderConfigs()** (8 connections) — `internal/config/config.go`
- **validateS3Clients()** (6 connections) — `internal/config/config.go`
- **createProviderFromProviderMap()** (5 connections) — `internal/config/config.go`
- **validateOptimizations()** (5 connections) — `internal/config/config.go`
- **validateProvider()** (5 connections) — `internal/config/config.go`
- **S3BackendConfig** (4 connections) — `internal/config/config.go`
- **S3ClientCredentials** (4 connections) — `internal/config/config.go`
- **loadProvidersFromInterfaceSlice()** (4 connections) — `internal/config/config.go`
- **loadProvidersFromMapSlice()** (4 connections) — `internal/config/config.go`
- **validateMonitoring()** (4 connections) — `internal/config/config.go`
- **validateS3Security()** (4 connections) — `internal/config/config.go`
- **.GetActiveProvider()** (3 connections) — `internal/config/config.go`
- **EncryptionConfig** (3 connections) — `internal/config/config.go`
- **isValidProviderType()** (3 connections) — `internal/config/config.go`
- **validateAESKey()** (3 connections) — `internal/config/config.go`
- **TestCfgCreateProviderFromProviderMap()** (3 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgValidateProviderTypes()** (3 connections) — `internal/config/validation_coverage_test.go`
- **.GetAllProviders()** (2 connections) — `internal/config/config.go`
- **MonitoringConfig** (2 connections) — `internal/config/config.go`
- **OptimizationsConfig** (2 connections) — `internal/config/config.go`
- *... and 5 more nodes in this community*

## Relationships

- [Config Loading Tests](Config_Loading_Tests.md) (12 shared connections)
- [Config Validation Tests](Config_Validation_Tests.md) (11 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (4 shared connections)
- [Provider Selection Tests](Provider_Selection_Tests.md) (4 shared connections)
- [Multipart Handler](Multipart_Handler.md) (4 shared connections)
- [Metadata Manager](Metadata_Manager.md) (4 shared connections)
- [Provider Manager](Provider_Manager.md) (4 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (4 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (3 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (3 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (2 shared connections)
- [Metadata Manager Tests](Metadata_Manager_Tests.md) (2 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/validation_coverage_test.go`

## Audit Trail

- EXTRACTED: 115 (88%)
- INFERRED: 16 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*