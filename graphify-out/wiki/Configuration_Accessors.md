# Configuration Accessors

> 34 nodes · cohesion 0.11

## Key Concepts

- **Config** (73 connections) — `internal/config/config.go`
- **config.go** (29 connections) — `internal/config/config.go`
- **EncryptionProvider** (11 connections) — `internal/config/config.go`
- **LoadAndStartLicense()** (11 connections) — `internal/config/config.go`
- **loadProviderConfigs()** (8 connections) — `internal/config/config.go`
- **createProviderFromProviderMap()** (5 connections) — `internal/config/config.go`
- **S3ClientCredentials** (5 connections) — `internal/config/config.go`
- **migrateLegacyConfig()** (5 connections) — `internal/config/config.go`
- **S3BackendConfig** (4 connections) — `internal/config/config.go`
- **S3SecurityConfig** (4 connections) — `internal/config/config.go`
- **loadProvidersFromInterfaceSlice()** (4 connections) — `internal/config/config.go`
- **loadProvidersFromMapSlice()** (4 connections) — `internal/config/config.go`
- **validateMonitoring()** (4 connections) — `internal/config/config.go`
- **.GetActiveProvider()** (3 connections) — `internal/config/config.go`
- **EncryptionConfig** (3 connections) — `internal/config/config.go`
- **S3ClientConfig** (3 connections) — `internal/config/config.go`
- **TestCfgIsValidProviderType()** (3 connections) — `internal/config/accessors_coverage_test.go`
- **isValidProviderType()** (3 connections) — `internal/config/config.go`
- **TestCfgCreateProviderFromProviderMap()** (3 connections) — `internal/config/loading_coverage_test.go`
- **.GetAllProviders()** (2 connections) — `internal/config/config.go`
- **.GetProviderByAlias()** (2 connections) — `internal/config/config.go`
- **.GetS3SecurityConfig()** (2 connections) — `internal/config/config.go`
- **MonitoringConfig** (2 connections) — `internal/config/config.go`
- **OptimizationsConfig** (2 connections) — `internal/config/config.go`
- **TLSConfig** (2 connections) — `internal/config/config.go`
- *... and 9 more nodes in this community*

## Relationships

- [Config Validation Tests](Config_Validation_Tests.md) (16 shared connections)
- [Config File Loading](Config_File_Loading.md) (9 shared connections)
- [Integrity Verification Config](Integrity_Verification_Config.md) (6 shared connections)
- [Encryption Metadata Management](Encryption_Metadata_Management.md) (6 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (4 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (4 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (4 shared connections)
- [Multipart Session Lifecycle Tests](Multipart_Session_Lifecycle_Tests.md) (4 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (3 shared connections)
- [SigV4 Pre-Signed URL Auth](SigV4_Pre-Signed_URL_Auth.md) (3 shared connections)
- [Orchestration Manager Tests](Orchestration_Manager_Tests.md) (3 shared connections)
- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (3 shared connections)

## Source Files

- `internal/config/accessors_coverage_test.go`
- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`
- `internal/orchestration/providers.go`
- `internal/validation/hmac_manager.go`

## Audit Trail

- EXTRACTED: 138 (93%)
- INFERRED: 11 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*