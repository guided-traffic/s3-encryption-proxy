# Config Defaults and Provider Loading

> 24 nodes · cohesion 0.12

## Key Concepts

- **setDefaults()** (16 connections) — `internal/config/config.go`
- **config_test.go** (12 connections) — `internal/config/config_test.go`
- **validateEncryption()** (9 connections) — `internal/config/config.go`
- **loadProviderConfigs()** (8 connections) — `internal/config/config.go`
- **TestCfgLoadProviderConfigsWithoutProviders()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromInterfaceSliceRejectsNonMapEntry()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromMapSlice()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestLoad_MissingTargetEndpoint()** (4 connections) — `internal/config/config_test.go`
- **TestLoad_ValidExitConfig()** (4 connections) — `internal/config/config_test.go`
- **TestCfgSetDefaults()** (4 connections) — `internal/config/loading_coverage_test.go`
- **TestTLSConfig()** (4 connections) — `internal/config/tls_test.go`
- **TestTLSDefaults()** (4 connections) — `internal/config/tls_test.go`
- **TestTLSEnvironmentVariables()** (4 connections) — `internal/config/tls_test.go`
- **TestListenerBudgetDefaults()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_MissingActiveProvider()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_MissingAESKey()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_UnsupportedType()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_ValidAES()** (3 connections) — `internal/config/config_test.go`
- **TestValidateListenerBudgets()** (3 connections) — `internal/config/config_test.go`
- **config/tls_test.go** (3 connections) — `internal/config/tls_test.go`
- **TestGetActiveProvider()** (2 connections) — `internal/config/config_test.go`
- **TestGetActiveProvider_NoAlias()** (2 connections) — `internal/config/config_test.go`
- **TestGetActiveProvider_NotFound()** (2 connections) — `internal/config/config_test.go`
- **TestGetAllProviders()** (2 connections) — `internal/config/config_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (19 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (18 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (10 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)
- [Validation](Validation.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/tls_test.go`

## Audit Trail

- EXTRACTED: 54 (67%)
- INFERRED: 27 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*