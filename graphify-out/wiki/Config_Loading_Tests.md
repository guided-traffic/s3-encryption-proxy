# Config Loading Tests

> 32 nodes · cohesion 0.20

## Key Concepts

- **Load()** (22 connections) — `internal/config/config.go`
- **loading_coverage_test.go** (22 connections) — `internal/config/loading_coverage_test.go`
- **CfgResetViper()** (20 connections) — `internal/config/loading_coverage_test.go`
- **InitConfig()** (17 connections) — `internal/config/config.go`
- **setDefaults()** (14 connections) — `internal/config/config.go`
- **CfgNoLicense()** (11 connections) — `internal/config/loading_coverage_test.go`
- **CfgWriteConfigFile()** (11 connections) — `internal/config/loading_coverage_test.go`
- **LoadAndStartLicense()** (9 connections) — `internal/config/config.go`
- **TestCfgLoadAndStartLicenseWithoutLicense()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadExpandsEnvironmentVariables()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnUnsetEnvironmentVariable()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsWhenProvidersAreNotASequence()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFromYAMLFile()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProviderConfigFromYAMLKeepsNestedValues()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMetadataKeyPrefix()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadAndStartLicensePropagatesLoadError()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnValidationError()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigDiscoversFileInHomeDirectory()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigWithExplicitFile()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnUnmarshalError()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProviderConfigsWithoutProviders()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromInterfaceSliceRejectsNonMapEntry()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromMapSlice()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestLoad_MissingTargetEndpoint()** (4 connections) — `internal/config/config_test.go`
- **TestLoad_ValidExitConfig()** (4 connections) — `internal/config/config_test.go`
- *... and 7 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (27 shared connections)
- [Config Structure](Config_Structure.md) (12 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (6 shared connections)
- [Metrics and Main Entry](Metrics_and_Main_Entry.md) (2 shared connections)
- [Provider Selection Tests](Provider_Selection_Tests.md) (2 shared connections)
- [License Loading](License_Loading.md) (1 shared connections)
- [License Validation](License_Validation.md) (1 shared connections)
- [License Types](License_Types.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/tls_test.go`

## Audit Trail

- EXTRACTED: 110 (72%)
- INFERRED: 42 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*