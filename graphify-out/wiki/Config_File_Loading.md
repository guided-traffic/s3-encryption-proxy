# Config File Loading

> 26 nodes · cohesion 0.25

## Key Concepts

- **loading_coverage_test.go** (26 connections) — `internal/config/loading_coverage_test.go`
- **CfgResetViper()** (24 connections) — `internal/config/loading_coverage_test.go`
- **InitConfig()** (19 connections) — `internal/config/config.go`
- **CfgNoLicense()** (13 connections) — `internal/config/loading_coverage_test.go`
- **CfgWriteConfigFile()** (13 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadAndStartLicenseWithoutLicense()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadExpandsEnvironmentVariables()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnUnsetEnvironmentVariable()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsWhenProvidersAreNotASequence()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFromYAMLFile()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProviderConfigFromYAMLKeepsNestedValues()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMetadataKeyPrefix()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMigrateLegacyDoesNotOverrideExplicitBackend()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMigrateLegacyS3Fields()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadAndStartLicensePropagatesLoadError()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnValidationError()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigDiscoversFileInHomeDirectory()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigWithExplicitFile()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProviderConfigsWithoutProviders()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromInterfaceSliceRejectsNonMapEntry()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromMapSlice()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMigrateLegacyIgnoresEmptyLegacyValues()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigEnablesEnvPrefix()** (4 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigWithMissingFileKeepsDefaults()** (4 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMigrateLegacyConfigWithoutDefaults()** (4 connections) — `internal/config/loading_coverage_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (24 shared connections)
- [Integrity Verification Config](Integrity_Verification_Config.md) (19 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (9 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)
- [Main Entrypoint Call Graph](Main_Entrypoint_Call_Graph.md) (1 shared connections)
- [None Provider Integration Tests](None_Provider_Integration_Tests.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`

## Audit Trail

- EXTRACTED: 100 (74%)
- INFERRED: 36 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*