# Config Loading Coverage Tests

> 33 nodes · cohesion 0.28

## Key Concepts

- **Load()** (40 connections) — `internal/config/config.go`
- **CfgResetViper()** (37 connections) — `internal/config/loading_coverage_test.go`
- **loading_coverage_test.go** (36 connections) — `internal/config/loading_coverage_test.go`
- **InitConfig()** (34 connections) — `internal/config/config.go`
- **CfgNoLicense()** (26 connections) — `internal/config/loading_coverage_test.go`
- **CfgWriteConfigFile()** (25 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgAbsentSessionIdleTimeoutTakesTheDefault()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgBackendsAreAList()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadAndStartLicenseWithoutLicense()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadExpandsEnvironmentVariables()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnUnsetEnvironmentVariable()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsWhenProvidersAreNotASequence()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFromYAMLFile()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProviderConfigFromYAMLKeepsNestedValues()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMetadataKeyPrefix()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMultipartPartSizeKeepsItsChecks()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgProviderConfigRefusesAKeyTheProviderDoesNotRead()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgProviderDescriptionIsNotAConfigKey()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgRenamedSegmentSizeIsRefusedByName()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgRetiredSessionMaxAgeIsRefusedByName()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgSecurityControlsCannotBeFlippedFromTheEnvironment()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgUnknownKeyRefusesTheStart()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgVerifyPayloadHashDefaultsToOff()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgVerifyPayloadHashIsReadFromTheFile()** (7 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgZeroRequestDocumentSizeIsRefusedByName()** (7 connections) — `internal/config/loading_coverage_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (30 shared connections)
- [Config Defaults and Provider Loading](Config_Defaults_and_Provider_Loading.md) (17 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (10 shared connections)
- [Default Config](Default_Config.md) (8 shared connections)
- [Encryption Mode Proxy Instances](Encryption_Mode_Proxy_Instances.md) (6 shared connections)
- [Strict Configuration Loading](Strict_Configuration_Loading.md) (2 shared connections)
- [Main](Main.md) (1 shared connections)
- [Validation](Validation.md) (1 shared connections)
- [Config Env Var Expansion](Config_Env_Var_Expansion.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`

## Audit Trail

- EXTRACTED: 161 (72%)
- INFERRED: 64 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*