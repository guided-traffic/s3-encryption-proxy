# Configuration Loading

> 61 nodes · cohesion 0.10

## Key Concepts

- **loading_coverage_test.go** (96 connections) — `internal/config/loading_coverage_test.go`
- **Load()** (42 connections) — `internal/config/config.go`
- **CfgResetViper()** (37 connections) — `internal/config/loading_coverage_test.go`
- **InitConfig()** (35 connections) — `internal/config/config.go`
- **CfgWriteConfigFile()** (26 connections) — `internal/config/loading_coverage_test.go`
- **setDefaults()** (15 connections) — `internal/config/config.go`
- **loadProviderConfigs()** (8 connections) — `internal/config/config.go`
- **cfgLoadFrom()** (7 connections) — `internal/config/default_config_test.go`
- **loadTestConfig()** (7 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **TestCfgAbsentSessionIdleTimeoutTakesTheDefault()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgBackendsAreAList()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgInitConfigRefusesAFileItCannotRead()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLicenseFileIsAcceptedAndIgnored()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadExpandsEnvironmentVariables()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsOnUnsetEnvironmentVariable()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFailsWhenProvidersAreNotASequence()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadFromYAMLFile()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadNeedsNoLicense()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProviderConfigFromYAMLKeepsNestedValues()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMetadataKeyPrefix()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgMultipartPartSizeKeepsItsChecks()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgProviderConfigRefusesAKeyTheProviderDoesNotRead()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgProviderDescriptionIsNotAConfigKey()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgRenamedSegmentSizeIsRefusedByName()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgRetiredSessionMaxAgeIsRefusedByName()** (6 connections) — `internal/config/loading_coverage_test.go`
- *... and 36 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (79 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (50 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (6 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (4 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (3 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)
- [Monitoring: Server Coverage Test](Monitoring-_Server_Coverage_Test.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)
- [Performance and Test Docs](Performance_and_Test_Docs.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/default_config_test.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/tls_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`

## Audit Trail

- EXTRACTED: 259 (77%)
- INFERRED: 79 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*