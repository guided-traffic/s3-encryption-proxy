# Configuration Loading

> 33 nodes · cohesion 0.20

## Key Concepts

- **loading_coverage_test.go** (96 connections) — `internal/config/loading_coverage_test.go`
- **CfgResetViper()** (37 connections) — `internal/config/loading_coverage_test.go`
- **InitConfig()** (35 connections) — `internal/config/config.go`
- **CfgWriteConfigFile()** (26 connections) — `internal/config/loading_coverage_test.go`
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
- **TestCfgSecurityControlsCannotBeFlippedFromTheEnvironment()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgUnknownKeyRefusesTheStart()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgVerifyPayloadHashDefaultsToOff()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgVerifyPayloadHashIsReadFromTheFile()** (6 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgZeroRequestDocumentSizeIsRefusedByName()** (6 connections) — `internal/config/loading_coverage_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (58 shared connections)
- [Misc (41)](Misc_41.md) (30 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (29 shared connections)
- [Tickets: 036 High Availability](Tickets-_036_High_Availability.md) (7 shared connections)
- [Shipped Config Loading Tests](Shipped_Config_Loading_Tests.md) (3 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [Exit Provider Config Tests](Exit_Provider_Config_Tests.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`

## Audit Trail

- EXTRACTED: 191 (78%)
- INFERRED: 54 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*