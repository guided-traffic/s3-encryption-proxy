# Validation

> 23 nodes · cohesion 0.16

## Key Concepts

- **validate()** (14 connections) — `internal/config/config.go`
- **validation_coverage_test.go** (14 connections) — `internal/config/validation_coverage_test.go`
- **CfgExitProviderConfig()** (12 connections) — `internal/config/validation_coverage_test.go`
- **validateLicenseAndEncryption()** (10 connections) — `internal/config/config.go`
- **validateBackendTransport()** (7 connections) — `internal/config/config.go`
- **validateS3Clients()** (6 connections) — `internal/config/config.go`
- **.Backend()** (4 connections) — `internal/config/config.go`
- **validateS3Security()** (4 connections) — `internal/config/config.go`
- **TestCfgValidateBackendTransport()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateEncryptionProviderList()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateLicenseAndEncryption()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateMonitoringPprofBindAddress()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidatePropagatesSubValidatorErrors()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateRequiresTargetEndpoint()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3Clients()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3ClientsPropagatesSecurityError()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateTLSRequirements()** (4 connections) — `internal/config/validation_coverage_test.go`
- **CfgValidClients()** (3 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateOptimizationsBoundaries()** (3 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateProviderTypes()** (3 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3SecurityBoundaries()** (3 connections) — `internal/config/validation_coverage_test.go`
- **backendUsesTLS()** (2 connections) — `internal/config/config.go`
- **Config** (1 connections)

## Relationships

- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (21 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (12 shared connections)
- [Logger](Logger.md) (2 shared connections)
- [Config Defaults and Provider Loading](Config_Defaults_and_Provider_Loading.md) (2 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (1 shared connections)
- [License Loading](License_Loading.md) (1 shared connections)
- [License Expiry Handling](License_Expiry_Handling.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/validation_coverage_test.go`

## Audit Trail

- EXTRACTED: 69 (85%)
- INFERRED: 12 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*