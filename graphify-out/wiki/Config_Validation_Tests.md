# Config Validation Tests

> 27 nodes · cohesion 0.13

## Key Concepts

- **validation_coverage_test.go** (14 connections) — `internal/config/validation_coverage_test.go`
- **CfgNoneProviderConfig()** (12 connections) — `internal/config/validation_coverage_test.go`
- **validate()** (11 connections) — `internal/config/config.go`
- **validateEncryption()** (10 connections) — `internal/config/config.go`
- **validateLicenseAndEncryption()** (9 connections) — `internal/config/config.go`
- **validateS3Clients()** (6 connections) — `internal/config/config.go`
- **validateOptimizations()** (5 connections) — `internal/config/config.go`
- **validateProvider()** (4 connections) — `internal/config/config.go`
- **validateS3Security()** (4 connections) — `internal/config/config.go`
- **CfgValidClients()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateEncryptionIntegrityModes()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateEncryptionProviderList()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateLicenseAndEncryption()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateMonitoringPprofBindAddress()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidatePropagatesSubValidatorErrors()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateRequiresTargetEndpoint()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3Clients()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateS3ClientsPropagatesSecurityError()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateTLSRequirements()** (4 connections) — `internal/config/validation_coverage_test.go`
- **TestValidateEncryption_MissingActiveProvider()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_MissingAESKey()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_UnsupportedType()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_ValidAES()** (3 connections) — `internal/config/config_test.go`
- **TestCfgValidateOptimizationsBoundaries()** (3 connections) — `internal/config/validation_coverage_test.go`
- **TestCfgValidateProviderTypes()** (3 connections) — `internal/config/validation_coverage_test.go`
- *... and 2 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (21 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (16 shared connections)
- [License Logging](License_Logging.md) (2 shared connections)
- [Integrity Verification Config](Integrity_Verification_Config.md) (1 shared connections)
- [License Claim Checks](License_Claim_Checks.md) (1 shared connections)
- [License Validator Tests](License_Validator_Tests.md) (1 shared connections)
- [Optimization Config Tests](Optimization_Config_Tests.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/validation_coverage_test.go`

## Audit Trail

- EXTRACTED: 72 (80%)
- INFERRED: 18 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*