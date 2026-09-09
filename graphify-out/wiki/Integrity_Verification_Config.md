# Integrity Verification Config

> 14 nodes · cohesion 0.29

## Key Concepts

- **Load()** (28 connections) — `internal/config/config.go`
- **setDefaults()** (19 connections) — `internal/config/config.go`
- **TestCfgLoadFailsOnUnmarshalError()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestLoad_MissingTargetEndpoint()** (4 connections) — `internal/config/config_test.go`
- **TestLoad_ValidNoneConfig()** (4 connections) — `internal/config/config_test.go`
- **integrity_verification_test.go** (4 connections) — `internal/config/integrity_verification_test.go`
- **TestIntegrityVerificationConfigLoading()** (4 connections) — `internal/config/integrity_verification_test.go`
- **TestIntegrityVerificationEnabledExplicitly()** (4 connections) — `internal/config/integrity_verification_test.go`
- **TestIntegrityVerificationWithDefaults()** (4 connections) — `internal/config/integrity_verification_test.go`
- **TestTLSConfig()** (4 connections) — `internal/config/tls_test.go`
- **TestTLSDefaults()** (4 connections) — `internal/config/tls_test.go`
- **TestTLSEnvironmentVariables()** (4 connections) — `internal/config/tls_test.go`
- **TestIntegrityVerificationConfigDefaults()** (3 connections) — `internal/config/integrity_verification_test.go`
- **config/tls_test.go** (3 connections) — `internal/config/tls_test.go`

## Relationships

- [Config File Loading](Config_File_Loading.md) (19 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (12 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (6 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)
- [Config Validation Tests](Config_Validation_Tests.md) (1 shared connections)
- [None Provider Integration Tests](None_Provider_Integration_Tests.md) (1 shared connections)
- [Config Env Var Expansion](Config_Env_Var_Expansion.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/config/integrity_verification_test.go`
- `internal/config/loading_coverage_test.go`
- `internal/config/tls_test.go`

## Audit Trail

- EXTRACTED: 32 (47%)
- INFERRED: 36 (53%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*