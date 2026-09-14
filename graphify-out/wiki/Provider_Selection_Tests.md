# Provider Selection Tests

> 10 nodes · cohesion 0.27

## Key Concepts

- **config_test.go** (10 connections) — `internal/config/config_test.go`
- **validateEncryption()** (9 connections) — `internal/config/config.go`
- **TestValidateEncryption_MissingActiveProvider()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_MissingAESKey()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_UnsupportedType()** (3 connections) — `internal/config/config_test.go`
- **TestValidateEncryption_ValidAES()** (3 connections) — `internal/config/config_test.go`
- **TestGetActiveProvider()** (2 connections) — `internal/config/config_test.go`
- **TestGetActiveProvider_NoAlias()** (2 connections) — `internal/config/config_test.go`
- **TestGetActiveProvider_NotFound()** (2 connections) — `internal/config/config_test.go`
- **TestGetAllProviders()** (2 connections) — `internal/config/config_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (8 shared connections)
- [Config Structure](Config_Structure.md) (4 shared connections)
- [Config Loading Tests](Config_Loading_Tests.md) (2 shared connections)
- [Config Validation Tests](Config_Validation_Tests.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/config_test.go`

## Audit Trail

- EXTRACTED: 22 (81%)
- INFERRED: 5 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*