# Config Env Var Expansion

> 26 nodes · cohesion 0.14

## Key Concepts

- **envexpand_test.go** (18 connections) — `internal/config/envexpand_test.go`
- **expandConfigEnvVars()** (15 connections) — `internal/config/envexpand.go`
- **expandEnvVars()** (11 connections) — `internal/config/envexpand.go`
- **TestCfgExpandConfigEnvVarsErrorPerField()** (3 connections) — `internal/config/envexpand_coverage_test.go`
- **TestCfgExpandConfigEnvVarsExpandsEveryField()** (3 connections) — `internal/config/envexpand_coverage_test.go`
- **TestExpandConfigEnvVars_MissingProviderVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_MissingVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_MultipleClientsWithMixedRefs()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_NonStringProviderConfigSkipped()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_PlainValuesUnchanged()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_ProviderConfig()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_RSAProviderConfig()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_S3Backend()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandConfigEnvVars_S3Clients()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_BareDoublareNotExpanded()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_EmptyString()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_EmptyVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_MultilineValue()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_MultipleVars()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_NoVars()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_SingleVar()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_UnsetVarReturnsError()** (3 connections) — `internal/config/envexpand_test.go`
- **TestExpandEnvVars_VarWithSurroundingText()** (3 connections) — `internal/config/envexpand_test.go`
- **envexpand.go** (2 connections) — `internal/config/envexpand.go`
- **envexpand_coverage_test.go** (2 connections) — `internal/config/envexpand_coverage_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (20 shared connections)
- [Integrity Verification Config](Integrity_Verification_Config.md) (1 shared connections)

## Source Files

- `internal/config/envexpand.go`
- `internal/config/envexpand_coverage_test.go`
- `internal/config/envexpand_test.go`

## Audit Trail

- EXTRACTED: 44 (68%)
- INFERRED: 21 (32%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*