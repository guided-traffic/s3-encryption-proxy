# Config Env Var Expansion

> 29 nodes · cohesion 0.12

## Key Concepts

- **envexpand_test.go** (18 connections) — `internal/config/envexpand_test.go`
- **expandConfigEnvVars()** (17 connections) — `internal/config/envexpand.go`
- **expandEnvVars()** (11 connections) — `internal/config/envexpand.go`
- **${VAR} References Inside a Named List of Fields** (3 connections) — `docs/developer/configuration.md`
- **envexpand.go** (3 connections) — `internal/config/envexpand.go`
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
- *... and 4 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (20 shared connections)
- [Strict Configuration Loading](Strict_Configuration_Loading.md) (1 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (1 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (1 shared connections)
- [Service TLS and Operator Certificates](Service_TLS_and_Operator_Certificates.md) (1 shared connections)

## Source Files

- `docs/developer/configuration.md`
- `docs/security/key-management.md`
- `internal/config/envexpand.go`
- `internal/config/envexpand_coverage_test.go`
- `internal/config/envexpand_test.go`

## Audit Trail

- EXTRACTED: 50 (70%)
- INFERRED: 21 (30%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*