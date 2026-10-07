# Strict Configuration Loading

> 5 nodes · cohesion 0.40

## Key Concepts

- **Configuration: Where a Value Comes From** (6 connections) — `docs/developer/configuration.md`
- **Strict Decoding: An Unknown Key Refuses the Start** (5 connections) — `docs/developer/configuration.md`
- **AutomaticEnv Removed in 5.0.0** (2 connections) — `docs/developer/configuration.md`
- **It Refuses Rather Than Documents** (1 connections) — `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- **loading_coverage_test.go — pins the AutomaticEnv removal** (1 connections) — `docs/developer/configuration.md`

## Relationships

- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (2 shared connections)
- [Abandoned Upload Sweeper](Abandoned_Upload_Sweeper.md) (1 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Config Env Var Expansion](Config_Env_Var_Expansion.md) (1 shared connections)

## Source Files

- `docs/adr/0033-a-proxy-instance-holds-its-uploads.md`
- `docs/developer/configuration.md`

## Audit Trail

- EXTRACTED: 10 (91%)
- INFERRED: 1 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*