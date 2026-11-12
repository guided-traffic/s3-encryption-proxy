# Tickets: 036 High Availability

> 8 nodes · cohesion 0.29

## Key Concepts

- **loadProviderConfigs()** (8 connections) — `internal/config/config.go`
- **createProviderFromProviderMap()** (5 connections) — `internal/config/config.go`
- **TestCfgLoadProviderConfigsWithoutProviders()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromInterfaceSliceRejectsNonMapEntry()** (5 connections) — `internal/config/loading_coverage_test.go`
- **TestCfgLoadProvidersFromMapSlice()** (5 connections) — `internal/config/loading_coverage_test.go`
- **loadProvidersFromInterfaceSlice()** (4 connections) — `internal/config/config.go`
- **loadProvidersFromMapSlice()** (4 connections) — `internal/config/config.go`
- **TestCfgCreateProviderFromProviderMap()** (3 connections) — `internal/config/loading_coverage_test.go`

## Relationships

- [Configuration Loading](Configuration_Loading.md) (7 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (4 shared connections)
- [Misc (41)](Misc_41.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (3 shared connections)
- [Config: Config](Config-_Config.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/config/loading_coverage_test.go`

## Audit Trail

- EXTRACTED: 24 (77%)
- INFERRED: 7 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*