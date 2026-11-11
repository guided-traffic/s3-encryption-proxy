# Orchestration: Providers

> 20 nodes · cohesion 0.13

## Key Concepts

- **ProviderManager** (24 connections) — `internal/orchestration/providers.go`
- **.GetAllProviders()** (5 connections) — `internal/config/config.go`
- **.DecryptDEK()** (5 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaDEKCacheStoresACopyOfTheCallerSlice()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestProviderManager_CacheLRUEviction()** (4 connections) — `internal/orchestration/providers_test.go`
- **.cacheGet()** (4 connections) — `internal/orchestration/providers.go`
- **.cachePut()** (4 connections) — `internal/orchestration/providers.go`
- **.GetLoadedProviders()** (4 connections) — `internal/orchestration/providers.go`
- **sync.RWMutex** (3 connections)
- **buildDEKCacheKey()** (3 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaDEKCacheKeyIsScopedByFingerprint()** (3 connections) — `internal/orchestration/providers_coverage_test.go`
- **ProviderInfo** (3 connections) — `internal/orchestration/providers.go`
- **.GetActiveProviderAlias()** (3 connections) — `internal/orchestration/providers.go`
- **ProviderSummary** (3 connections) — `internal/orchestration/providers.go`
- **.GetLoadedProviders()** (2 connections) — `internal/orchestration/manager.go`
- **.GetProviderAliases()** (2 connections) — `internal/orchestration/providers.go`
- **.IsExitProvider()** (2 connections) — `internal/orchestration/providers.go`
- **container/list.Element** (1 connections)
- **container/list.List** (1 connections)
- **.GetActiveFingerprint()** (1 connections) — `internal/orchestration/providers.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (8 shared connections)
- [Factory: Factory](Factory-_Factory.md) (5 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (4 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (3 shared connections)
- [Config: Config](Config-_Config.md) (2 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (2 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (1 shared connections)

## Source Files

- `internal/config/config.go`
- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/providers_test.go`

## Audit Trail

- EXTRACTED: 42 (75%)
- INFERRED: 14 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*