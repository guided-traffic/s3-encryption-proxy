# Provider Manager DEK Cache

> 26 nodes · cohesion 0.10

## Key Concepts

- **ProviderManager** (33 connections) — `internal/orchestration/providers.go`
- **providers.go** (6 connections) — `internal/orchestration/providers.go`
- **.GetAllProviders()** (5 connections) — `internal/orchestration/providers.go`
- **ProviderInfo** (4 connections) — `internal/orchestration/providers.go`
- **.DecryptDEK()** (4 connections) — `internal/orchestration/providers.go`
- **.GetLoadedProviders()** (4 connections) — `internal/orchestration/providers.go`
- **buildDEKCacheKey()** (3 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaDEKCacheKeyIsScopedByFingerprint()** (3 connections) — `internal/orchestration/providers_coverage_test.go`
- **ProviderSummary** (3 connections) — `internal/orchestration/providers.go`
- **.GetLoadedProviders()** (2 connections) — `internal/orchestration/manager.go`
- **.cacheGet()** (2 connections) — `internal/orchestration/providers.go`
- **.cachePut()** (2 connections) — `internal/orchestration/providers.go`
- **.GetActiveProviderAlias()** (2 connections) — `internal/orchestration/providers.go`
- **.GetFactory()** (2 connections) — `internal/orchestration/providers.go`
- **.GetProviderAliases()** (2 connections) — `internal/orchestration/providers.go`
- **.GetProviderByFingerprint()** (2 connections) — `internal/orchestration/providers.go`
- **container/list.Element** (1 connections)
- **container/list.List** (1 connections)
- **dekCacheEntry** (1 connections) — `internal/orchestration/providers.go`
- **.ClearCache()** (1 connections) — `internal/orchestration/providers.go`
- **.ClearKeyCache()** (1 connections) — `internal/orchestration/providers.go`
- **.EncryptDEK()** (1 connections) — `internal/orchestration/providers.go`
- **.GetActiveFingerprint()** (1 connections) — `internal/orchestration/providers.go`
- **.GetActiveProviderAlgorithm()** (1 connections) — `internal/orchestration/providers.go`
- **.IsNoneProvider()** (1 connections) — `internal/orchestration/providers.go`
- *... and 1 more nodes in this community*

## Relationships

- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (6 shared connections)
- [KEK Provider Factory](KEK_Provider_Factory.md) (4 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (3 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (3 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (2 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (1 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (1 shared connections)
- [Envelope Encryptor Implementation](Envelope_Encryptor_Implementation.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`

## Audit Trail

- EXTRACTED: 54 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*