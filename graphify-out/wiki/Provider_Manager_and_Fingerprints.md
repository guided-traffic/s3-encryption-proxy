# Provider Manager and Fingerprints

> 79 nodes · cohesion 0.07

## Key Concepts

- **NewProviderManager()** (34 connections) — `internal/orchestration/providers.go`
- **providers_coverage_test.go** (33 connections) — `internal/orchestration/providers_coverage_test.go`
- **ProviderManager** (21 connections) — `internal/orchestration/providers.go`
- **.GetActiveFingerprint()** (17 connections) — `internal/orchestration/providers.go`
- **OrcMetaProviderConfig()** (14 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (13 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (13 connections) — `internal/orchestration/providers.go`
- **OrcMetaAESProvider()** (12 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaNewProviderManager()** (12 connections) — `internal/orchestration/providers_coverage_test.go`
- **.GetActiveProviderAlgorithm()** (11 connections) — `internal/orchestration/providers.go`
- **.GetProviderByFingerprint()** (11 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaProviderRegistrationAES()** (11 connections) — `internal/orchestration/providers_coverage_test.go`
- **.GetAllProviders()** (10 connections) — `internal/orchestration/providers.go`
- **OrcMetaCachingManager()** (10 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaRegisterProviderAddsToRegistryAndFactory()** (10 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestProviderManager_GetProviderInfo()** (10 connections) — `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/providers_test.go`
- **.GetKeyEncryptor()** (9 connections) — `pkg/encryption/factory/factory.go`
- **.buildEncryptionMetadataSimple()** (9 connections) — `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/singlepart.go`
- **.cacheGet()** (9 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (9 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaEncryptDEKRejectsEmptyAndUnknownActiveProvider()** (9 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationNone()** (9 connections) — `internal/orchestration/providers_coverage_test.go`
- **providers_test.go** (9 connections) — `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/providers_test.go`
- **orcMetaXOR()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDecryptionSelectsProviderByFingerprint()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- *... and 54 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/providers_test.go`
- `/Users/hfi/repos/s3-encryption-proxy/internal/orchestration/singlepart.go`
- `docs/architecture/callgraph_orchestration_layer.svg`
- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `pkg/encryption/factory/factory.go`

## Audit Trail

- EXTRACTED: 359 (61%)
- INFERRED: 232 (39%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*