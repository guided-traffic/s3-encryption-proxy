# DEK Cache and Providers

> 40 nodes · cohesion 0.15

## Key Concepts

- **providers_coverage_test.go** (33 connections) — `internal/orchestration/providers_coverage_test.go`
- **NewProviderManager()** (27 connections) — `internal/orchestration/providers.go`
- **OrcMetaProviderConfig()** (15 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaNewProviderManager()** (14 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaAESProvider()** (13 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (13 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCachingManager()** (11 connections) — `internal/orchestration/providers_coverage_test.go`
- **orcMetaXOR()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCountingKEK** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **.EncryptDEK()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDecryptionSelectsProviderByFingerprint()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationRSA()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaRSAKeyPEMs()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaFingerprintIsStableAcrossConstruction()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationAES()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationNone()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaRegisterProviderAddsToRegistryAndFactory()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheReturnsSharedStorage()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheServesRepeatedReadsWithoutTouchingTheKEK()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaEncryptDEKRejectsEmptyAndUnknownActiveProvider()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaGetLoadedProvidersReportsEachAliasOwnFingerprint()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationRejectsBrokenAESKey()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- *... and 15 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (28 shared connections)
- [Provider Manager Cache Tests](Provider_Manager_Cache_Tests.md) (7 shared connections)
- [Provider Manager DEK Cache](Provider_Manager_DEK_Cache.md) (6 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (3 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [Encryption Metadata Management](Encryption_Metadata_Management.md) (1 shared connections)
- [Content Type Factory Selection](Content_Type_Factory_Selection.md) (1 shared connections)
- [Encryption Factory Tests](Encryption_Factory_Tests.md) (1 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (1 shared connections)
- [Multipart Session Lifecycle Tests](Multipart_Session_Lifecycle_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`

## Audit Trail

- EXTRACTED: 146 (86%)
- INFERRED: 23 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*