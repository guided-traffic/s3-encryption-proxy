# DEK Cache and Provider Manager

> 75 nodes · cohesion 0.06

## Key Concepts

- **providers_coverage_test.go** (28 connections) — `internal/orchestration/providers_coverage_test.go`
- **NewProviderManager()** (23 connections) — `internal/orchestration/providers.go`
- **ProviderManager** (23 connections) — `internal/orchestration/providers.go`
- **OrcMetaProviderConfig()** (16 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (14 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaAESProvider()** (13 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCachingManager()** (11 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaNewProviderManager()** (10 connections) — `internal/orchestration/providers_coverage_test.go`
- **orcMetaXOR()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **providers_test.go** (8 connections) — `internal/orchestration/providers_test.go`
- **.EncryptDEK()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **Recorder** (7 connections) — `test/e2e/harness/verdict.go`
- **TestOrcMetaDecryptionSelectsProviderByFingerprint()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaExitProviderStillUnwrapsWhatTheAESProviderWrapped()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCountingKEK** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **verdict.go** (7 connections) — `test/e2e/harness/verdict.go`
- **providers.go** (6 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaForgedExitFingerprintIsRefused()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationExit()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **sync.Mutex** (5 connections)
- **TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheReturnsSharedStorage()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheServesRepeatedReadsWithoutTouchingTheKEK()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- *... and 50 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (32 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (4 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (4 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (4 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (3 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (3 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)
- [Report](Report.md) (1 shared connections)
- [Metadata Manager Coverage](Metadata_Manager_Coverage.md) (1 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/providers_test.go`
- `test/e2e/harness/verdict.go`

## Audit Trail

- EXTRACTED: 202 (89%)
- INFERRED: 24 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*