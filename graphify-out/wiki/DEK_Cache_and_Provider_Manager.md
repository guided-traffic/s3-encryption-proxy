# DEK Cache and Provider Manager

> 79 nodes · cohesion 0.06

## Key Concepts

- **providers_coverage_test.go** (28 connections) — `internal/orchestration/providers_coverage_test.go`
- **NewProviderManager()** (23 connections) — `internal/orchestration/providers.go`
- **ProviderManager** (23 connections) — `internal/orchestration/providers.go`
- **OrcMetaProviderConfig()** (16 connections) — `internal/orchestration/providers_coverage_test.go`
- **.DecryptDEK()** (14 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaAESProvider()** (13 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCachingManager()** (11 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaNewProviderManager()** (10 connections) — `internal/orchestration/providers_coverage_test.go`
- **providers.go** (8 connections) — `internal/orchestration/providers.go`
- **orcMetaXOR()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **providers_test.go** (8 connections) — `internal/orchestration/providers_test.go`
- **.EncryptDEK()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **Recorder** (7 connections) — `test/e2e/harness/verdict.go`
- **TestOrcMetaDecryptionSelectsProviderByFingerprint()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaExitProviderStillUnwrapsWhatTheAESProviderWrapped()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCountingKEK** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **verdict.go** (7 connections) — `test/e2e/harness/verdict.go`
- **TestOrcMetaForgedExitFingerprintIsRefused()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationExit()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **MockKeyEncryptor** (6 connections) — `internal/orchestration/providers_test.go`
- **github.com/stretchr/testify/mock.Mock** (5 connections)
- **sync.Mutex** (5 connections)
- **TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- *... and 54 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (32 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (4 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (4 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (4 shared connections)
- [Keygen and KEK Factory](Keygen_and_KEK_Factory.md) (3 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (2 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (1 shared connections)
- [MockS3Backend Listing and Upload Stubs](MockS3Backend_Listing_and_Upload_Stubs.md) (1 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/providers_test.go`
- `test/e2e/harness/verdict.go`

## Audit Trail

- EXTRACTED: 211 (90%)
- INFERRED: 24 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*