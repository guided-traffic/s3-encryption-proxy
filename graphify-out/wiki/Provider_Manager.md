# Provider Manager

> 65 nodes · cohesion 0.07

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
- **TestOrcMetaDecryptionSelectsProviderByFingerprint()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaExitProviderStillUnwrapsWhatTheAESProviderWrapped()** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCountingKEK** (7 connections) — `internal/orchestration/providers_coverage_test.go`
- **providers.go** (6 connections) — `internal/orchestration/providers.go`
- **TestOrcMetaForgedExitFingerprintIsRefused()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationExit()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheReturnsSharedStorage()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheServesRepeatedReadsWithoutTouchingTheKEK()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaEncryptDEKRejectsEmptyAndUnknownActiveProvider()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaFingerprintIsStableAcrossConstruction()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaGetLoadedProvidersReportsEachAliasOwnFingerprint()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- *... and 40 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (31 shared connections)
- [Config Structure](Config_Structure.md) (4 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (4 shared connections)
- [AES KEK Provider](AES_KEK_Provider.md) (3 shared connections)
- [Handler Fixture Helpers](Handler_Fixture_Helpers.md) (3 shared connections)
- [Multipart Handler](Multipart_Handler.md) (3 shared connections)
- [Segmented Orchestration Tests](Segmented_Orchestration_Tests.md) (2 shared connections)
- [Metadata Manager Tests](Metadata_Manager_Tests.md) (1 shared connections)
- [Orchestration Manager](Orchestration_Manager.md) (1 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/providers_test.go`

## Audit Trail

- EXTRACTED: 180 (89%)
- INFERRED: 23 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*