# Orchestration: Providers Coverage Test

> 32 nodes · cohesion 0.12

## Key Concepts

- **NewProviderManager()** (24 connections) — `internal/orchestration/providers.go`
- **OrcMetaProviderConfig()** (15 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaAESProvider()** (12 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaCachingManager()** (11 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaNewProviderManager()** (10 connections) — `internal/orchestration/providers_coverage_test.go`
- **wrapDEK()** (10 connections) — `internal/orchestration/providers_test.go`
- **orcMetaXOR()** (8 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDecryptionSelectsProviderByFingerprint()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaExitProviderStillUnwrapsWhatTheAESProviderWrapped()** (6 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaFingerprintIsStableAcrossConstruction()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaForgedExitFingerprintIsRefused()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaGetLoadedProvidersReportsEachAliasOwnFingerprint()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationAES()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationExit()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationRejectsBrokenAESKey()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationRejectsMissingActiveProvider()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationRejectsUnknownSecondaryType()** (5 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheIsConcurrencySafe()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheReturnsSharedStorage()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaDEKCacheServesRepeatedReadsWithoutTouchingTheKEK()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaProviderRegistrationRSAIsGone()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaRejectsEmptyDEKAndUnknownActiveProvider()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestProviderManager_Cache()** (4 connections) — `internal/orchestration/providers_test.go`
- *... and 7 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (32 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (27 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (5 shared connections)
- [Tampering Harness](Tampering_Harness.md) (3 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Config: Config](Config-_Config.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)
- [Orchestration: Metadata Coverage Test](Orchestration-_Metadata_Coverage_Test.md) (1 shared connections)
- [Factory: Factory](Factory-_Factory.md) (1 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/providers_test.go`

## Audit Trail

- EXTRACTED: 107 (79%)
- INFERRED: 29 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*