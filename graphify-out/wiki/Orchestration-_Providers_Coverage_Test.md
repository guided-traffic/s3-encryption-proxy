# Orchestration: Providers Coverage Test

> 25 nodes · cohesion 0.17

## Key Concepts

- **NewProviderManager()** (25 connections) — `internal/orchestration/providers.go`
- **OrcMetaProviderConfig()** (16 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaAESProvider()** (13 connections) — `internal/orchestration/providers_coverage_test.go`
- **OrcMetaNewProviderManager()** (10 connections) — `internal/orchestration/providers_coverage_test.go`
- **wrapDEK()** (10 connections) — `internal/orchestration/providers_test.go`
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
- **TestOrcMetaProviderRegistrationRSAIsGone()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaRejectsEmptyDEKAndUnknownActiveProvider()** (4 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestProviderManager_Cache()** (4 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_EncryptDecryptDEK()** (4 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_ExitProvider()** (4 connections) — `internal/orchestration/providers_test.go`
- **TestOrcMetaDecryptDEKUnknownFingerprint()** (3 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestOrcMetaGetActiveProviderAliasHandlesBrokenConfig()** (3 connections) — `internal/orchestration/providers_coverage_test.go`
- **TestNewProviderManager()** (3 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_GetProviderInfo()** (3 connections) — `internal/orchestration/providers_test.go`
- **TestProviderManager_NewProviderManager()** (3 connections) — `internal/orchestration/providers_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (25 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (21 shared connections)
- [Orchestration: Providers](Orchestration-_Providers.md) (4 shared connections)
- [Config: Config](Config-_Config.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (2 shared connections)
- [Factory: Factory](Factory-_Factory.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)
- [Orchestration: Metadata Coverage Test](Orchestration-_Metadata_Coverage_Test.md) (1 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers.go`
- `internal/orchestration/providers_coverage_test.go`
- `internal/orchestration/providers_test.go`

## Audit Trail

- EXTRACTED: 82 (74%)
- INFERRED: 29 (26%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*