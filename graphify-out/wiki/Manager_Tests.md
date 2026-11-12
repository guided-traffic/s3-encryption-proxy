# Manager Tests

> 26 nodes · cohesion 0.17

## Key Concepts

- **NewManager()** (28 connections) — `internal/orchestration/manager.go`
- **OrcMgrAESConfig()** (15 connections) — `internal/orchestration/manager_coverage_test.go`
- **orcMgrOpenSession()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrNewManager()** (12 connections) — `internal/orchestration/manager_coverage_test.go`
- **orcMgrSessionCount()** (10 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrIdleClockFollowsTheLastPart()** (7 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrBackgroundCleanupRemovesExpiredSessions()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrCleanupExpiredSessions()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownEndsTheUploadsItHolds()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweeperAbandonsAtTheBackend()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweeperRetriesAndThenGivesUp()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweeperWithoutAnAbandonerStillForgets()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweptUploadIsLoggedWithWhatAnOperatorNeeds()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrAccessorsAndMetadataFiltering()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownReportsWhatItCouldNotEnd()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownStopsWhenTheBudgetIsGone()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownReturnsWhenContextExpires()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownWithoutBackgroundCleanup()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrPrefixPtr()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrNewManagerInvalidConfigurations()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestManager_ComponentIntegration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ExitProvider()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_LoggingIntegration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ValidateConfiguration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestNewManager()** (3 connections) — `internal/orchestration/manager_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (25 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (21 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (6 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (2 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (1 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (1 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (1 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Orchestration: Providers Coverage Test](Orchestration-_Providers_Coverage_Test.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/manager_coverage_test.go`
- `internal/orchestration/manager_test.go`

## Audit Trail

- EXTRACTED: 101 (85%)
- INFERRED: 18 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*