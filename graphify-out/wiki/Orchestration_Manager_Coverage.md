# Orchestration Manager Coverage

> 29 nodes · cohesion 0.20

## Key Concepts

- **NewManager()** (29 connections) — `internal/orchestration/manager.go`
- **manager_coverage_test.go** (19 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrAESConfig()** (16 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrNewManager()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
- **orcMgrOpenSession()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
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
- **manager_test.go** (5 connections) — `internal/orchestration/manager_test.go`
- **TestOrcMgrShutdownReturnsWhenContextExpires()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownWithoutBackgroundCleanup()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **Manager** (3 connections)
- **OrcMgrPrefixPtr()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrNewManagerInvalidConfigurations()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestManager_ComponentIntegration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ExitProvider()** (3 connections) — `internal/orchestration/manager_test.go`
- *... and 4 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (21 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (4 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (3 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Metadata Manager Coverage](Metadata_Manager_Coverage.md) (2 shared connections)
- [Shutdown](Shutdown.md) (1 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/manager_coverage_test.go`
- `internal/orchestration/manager_test.go`

## Audit Trail

- EXTRACTED: 105 (86%)
- INFERRED: 17 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*