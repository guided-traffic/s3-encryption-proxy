# Orchestration Manager Coverage

> 54 nodes · cohesion 0.10

## Key Concepts

- **NewManager()** (29 connections) — `internal/orchestration/manager.go`
- **manager_coverage_test.go** (19 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrAESConfig()** (16 connections) — `internal/orchestration/manager_coverage_test.go`
- **NewMetadataManager()** (15 connections) — `internal/orchestration/metadata.go`
- **orchestration/metadata_coverage_test.go** (14 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMgrNewManager()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
- **orcMgrOpenSession()** (13 connections) — `internal/orchestration/manager_coverage_test.go`
- **orcMgrSessionCount()** (10 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMetaConfig()** (10 connections) — `internal/orchestration/metadata_coverage_test.go`
- **OrcMetaPrefixPtr()** (9 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMgrIdleClockFollowsTheLastPart()** (7 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMetaNewManager()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys()** (7 connections) — `internal/orchestration/metadata_coverage_test.go`
- **metadata_test.go** (7 connections) — `internal/orchestration/metadata_test.go`
- **createTestConfigForMetadata()** (7 connections) — `internal/orchestration/metadata_test.go`
- **TestOrcMgrBackgroundCleanupRemovesExpiredSessions()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrCleanupExpiredSessions()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownEndsTheUploadsItHolds()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweeperAbandonsAtTheBackend()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweeperRetriesAndThenGivesUp()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweeperWithoutAnAbandonerStillForgets()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrSweptUploadIsLoggedWithWhatAnOperatorNeeds()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMetaAssertOnlyAllowedKeys()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- **TestOrcMetaGettersRefuseUnprefixedKeys()** (6 connections) — `internal/orchestration/metadata_coverage_test.go`
- *... and 29 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (36 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (8 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (3 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (1 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)
- [Object Metadata Coverage Tests](Object_Metadata_Coverage_Tests.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/manager_coverage_test.go`
- `internal/orchestration/manager_test.go`
- `internal/orchestration/metadata.go`
- `internal/orchestration/metadata_coverage_test.go`
- `internal/orchestration/metadata_test.go`

## Audit Trail

- EXTRACTED: 177 (86%)
- INFERRED: 30 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*