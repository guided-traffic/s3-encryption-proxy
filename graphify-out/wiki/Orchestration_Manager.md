# Orchestration Manager

> 22 nodes · cohesion 0.19

## Key Concepts

- **NewManager()** (27 connections) — `internal/orchestration/manager.go`
- **manager_coverage_test.go** (11 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrAESConfig()** (8 connections) — `internal/orchestration/manager_coverage_test.go`
- **OrcMgrNewManager()** (7 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrBackgroundCleanupRemovesExpiredSessions()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrCleanupExpiredSessions()** (6 connections) — `internal/orchestration/manager_coverage_test.go`
- **orcMgrOpenSession()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrAccessorsAndMetadataFiltering()** (5 connections) — `internal/orchestration/manager_coverage_test.go`
- **manager_test.go** (5 connections) — `internal/orchestration/manager_test.go`
- **orcMgrSessionCount()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownReturnsWhenContextExpires()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrShutdownWithoutBackgroundCleanup()** (4 connections) — `internal/orchestration/manager_coverage_test.go`
- **Manager** (3 connections)
- **OrcMgrPrefixPtr()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestOrcMgrNewManagerInvalidConfigurations()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestManager_ComponentIntegration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ExitProvider()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_LoggingIntegration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ValidateConfiguration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestNewManager()** (3 connections) — `internal/orchestration/manager_test.go`
- **manager.go** (2 connections) — `internal/orchestration/manager.go`
- **.startBackgroundCleanup()** (2 connections) — `internal/orchestration/manager.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (13 shared connections)
- [Multipart Handler](Multipart_Handler.md) (3 shared connections)
- [Config Structure](Config_Structure.md) (3 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (3 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [Multipart Handler Unit Tests](Multipart_Handler_Unit_Tests.md) (1 shared connections)
- [Object Dispatch and Metadata Tests](Object_Dispatch_and_Metadata_Tests.md) (1 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [Provider Manager](Provider_Manager.md) (1 shared connections)
- [Metadata Manager](Metadata_Manager.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/manager_coverage_test.go`
- `internal/orchestration/manager_test.go`

## Audit Trail

- EXTRACTED: 62 (82%)
- INFERRED: 14 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*