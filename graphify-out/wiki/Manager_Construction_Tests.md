# Manager Construction Tests

> 11 nodes · cohesion 0.33

## Key Concepts

- **NewManager()** (33 connections) — `internal/orchestration/manager.go`
- **manager_test.go** (7 connections) — `internal/orchestration/manager_test.go`
- **calculateSHA256ForManagerTest()** (4 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ComponentIntegration()** (4 connections) — `internal/orchestration/manager_test.go`
- **TestManager_NoneProvider()** (4 connections) — `internal/orchestration/manager_test.go`
- **TestManager_StreamingOperations()** (4 connections) — `internal/orchestration/manager_test.go`
- **TestOrcMgrNewManagerInvalidConfigurations()** (3 connections) — `internal/orchestration/manager_coverage_test.go`
- **TestManager_LoggingIntegration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestManager_ValidateConfiguration()** (3 connections) — `internal/orchestration/manager_test.go`
- **TestNewManager()** (3 connections) — `internal/orchestration/manager_test.go`
- **.GetStreamingSegmentSize()** (2 connections) — `internal/orchestration/manager.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (7 shared connections)
- [Orchestration Manager Tests](Orchestration_Manager_Tests.md) (5 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (5 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (2 shared connections)
- [Encryption Metadata Management](Encryption_Metadata_Management.md) (2 shared connections)
- [HMAC Manager Tests](HMAC_Manager_Tests.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [Multipart Create Handler Tests](Multipart_Create_Handler_Tests.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (1 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/orchestration/manager_coverage_test.go`
- `internal/orchestration/manager_test.go`

## Audit Trail

- EXTRACTED: 34 (65%)
- INFERRED: 18 (35%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*