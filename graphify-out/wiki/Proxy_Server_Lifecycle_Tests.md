# Proxy Server Lifecycle Tests

> 40 nodes · cohesion 0.10

## Key Concepts

- **NewServer()** (28 connections) — `internal/proxy/server.go`
- **proxy/server_coverage_test.go** (16 connections) — `internal/proxy/server_coverage_test.go`
- **server_test.go** (15 connections) — `internal/proxy/server_test.go`
- **RtPxconfig()** (13 connections) — `internal/proxy/server_coverage_test.go`
- **createTestConfigExit()** (9 connections) — `internal/proxy/server_test.go`
- **TestServer_handleS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **TestServer_WriteS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **TestRtPxMetadataPrefixResolution()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxProbesReportShutdownState()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsShutdownFailure()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **proxy/tls_test.go** (5 connections) — `internal/proxy/tls_test.go`
- **generateTestCertificates()** (5 connections) — `internal/proxy/tls_test.go`
- **TestRtPxListenerBudgetsReachTheServer()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxNewServerLoadsAllProvidersButActivatesOne()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxNewServerRejectsUnusableConfig()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxRequestTrackerCountsRequests()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsListenFailure()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartShutsDownOnContextCancel()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxTransferBudgetsDefaultToNoDeadline()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **routeHandlerName()** (4 connections) — `internal/proxy/server_test.go`
- **sdkError()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_AuthErrorDoesNotReflectAttackerText()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_HTTPStatusFromAWSError()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_NewServer_WithExitProvider()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_ProbeEndpoints()** (4 connections) — `internal/proxy/server_test.go`
- *... and 15 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (30 shared connections)
- [Server](Server.md) (3 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (3 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (3 shared connections)
- [Backend Client](Backend_Client.md) (2 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (2 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (1 shared connections)
- [Main](Main.md) (1 shared connections)
- [Orchestration Manager Coverage](Orchestration_Manager_Coverage.md) (1 shared connections)
- [Monitoring Status Endpoint](Monitoring_Status_Endpoint.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)

## Source Files

- `internal/proxy/server.go`
- `internal/proxy/server_coverage_test.go`
- `internal/proxy/server_test.go`
- `internal/proxy/tls_test.go`

## Audit Trail

- EXTRACTED: 108 (84%)
- INFERRED: 21 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*