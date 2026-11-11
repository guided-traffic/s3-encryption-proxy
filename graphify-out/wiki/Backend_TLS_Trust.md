# Backend TLS Trust

> 35 nodes · cohesion 0.08

## Key Concepts

- **NewServer()** (31 connections) — `internal/proxy/server.go`
- **RtPxconfig()** (13 connections) — `internal/proxy/server_coverage_test.go`
- **createTestConfigExit()** (9 connections) — `internal/proxy/server_test.go`
- **backendClientOptions()** (8 connections) — `internal/proxy/server.go`
- **backendHTTPClient()** (6 connections) — `internal/proxy/server.go`
- **TestServer_handleS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **TestServer_WriteS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **TestRtPxMetadataPrefixResolution()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsShutdownFailure()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **generateTestCertificates()** (5 connections) — `internal/proxy/tls_test.go`
- **TestRtPxListenerBudgetsReachTheServer()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxNewServerLoadsAllProvidersButActivatesOne()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxNewServerRejectsUnusableConfig()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxProbesReportShutdownState()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxRequestTrackerCountsRequests()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsListenFailure()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartShutsDownOnContextCancel()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxTransferBudgetsDefaultToNoDeadline()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **sdkError()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_AuthErrorDoesNotReflectAttackerText()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_HTTPStatusFromAWSError()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_NewServer_WithExitProvider()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_ProbeEndpoints()** (4 connections) — `internal/proxy/server_test.go`
- **TestServerTLSConfiguration()** (4 connections) — `internal/proxy/tls_test.go`
- **TestServerTLSGracefulShutdown()** (4 connections) — `internal/proxy/tls_test.go`
- *... and 10 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (32 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (26 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (5 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (3 shared connections)
- [Manager Tests](Manager_Tests.md) (2 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (1 shared connections)
- [Monitoring: Backend Test](Monitoring-_Backend_Test.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (1 shared connections)
- [Router and Middleware Setup](Router_and_Middleware_Setup.md) (1 shared connections)
- [Misc](Misc.md) (1 shared connections)

## Source Files

- `docs/tickets/039-backend-certificate-verification-failure-is-named.md`
- `internal/proxy/backend_client_test.go`
- `internal/proxy/server.go`
- `internal/proxy/server_coverage_test.go`
- `internal/proxy/server_test.go`
- `internal/proxy/tls_test.go`

## Audit Trail

- EXTRACTED: 104 (80%)
- INFERRED: 26 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*