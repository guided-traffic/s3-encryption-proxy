# Backend TLS Trust

> 28 nodes · cohesion 0.11

## Key Concepts

- **NewServer()** (30 connections) — `internal/proxy/server.go`
- **RtPxconfig()** (12 connections) — `internal/proxy/server_coverage_test.go`
- **createTestConfigExit()** (8 connections) — `internal/proxy/server_test.go`
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
- **TestTLSConfigurationLogging()** (4 connections) — `internal/proxy/tls_test.go`
- **TestServer_CORSOptionsRequest()** (3 connections) — `internal/proxy/server_test.go`
- *... and 3 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (28 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (23 shared connections)
- [Config Types and Monitoring Plan](Config_Types_and_Monitoring_Plan.md) (3 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (3 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Misc (18)](Misc_18.md) (1 shared connections)
- [Failing Listener Test Fixture](Failing_Listener_Test_Fixture.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Io](Dataencryption-_Segmented_Gcm_Io.md) (1 shared connections)
- [Manager Tests](Manager_Tests.md) (1 shared connections)
- [Monitoring: Status](Monitoring-_Status.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (1 shared connections)

## Source Files

- `internal/proxy/server.go`
- `internal/proxy/server_coverage_test.go`
- `internal/proxy/server_test.go`
- `internal/proxy/tls_test.go`

## Audit Trail

- EXTRACTED: 87 (80%)
- INFERRED: 22 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*