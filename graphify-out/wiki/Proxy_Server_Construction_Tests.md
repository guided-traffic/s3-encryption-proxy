# Proxy Server Construction Tests

> 18 nodes · cohesion 0.24

## Key Concepts

- **NewServer()** (28 connections) — `internal/proxy/server.go`
- **proxy/server_coverage_test.go** (14 connections) — `internal/proxy/server_coverage_test.go`
- **RtPxconfig()** (12 connections) — `internal/proxy/server_coverage_test.go`
- **backendClientOptions()** (6 connections) — `internal/proxy/server.go`
- **TestRtPxHealthReportsShutdownState()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxMetadataPrefixResolution()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsShutdownFailure()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxGetHandlerBuildsUsableRouter()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxNewServerLoadsAllProvidersButActivatesOne()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxNewServerRejectsUnusableConfig()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxRequestTrackerCountsRequests()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsListenFailure()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartShutsDownOnContextCancel()** (4 connections) — `internal/proxy/server_coverage_test.go`
- **proxy/server.go** (3 connections) — `internal/proxy/server.go`
- **RtPxnewFailingListener()** (3 connections) — `internal/proxy/server_coverage_test.go`
- **RtPxstringPtr()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **RtPxquietWriter** (2 connections) — `internal/proxy/server_coverage_test.go`
- **.Write()** (1 connections) — `internal/proxy/server_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (10 shared connections)
- [Proxy Server Auth Error Tests](Proxy_Server_Auth_Error_Tests.md) (5 shared connections)
- [Proxy TLS Listener Tests](Proxy_TLS_Listener_Tests.md) (4 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (3 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (2 shared connections)
- [Failing Listener Test Fake](Failing_Listener_Test_Fake.md) (2 shared connections)
- [Main Entrypoint Call Graph](Main_Entrypoint_Call_Graph.md) (2 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (1 shared connections)
- [Middleware Chain Setup Tests](Middleware_Chain_Setup_Tests.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `internal/proxy/server.go`
- `internal/proxy/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 51 (70%)
- INFERRED: 22 (30%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*