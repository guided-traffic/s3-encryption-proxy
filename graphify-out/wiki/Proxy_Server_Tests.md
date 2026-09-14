# Proxy Server Tests

> 72 nodes · cohesion 0.06

## Key Concepts

- **NewServer()** (25 connections) — `internal/proxy/server.go`
- **utils_coverage_test.go** (17 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **HandleS3Error()** (17 connections) — `internal/proxy/utils/utils.go`
- **server_test.go** (15 connections) — `internal/proxy/server_test.go`
- **proxy/server_coverage_test.go** (13 connections) — `internal/proxy/server_coverage_test.go`
- **RtPxconfig()** (11 connections) — `internal/proxy/server_coverage_test.go`
- **UtlCaptureLogger()** (11 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlDecodeLog()** (10 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **createTestConfigExit()** (9 connections) — `internal/proxy/server_test.go`
- **UtlParseErrorBody()** (9 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_DoesNotLeakBackendDetail()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_StatusDrivesLogLevel()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **UtlFindLog()** (8 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_InternalTextStaysInternal()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_NilError()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_ResourceComposition()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlHandleS3Error_WriteFailureIsLogged()** (7 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **backendClientOptions()** (6 connections) — `internal/proxy/server.go`
- **TestServer_handleS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **TestServer_HandleS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **RtPxfailingListener** (6 connections) — `internal/proxy/server_coverage_test.go`
- **UtlFailingWriter** (6 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestRtPxHealthReportsShutdownState()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxMetadataPrefixResolution()** (5 connections) — `internal/proxy/server_coverage_test.go`
- **TestRtPxStartReportsShutdownFailure()** (5 connections) — `internal/proxy/server_coverage_test.go`
- *... and 47 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (38 shared connections)
- [Config Structure](Config_Structure.md) (4 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (3 shared connections)
- [Object Helper Functions](Object_Helper_Functions.md) (3 shared connections)
- [Request Tracking Middleware](Request_Tracking_Middleware.md) (2 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (2 shared connections)
- [ListBuckets Handler Tests](ListBuckets_Handler_Tests.md) (1 shared connections)
- [Request Parser Tests](Request_Parser_Tests.md) (1 shared connections)
- [Multipart Handler](Multipart_Handler.md) (1 shared connections)
- [Backend SDK Client Options](Backend_SDK_Client_Options.md) (1 shared connections)
- [Router and Middleware Setup](Router_and_Middleware_Setup.md) (1 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (1 shared connections)

## Source Files

- `internal/proxy/server.go`
- `internal/proxy/server_coverage_test.go`
- `internal/proxy/server_test.go`
- `internal/proxy/tls_test.go`
- `internal/proxy/utils/utils.go`
- `internal/proxy/utils/utils_coverage_test.go`
- `internal/proxy/utils/utils_test.go`

## Audit Trail

- EXTRACTED: 192 (86%)
- INFERRED: 30 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*