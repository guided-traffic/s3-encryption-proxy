# Proxy Server Auth Error Tests

> 16 nodes · cohesion 0.22

## Key Concepts

- **server_test.go** (16 connections) — `internal/proxy/server_test.go`
- **createTestConfigNone()** (9 connections) — `internal/proxy/server_test.go`
- **TestServer_handleS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **TestServer_HandleS3Error_KEK_MISSING()** (6 connections) — `internal/proxy/server_test.go`
- **routeHandlerName()** (4 connections) — `internal/proxy/server_test.go`
- **sdkError()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_AuthErrorDoesNotReflectAttackerText()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_HealthEndpoint()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_HTTPStatusFromAWSError()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_NewServer_WithNoneProvider()** (4 connections) — `internal/proxy/server_test.go`
- **TestServer_CORSOptionsRequest()** (3 connections) — `internal/proxy/server_test.go`
- **TestServer_MiddlewareApplication()** (3 connections) — `internal/proxy/server_test.go`
- **TestServer_UploadPartCopyIsNotShadowedByUploadPart()** (3 connections) — `internal/proxy/server_test.go`
- **TestServer_AuthErrorCodesAllHaveWording()** (2 connections) — `internal/proxy/server_test.go`
- **TestServer_HealthEndpointLogging()** (2 connections) — `internal/proxy/server_test.go`
- **TestServer_RoutingSetup()** (2 connections) — `internal/proxy/server_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (13 shared connections)
- [Proxy Server Construction Tests](Proxy_Server_Construction_Tests.md) (5 shared connections)
- [Proxy Utils Tests](Proxy_Utils_Tests.md) (3 shared connections)
- [Proxy Utility Functions](Proxy_Utility_Functions.md) (1 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (1 shared connections)
- [CORS Logging Tracking Middleware](CORS_Logging_Tracking_Middleware.md) (1 shared connections)

## Source Files

- `internal/proxy/server_test.go`

## Audit Trail

- EXTRACTED: 45 (90%)
- INFERRED: 5 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*