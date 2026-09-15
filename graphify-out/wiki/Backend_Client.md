# Backend Client

> 15 nodes · cohesion 0.21

## Key Concepts

- **backendOptions()** (10 connections) — `internal/proxy/backend_client_test.go`
- **backend_client_test.go** (9 connections) — `internal/proxy/backend_client_test.go`
- **backendClientOptions()** (8 connections) — `internal/proxy/server.go`
- **backendHTTPClient()** (5 connections) — `internal/proxy/server.go`
- **proxy/server.go** (4 connections) — `internal/proxy/server.go`
- **TestBackendClientOptions_ChecksumsOnlyWhenRequired()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_EveryPathIsObserved()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_InsecureSkipVerifyReachesTheTransport()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_NoEndpointLeavesDefaults()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_PathStyleAndEndpoint()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendHTTPClient_SkipVerifyKeepsEverythingElse()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendHTTPClient_VerifiesByDefault()** (3 connections) — `internal/proxy/backend_client_test.go`
- **discardWriter** (2 connections) — `internal/proxy/backend_client_test.go`
- **github.com/aws/aws-sdk-go-v2/aws/transport/http.BuildableClient** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/backend_client_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (8 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (2 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (2 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (2 shared connections)
- [Server](Server.md) (1 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)

## Source Files

- `internal/proxy/backend_client_test.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 36 (92%)
- INFERRED: 3 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*