# Backend Client

> 16 nodes · cohesion 0.19

## Key Concepts

- **backendOptions()** (10 connections) — `internal/proxy/backend_client_test.go`
- **backend_client_test.go** (9 connections) — `internal/proxy/backend_client_test.go`
- **backendClientOptions()** (8 connections) — `internal/proxy/server.go`
- **proxy/server.go** (7 connections) — `internal/proxy/server.go`
- **backendHTTPClient()** (6 connections) — `internal/proxy/server.go`
- **TestBackendClientOptions_ChecksumsOnlyWhenRequired()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_EveryPathIsObserved()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_InsecureSkipVerifyReachesTheTransport()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_NoEndpointLeavesDefaults()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_PathStyleAndEndpoint()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendHTTPClient_SkipVerifyKeepsEverythingElse()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendHTTPClient_VerifiesByDefault()** (3 connections) — `internal/proxy/backend_client_test.go`
- **http:// backend endpoint refuses the start** (2 connections) — `docs/security/threat-model.md`
- **discardWriter** (2 connections) — `internal/proxy/backend_client_test.go`
- **github.com/aws/aws-sdk-go-v2/aws/transport/http.BuildableClient** (1 connections)
- **.Write()** (1 connections) — `internal/proxy/backend_client_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (8 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (3 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (2 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (2 shared connections)
- [Server](Server.md) (1 shared connections)
- [Transfer Bounds and Shutdown](Transfer_Bounds_and_Shutdown.md) (1 shared connections)
- [SigV4 Header and Presign Tests](SigV4_Header_and_Presign_Tests.md) (1 shared connections)
- [Backend Call Observation](Backend_Call_Observation.md) (1 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (1 shared connections)
- [Multipart Part Layout Decisions](Multipart_Part_Layout_Decisions.md) (1 shared connections)

## Source Files

- `docs/security/threat-model.md`
- `internal/proxy/backend_client_test.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 41 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*