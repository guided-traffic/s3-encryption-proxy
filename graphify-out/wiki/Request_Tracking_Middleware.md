# Request Tracking Middleware

> 11 nodes · cohesion 0.22

## Key Concepts

- **Server** (19 connections) — `internal/proxy/server.go`
- **RequestTracker** (6 connections) — `internal/proxy/middleware/tracking.go`
- **NewRequestTracker()** (5 connections) — `internal/proxy/middleware/tracking.go`
- **.Shutdown()** (3 connections) — `internal/proxy/server.go`
- **.Start()** (3 connections) — `internal/proxy/server.go`
- **tracking.go** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/server.go`
- **.SetHandlers()** (1 connections) — `internal/proxy/middleware/tracking.go`
- **.getMetadataPrefix()** (1 connections) — `internal/proxy/server.go`
- **.SetRequestTracker()** (1 connections) — `internal/proxy/server.go`

## Relationships

- [Multipart Handler](Multipart_Handler.md) (4 shared connections)
- [CORS Middleware](CORS_Middleware.md) (3 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (2 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (2 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (2 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (2 shared connections)
- [HTTP Middleware Tests](HTTP_Middleware_Tests.md) (1 shared connections)
- [pprof Listener](pprof_Listener.md) (1 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (1 shared connections)
- [Config Structure](Config_Structure.md) (1 shared connections)
- [Logging Middleware](Logging_Middleware.md) (1 shared connections)
- [SigV4 Header Authentication](SigV4_Header_Authentication.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/tracking.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 32 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*