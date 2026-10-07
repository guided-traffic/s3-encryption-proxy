# Server

> 14 nodes · cohesion 0.19

## Key Concepts

- **Server** (23 connections) — `internal/proxy/server.go`
- **RequestTracker** (6 connections) — `internal/proxy/middleware/tracking.go`
- **NewRequestTracker()** (5 connections) — `internal/proxy/middleware/tracking.go`
- **.Start()** (5 connections) — `internal/proxy/server.go`
- **.Shutdown()** (3 connections) — `internal/proxy/server.go`
- **.shutdownBudget()** (3 connections) — `internal/proxy/server.go`
- **tracking.go** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.Middleware()** (2 connections) — `internal/proxy/middleware/tracking.go`
- **.Addr()** (2 connections) — `internal/proxy/server.go`
- **.SetShutdownDeadline()** (2 connections) — `internal/proxy/server.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/server.go`
- **sync/atomic.Value** (1 connections)
- **.SetHandlers()** (1 connections) — `internal/proxy/middleware/tracking.go`
- **.SetRequestTracker()** (1 connections) — `internal/proxy/server.go`

## Relationships

- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (4 shared connections)
- [Health Probes and Request Tracker](Health_Probes_and_Request_Tracker.md) (3 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (2 shared connections)
- [Encryption Mode Proxy Instances](Encryption_Mode_Proxy_Instances.md) (2 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (2 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)
- [Pprof](Pprof.md) (1 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Integration Corpus Seed and Budget](Integration_Corpus_Seed_and_Budget.md) (1 shared connections)
- [Logging Middleware](Logging_Middleware.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/tracking.go`
- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 40 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*