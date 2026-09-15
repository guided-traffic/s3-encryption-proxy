# Server

> 9 nodes · cohesion 0.31

## Key Concepts

- **Server** (23 connections) — `internal/proxy/server.go`
- **.Start()** (5 connections) — `internal/proxy/server.go`
- **.Shutdown()** (3 connections) — `internal/proxy/server.go`
- **.shutdownBudget()** (3 connections) — `internal/proxy/server.go`
- **.Addr()** (2 connections) — `internal/proxy/server.go`
- **.SetShutdownDeadline()** (2 connections) — `internal/proxy/server.go`
- **.SetShutdownStateHandler()** (2 connections) — `internal/proxy/server.go`
- **sync/atomic.Value** (1 connections)
- **.SetRequestTracker()** (1 connections) — `internal/proxy/server.go`

## Relationships

- [S3 Signing Helper](S3_Signing_Helper.md) (3 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (2 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (2 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (2 shared connections)
- [Monitoring HTTP Server](Monitoring_HTTP_Server.md) (1 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (1 shared connections)
- [Configuration Struct and Accessors](Configuration_Struct_and_Accessors.md) (1 shared connections)
- [Integration Corpus Seed and Budget](Integration_Corpus_Seed_and_Budget.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)
- [S3auth Robust](S3auth_Robust.md) (1 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/server.go`

## Audit Trail

- EXTRACTED: 31 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*