# Requestid

> 11 nodes · cohesion 0.33

## Key Concepts

- **EnsureRequestID()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestID()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestIDMiddleware()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **requestid.go** (5 connections) — `internal/proxy/middleware/requestid.go`
- **TestMwEnsureRequestIDDoesNotRestateAnExistingID()** (5 connections) — `internal/proxy/middleware/requestid_test.go`
- **requestid_test.go** (4 connections) — `internal/proxy/middleware/requestid_test.go`
- **TestMwRequestIDIsStatedAndReachesTheHandler()** (4 connections) — `internal/proxy/middleware/requestid_test.go`
- **NewRequestID()** (3 connections) — `internal/proxy/middleware/requestid.go`
- **TestMwRequestIDIsEmptyOutsideTheMiddleware()** (3 connections) — `internal/proxy/middleware/requestid_test.go`
- **TestMwRequestIDIsUniquePerRequest()** (3 connections) — `internal/proxy/middleware/requestid_test.go`
- **requestIDKey** (1 connections) — `internal/proxy/middleware/requestid.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Router](Router.md) (1 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (1 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (1 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (1 shared connections)
- [HTTP Middleware Coverage Tests](HTTP_Middleware_Coverage_Tests.md) (1 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/requestid.go`
- `internal/proxy/middleware/requestid_test.go`

## Audit Trail

- EXTRACTED: 20 (71%)
- INFERRED: 8 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*