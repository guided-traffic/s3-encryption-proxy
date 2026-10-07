# Requestid

> 12 nodes · cohesion 0.29

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
- **.Middleware()** (3 connections) — `internal/proxy/middleware/logging.go`
- **requestIDKey** (1 connections) — `internal/proxy/middleware/requestid.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (2 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (2 shared connections)
- [Router](Router.md) (1 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)
- [Logging Middleware](Logging_Middleware.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/logging.go`
- `internal/proxy/middleware/requestid.go`
- `internal/proxy/middleware/requestid_test.go`

## Audit Trail

- EXTRACTED: 22 (73%)
- INFERRED: 8 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*