# Adr: 0027 Conformance Is Asserted Against A Backend That Is Not Minio

> 10 nodes · cohesion 0.24

## Key Concepts

- **EnsureRequestID()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestID()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **RequestIDMiddleware()** (6 connections) — `internal/proxy/middleware/requestid.go`
- **Logger** (5 connections) — `internal/proxy/middleware/logging.go`
- **TestMwEnsureRequestIDDoesNotRestateAnExistingID()** (5 connections) — `internal/proxy/middleware/requestid_test.go`
- **TestMwRequestIDIsStatedAndReachesTheHandler()** (4 connections) — `internal/proxy/middleware/requestid_test.go`
- **NewRequestID()** (3 connections) — `internal/proxy/middleware/requestid.go`
- **TestMwRequestIDIsEmptyOutsideTheMiddleware()** (3 connections) — `internal/proxy/middleware/requestid_test.go`
- **TestMwRequestIDIsUniquePerRequest()** (3 connections) — `internal/proxy/middleware/requestid_test.go`
- **.Middleware()** (3 connections) — `internal/proxy/middleware/logging.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (9 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [CORS and Middleware](CORS_and_Middleware.md) (2 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Server and Listings](Server_and_Listings.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Io (2)](Dataencryption-_Segmented_Gcm_Io_2.md) (1 shared connections)
- [Method Not Allowed Handler](Method_Not_Allowed_Handler.md) (1 shared connections)
- [Misc (15)](Misc_15.md) (1 shared connections)

## Source Files

- `internal/proxy/middleware/logging.go`
- `internal/proxy/middleware/requestid.go`
- `internal/proxy/middleware/requestid_test.go`

## Audit Trail

- EXTRACTED: 25 (76%)
- INFERRED: 8 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*