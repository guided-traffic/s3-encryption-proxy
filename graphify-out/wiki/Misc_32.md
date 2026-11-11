# Misc (32)

> 7 nodes · cohesion 0.67

## Key Concepts

- **.ListObjects()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsInput** (6 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsOutput** (6 connections)
- **.ListObjects()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListObjects()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.ListObjects()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.ListObjects()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (2 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (2 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (2 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 22 (85%)
- INFERRED: 4 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*