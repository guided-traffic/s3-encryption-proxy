# GetObject Backend Method

> 6 nodes · cohesion 0.53

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectOutput** (10 connections)
- **.GetObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectInput** (4 connections)
- **.GetObject()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetObject()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (4 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (4 shared connections)
- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 22 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*