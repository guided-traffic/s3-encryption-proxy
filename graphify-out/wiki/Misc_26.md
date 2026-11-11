# Misc (26)

> 7 nodes · cohesion 0.67

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectOutput** (11 connections)
- **.GetObject()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectInput** (7 connections)
- **.GetObject()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObject()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetObject()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObject()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (3 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (2 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (2 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (1 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 28 (88%)
- INFERRED: 4 (12%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*