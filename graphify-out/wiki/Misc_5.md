# Misc (5)

> 7 nodes · cohesion 0.67

## Key Concepts

- **.CreateMultipartUpload()** (9 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadInput** (8 connections)
- **.CreateMultipartUpload()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadOutput** (5 connections)
- **.CreateMultipartUpload()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.CreateMultipartUpload()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CreateMultipartUpload()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (2 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (2 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (2 shared connections)
- [Object Checksum Agreement Tests](Object_Checksum_Agreement_Tests.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 23 (82%)
- INFERRED: 5 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*