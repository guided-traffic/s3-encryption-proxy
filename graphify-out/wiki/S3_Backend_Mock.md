# S3 Backend Mock

> 46 nodes · cohesion 0.07

## Key Concepts

- **MockS3Backend** (64 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **MockS3Backend** (64 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.DeleteBucketCors()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.DeleteBucketCors()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsOutput** (5 connections)
- **.DeleteBucketCors()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteBucketCors()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.DeleteBucketCors()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.SelectObjectContent()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketWebsite()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- *... and 21 more nodes in this community*

## Relationships

- [Misc (15)](Misc_15.md) (32 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (7 shared connections)
- [Misc (12)](Misc_12.md) (6 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [PutBucketLogging Test Stubs](PutBucketLogging_Test_Stubs.md) (2 shared connections)
- [GetBucketVersioning Test Stubs](GetBucketVersioning_Test_Stubs.md) (2 shared connections)
- [Misc (40)](Misc_40.md) (2 shared connections)
- [Misc (11)](Misc_11.md) (2 shared connections)
- [Misc (21)](Misc_21.md) (2 shared connections)
- [Misc (38)](Misc_38.md) (2 shared connections)
- [Misc (37)](Misc_37.md) (2 shared connections)
- [Misc (8)](Misc_8.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 204 (98%)
- INFERRED: 4 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*