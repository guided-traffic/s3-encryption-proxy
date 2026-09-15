# MockS3Backend Object Operations

> 41 nodes · cohesion 0.07

## Key Concepts

- **MockS3Backend** (64 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **MockS3Backend** (64 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketCors()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.SelectObjectContent()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsOutput** (4 connections)
- **.DeleteBucketCors()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteBucketCors()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.DeleteBucketCors()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketWebsite()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutObjectAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.SelectObjectContent()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectInput** (2 connections)
- *... and 16 more nodes in this community*

## Relationships

- [Helpers](Helpers.md) (66 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (38 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (9 shared connections)
- [MockS3Backend Attribute Operations](MockS3Backend_Attribute_Operations.md) (9 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (8 shared connections)
- [Bucket Location and Logging Tests](Bucket_Location_and_Logging_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 190 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*