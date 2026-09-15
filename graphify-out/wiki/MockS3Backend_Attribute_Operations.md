# MockS3Backend Attribute Operations

> 24 nodes · cohesion 0.12

## Key Concepts

- **MockS3Backend** (57 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketVersioning()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectRetention()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketVersioningInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketVersioningOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectRetentionInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectRetentionOutput** (4 connections)
- **.GetBucketVersioning()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetObjectRetention()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketVersioning()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObjectRetention()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketVersioning()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectRetention()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesInput** (3 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesOutput** (3 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.UploadPartCopyInput** (3 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.UploadPartCopyOutput** (3 connections)
- **object/test_helpers_test.go** (2 connections) — `internal/proxy/handlers/object/test_helpers_test.go`

## Relationships

- [Helpers](Helpers.md) (33 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (23 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (9 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (6 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (4 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 110 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*