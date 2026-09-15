# MockS3Backend Bucket Operations

> 55 nodes · cohesion 0.07

## Key Concepts

- **context.Context** (399 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput** (5 connections)
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucket()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketLifecycleConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketLogging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLifecycleConfigurationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLifecycleConfigurationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketReplicationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketReplicationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketTaggingInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketTaggingOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAclInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAclOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketLoggingInput** (4 connections)
- *... and 30 more nodes in this community*

## Relationships

- [Helpers](Helpers.md) (132 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (38 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (34 shared connections)
- [MockS3Backend Attribute Operations](MockS3Backend_Attribute_Operations.md) (23 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (21 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (19 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (16 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (8 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (7 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (7 shared connections)
- [Shutdown](Shutdown.md) (6 shared connections)
- [Backend](Backend.md) (6 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 508 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*