# MockS3Backend Listing and Upload Stubs

> 27 nodes · cohesion 0.11

## Key Concepts

- **MockS3Backend** (57 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketNotificationConfigurationOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsV2Input** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsV2Output** (5 connections)
- **BktcaptureHead()** (5 connections) — `internal/proxy/handlers/bucket/operations_coverage_test.go`
- **.GetBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.HeadBucket()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPart()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketNotificationConfigurationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.UploadPartInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.UploadPartOutput** (4 connections)
- **.GetBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.HeadBucket()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.UploadPart()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.HeadBucket()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.UploadPart()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.HeadBucket()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- *... and 2 more nodes in this community*

## Relationships

- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (25 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (11 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (8 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (5 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (4 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (2 shared connections)
- [Bucket Notification Documents](Bucket_Notification_Documents.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [MockS3Backend PutBucketLogging Stub](MockS3Backend_PutBucketLogging_Stub.md) (1 shared connections)
- [MockS3Backend GetBucketVersioning Stub](MockS3Backend_GetBucketVersioning_Stub.md) (1 shared connections)
- [MockS3Backend PutBucketVersioning Stub](MockS3Backend_PutBucketVersioning_Stub.md) (1 shared connections)
- [MockS3Backend GetBucketTagging Stub](MockS3Backend_GetBucketTagging_Stub.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/operations_coverage_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 126 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*