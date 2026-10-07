# MockS3Backend Object Operations

> 51 nodes · cohesion 0.06

## Key Concepts

- **MockS3Backend** (64 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **MockS3Backend** (64 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.SelectObjectContent()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketNotificationConfigurationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketNotificationConfigurationOutput** (4 connections)
- **.PutBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketNotificationConfiguration()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- *... and 26 more nodes in this community*

## Relationships

- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (44 shared connections)
- [MockS3Backend Listing and Upload Stubs](MockS3Backend_Listing_and_Upload_Stubs.md) (11 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (9 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (8 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (2 shared connections)
- [MockS3Backend PutBucketLogging Stub](MockS3Backend_PutBucketLogging_Stub.md) (2 shared connections)
- [MockS3Backend GetBucketVersioning Stub](MockS3Backend_GetBucketVersioning_Stub.md) (2 shared connections)
- [MockS3Backend PutBucketVersioning Stub](MockS3Backend_PutBucketVersioning_Stub.md) (2 shared connections)
- [MockS3Backend GetBucketTagging Stub](MockS3Backend_GetBucketTagging_Stub.md) (2 shared connections)
- [MockS3Backend PutBucketTagging Stub](MockS3Backend_PutBucketTagging_Stub.md) (2 shared connections)
- [MockS3Backend GetBucketLifecycleConfiguration Stub](MockS3Backend_GetBucketLifecycleConfiguration_Stub.md) (2 shared connections)
- [MockS3Backend PutBucketLifecycleConfiguration Stub](MockS3Backend_PutBucketLifecycleConfiguration_Stub.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 210 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*