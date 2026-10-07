# MockS3Backend Abort and ACL Stubs

> 25 nodes · cohesion 0.12

## Key Concepts

- **MockS3Backend** (55 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketAclOutput** (5 connections)
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketReplicationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketReplicationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketAclInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAclInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAclOutput** (4 connections)
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteBucketReplication()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.DeleteBucketReplication()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.DeleteBucketReplication()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (25 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (9 shared connections)
- [MockS3Backend Listing and Upload Stubs](MockS3Backend_Listing_and_Upload_Stubs.md) (8 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (4 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)
- [Subresource Documents](Subresource_Documents.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [MockS3Backend DeleteBucket Stub](MockS3Backend_DeleteBucket_Stub.md) (1 shared connections)
- [MockS3Backend GetObjectTagging Stub](MockS3Backend_GetObjectTagging_Stub.md) (1 shared connections)
- [MockS3Backend PutObjectTagging Stub](MockS3Backend_PutObjectTagging_Stub.md) (1 shared connections)
- [MockS3Backend DeleteObjectTagging Stub](MockS3Backend_DeleteObjectTagging_Stub.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 117 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*