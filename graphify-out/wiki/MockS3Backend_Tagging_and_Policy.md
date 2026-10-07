# MockS3Backend Tagging and Policy

> 56 nodes · cohesion 0.07

## Key Concepts

- **context.Context** (401 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutObjectInput** (8 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsOutput** (6 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutObjectOutput** (5 connections)
- **shutdownTail** (5 connections) — `cmd/s3-encryption-proxy/main.go`
- **.CreateBucket()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketLocation()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectLegalHold()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectTorrent()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListBuckets()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketPolicy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateBucketInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateBucketOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketTaggingInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketTaggingOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectLegalHoldInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectLegalHoldOutput** (4 connections)
- *... and 31 more nodes in this community*

## Relationships

- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (44 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (37 shared connections)
- [MockS3Backend Abort and ACL Stubs](MockS3Backend_Abort_and_ACL_Stubs.md) (25 shared connections)
- [MockS3Backend Listing and Upload Stubs](MockS3Backend_Listing_and_Upload_Stubs.md) (25 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (22 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (19 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (7 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (7 shared connections)
- [E2E Harness Backend Client](E2E_Harness_Backend_Client.md) (6 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (6 shared connections)
- [Segment Tamper](Segment_Tamper.md) (5 shared connections)
- [Exec](Exec.md) (5 shared connections)

## Source Files

- `cmd/s3-encryption-proxy/main.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 521 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*