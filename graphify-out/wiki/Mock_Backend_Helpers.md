# Mock Backend Helpers

> 48 nodes · cohesion 0.08

## Key Concepts

- **context.Context** (341 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketOutput** (5 connections)
- **.CompleteMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketLocation()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketLogging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.HeadBucket()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketPolicy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketVersioning()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketReplicationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketReplicationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLoggingInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLoggingOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketPolicyInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketPolicyOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketVersioningInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketVersioningOutput** (4 connections)
- **.CompleteMultipartUpload()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteBucketReplication()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- *... and 23 more nodes in this community*

## Relationships

- [Handler Test Helpers](Handler_Test_Helpers.md) (50 shared connections)
- [Handler Fixture Helpers](Handler_Fixture_Helpers.md) (34 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (32 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (14 shared connections)
- [Performance Harness](Performance_Harness.md) (10 shared connections)
- [360-Degree Multipart Tests](360-Degree_Multipart_Tests.md) (7 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (7 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (6 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (6 shared connections)
- [Segment Tamper Tests](Segment_Tamper_Tests.md) (5 shared connections)
- [Range Conformance Tests](Range_Conformance_Tests.md) (5 shared connections)
- [Multipart Conformance Tests](Multipart_Conformance_Tests.md) (5 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 438 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*