# S3 Backend Interface Types

> 64 nodes · cohesion 0.06

## Key Concepts

- **context.Context** (425 connections)
- **NoneProvider** (6 connections) — `pkg/encryption/keyencryption/none.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsOutput** (5 connections)
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucket()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketCors()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListBuckets()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListParts()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketLogging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketTaggingInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketTaggingOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListPartsInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListPartsOutput** (4 connections)
- *... and 39 more nodes in this community*

## Relationships

- [S3 Backend Mock](S3_Backend_Mock.md) (82 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (32 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (24 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (12 shared connections)
- [Comprehensive Multipart Tests](Comprehensive_Multipart_Tests.md) (9 shared connections)
- [Single-Part Throughput Tests](Single-Part_Throughput_Tests.md) (7 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (7 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (6 shared connections)
- [AES-GCM Data Encryptor](AES-GCM_Data_Encryptor.md) (6 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (6 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (5 shared connections)
- [Range Request Conformance Tests](Range_Request_Conformance_Tests.md) (5 shared connections)

## Source Files

- `internal/orchestration/manager.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `pkg/encryption/keyencryption/none.go`

## Audit Trail

- EXTRACTED: 544 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*