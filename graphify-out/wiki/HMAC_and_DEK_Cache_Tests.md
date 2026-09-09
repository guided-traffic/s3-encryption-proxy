# HMAC and DEK Cache Tests

> 18 nodes · cohesion 0.24

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.Client** (78 connections)
- **SetupTestBucket()** (14 connections) — `test/integration/minio_test_helper.go`
- **TestHMACValidation()** (12 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **TestDEKCacheReuploadRegression()** (7 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **hmac_validation_test.go** (7 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **dek_cache_reupload_test.go** (6 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **runReuploadCycle()** (6 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **requireDownloadHashEquals()** (5 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **testInvalidHMACDownload()** (5 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **testManipulatedHMACMetadata()** (5 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **testRangeRequestWithHMAC()** (5 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **testSinglePartCTRWithHMAC()** (5 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **testSmallFileWithHMAC()** (5 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **testValidHMACDownload()** (5 connections) — `test/integration/360-degree-variants/hmac_validation_test.go`
- **ClearBucketObjects()** (5 connections) — `test/integration/minio_test_helper.go`
- **putMultipartTwoParts()** (4 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **putSinglePart()** (4 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **makePattern()** (2 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (14 shared connections)
- [Comprehensive Multipart Tests](Comprehensive_Multipart_Tests.md) (12 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (12 shared connections)
- [Single-Part Throughput Tests](Single-Part_Throughput_Tests.md) (10 shared connections)
- [MinIO Integration Test Helper](MinIO_Integration_Test_Helper.md) (9 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (7 shared connections)
- [CTR Single-Part Tests](CTR_Single-Part_Tests.md) (6 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (5 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (5 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (5 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (4 shared connections)
- [Throughput Benchmark Suite](Throughput_Benchmark_Suite.md) (4 shared connections)

## Source Files

- `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `test/integration/360-degree-variants/hmac_validation_test.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 143 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*