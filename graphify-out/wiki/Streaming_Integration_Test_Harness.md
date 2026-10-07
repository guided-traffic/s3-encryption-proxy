# Streaming Integration Test Harness

> 71 nodes · cohesion 0.07

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.Client** (91 connections)
- **minio_test_helper.go** (35 connections) — `test/integration/minio_test_helper.go`
- **comprehensive_singlepart_test.go** (15 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **comprehensive_multipart_test.go** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestComprehensiveMultipartUpload()** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestComprehensiveSinglePartUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **SetupTestBucket()** (13 connections) — `test/integration/minio_test_helper.go`
- **TestSinglePartUploadCornerCases()** (12 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **PurgeBucket()** (11 connections) — `test/integration/minio_test_helper.go`
- **TestMultipartUploadCorruption()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestStreamingMultipartUpload()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadVsMultipart()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifyDataIntegrityStreaming()** (9 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **createMinIOClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **createProxyClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **uploadLargeFileStreaming()** (7 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **cleanupSinglePartTestFile()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartFileInMinIO()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestDEKCacheReuploadRegression()** (7 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **AssertDataIsNotEncrypted()** (7 connections) — `test/integration/encryption_validation_helper.go`
- **NewS3Client()** (7 connections) — `test/integration/minio_test_helper.go`
- **StreamingReader** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadLargeFile()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- *... and 46 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (38 shared connections)
- [Encryption Mode Proxy Instances](Encryption_Mode_Proxy_Instances.md) (23 shared connections)
- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (23 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (22 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (7 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (7 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (7 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (6 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (5 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (5 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (5 shared connections)
- [Encryption Validation Helper](Encryption_Validation_Helper.md) (5 shared connections)

## Source Files

- `test/integration/180-degree-variants/large_multipart_upload_test.go`
- `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 346 (97%)
- INFERRED: 10 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*