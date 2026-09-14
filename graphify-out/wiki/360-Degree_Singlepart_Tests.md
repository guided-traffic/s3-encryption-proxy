# 360-Degree Singlepart Tests

> 30 nodes · cohesion 0.18

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.Client** (78 connections)
- **CreateProxyClient()** (19 connections) — `test/integration/minio_test_helper.go`
- **comprehensive_singlepart_test.go** (17 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestComprehensiveSinglePartUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **SetupTestBucket()** (13 connections) — `test/integration/minio_test_helper.go`
- **TestSinglePartUploadCornerCases()** (12 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **downloadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadVsMultipart()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **cleanupSinglePartTestFile()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartFileInMinIO()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestDEKCacheReuploadRegression()** (7 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **verifyMinIODirectAccess()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **calculateThroughput()** (6 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **downloadSinglePartFileWithMetrics()** (6 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFileWithMetrics()** (6 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySegmentedObjectMetadata()** (6 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **dek_cache_reupload_test.go** (6 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **runReuploadCycle()** (6 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **generateSinglePartTestData()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartDataIntegrity()** (5 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **requireDownloadHashEquals()** (5 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **ClearBucketObjects()** (5 connections) — `test/integration/minio_test_helper.go`
- **PerformanceMetrics** (4 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **segStoredSize()** (4 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- *... and 5 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (20 shared connections)
- [360-Degree Multipart Tests](360-Degree_Multipart_Tests.md) (17 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (14 shared connections)
- [MinIO Test Helper](MinIO_Test_Helper.md) (10 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (8 shared connections)
- [Chunked Upload Tests](Chunked_Upload_Tests.md) (7 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (6 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (6 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (5 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (5 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (5 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (4 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 205 (98%)
- INFERRED: 4 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*