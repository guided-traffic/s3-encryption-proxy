# Streaming Integration Helpers

> 70 nodes · cohesion 0.06

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.Client** (93 connections)
- **comprehensive_singlepart_test.go** (40 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **CreateProxyClient()** (19 connections) — `test/integration/minio_test_helper.go`
- **TestComprehensiveMultipartUpload()** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestComprehensiveSinglePartUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **SetupTestBucket()** (13 connections) — `test/integration/minio_test_helper.go`
- **TestSinglePartUploadCornerCases()** (12 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **PurgeBucket()** (12 connections) — `test/integration/minio_test_helper.go`
- **TestMultipartUploadCorruption()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestStreamingMultipartUpload()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadVsMultipart()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifyDataIntegrityStreaming()** (9 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestDEKCacheReuploadRegression()** (8 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **createProxyClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **purgePerformanceBucket()** (8 connections) — `test/integration/performance-test/performance_test.go`
- **TestPerformanceComparison()** (8 connections) — `test/integration/performance-test/performance_test.go`
- **uploadLargeFileStreaming()** (7 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **cleanupSinglePartTestFile()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifySinglePartFileInMinIO()** (7 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **AssertDataIsNotEncrypted()** (7 connections) — `test/integration/encryption_validation_helper.go`
- **TestStreamingPerformance()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **StreamingReader** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadLargeFile()** (6 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- *... and 45 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (71 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (44 shared connections)
- [Tampering Harness](Tampering_Harness.md) (27 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (21 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (16 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (8 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (7 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (6 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (6 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (5 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (5 shared connections)
- [Conformance Suite](Conformance_Suite.md) (4 shared connections)

## Source Files

- `docs/developer/testing.md`
- `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/performance_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`

## Audit Trail

- EXTRACTED: 383 (97%)
- INFERRED: 13 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*