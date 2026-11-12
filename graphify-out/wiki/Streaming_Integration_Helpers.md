# Streaming Integration Helpers

> 82 nodes · cohesion 0.05

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.Client** (93 connections)
- **minio_test_helper.go** (92 connections) — `test/integration/minio_test_helper.go`
- **CreateProxyClient()** (19 connections) — `test/integration/minio_test_helper.go`
- **TestComprehensiveMultipartUpload()** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestComprehensiveSinglePartUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **SetupTestBucket()** (13 connections) — `test/integration/minio_test_helper.go`
- **TestSinglePartUploadCornerCases()** (12 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **PurgeBucket()** (12 connections) — `test/integration/minio_test_helper.go`
- **TestComprehensiveChunkedEncoding()** (10 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestMultipartUploadCorruption()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestStreamingMultipartUpload()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadVsMultipart()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **uploadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **verifyDataIntegrityStreaming()** (9 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadObjectSimple()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestChunkedEncodingCornerCases()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestPureHTTPChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestRealChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **uploadWithChunkedEncodingPureHTTP()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestDEKCacheReuploadRegression()** (8 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **createMinIOClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **createProxyClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **purgePerformanceBucket()** (8 connections) — `test/integration/performance-test/performance_test.go`
- **TestPerformanceComparison()** (8 connections) — `test/integration/performance-test/performance_test.go`
- *... and 57 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (97 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (50 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (32 shared connections)
- [Misc (15)](Misc_15.md) (31 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (30 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (10 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (8 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (7 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (6 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (6 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (4 shared connections)
- [Harness: Backend](Harness-_Backend.md) (4 shared connections)

## Source Files

- `docs/developer/testing.md`
- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/performance_test.go`

## Audit Trail

- EXTRACTED: 483 (97%)
- INFERRED: 16 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*