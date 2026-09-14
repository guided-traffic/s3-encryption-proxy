# Chunked Upload Tests

> 23 nodes · cohesion 0.18

## Key Concepts

- **comprehensive_chunked_test.go** (16 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TLSHTTPClient()** (13 connections) — `test/integration/minio_test_helper.go`
- **TestChunkedUploadDecoding()** (10 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestComprehensiveChunkedEncoding()** (9 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **downloadObjectSimple()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestChunkedEncodingCornerCases()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestPureHTTPChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestRealChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **uploadWithChunkedEncodingPureHTTP()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **SignHTTPRequestForS3WithCredentials()** (8 connections) — `test/integration/s3_signing_helper.go`
- **uploadWithRealChunkedEncoding()** (7 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestAWSV4SigningHelper()** (7 connections) — `test/integration/s3_signing_test.go`
- **verifyDataMatches()** (6 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **parseChunkedDataManually()** (4 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestChunkedReaderUnit()** (4 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestUnauthenticatedEndpoints()** (4 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **ChunkedReader** (3 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **NewChunkedReader()** (3 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **createAWSChunkedDataMultiChunk()** (2 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **createAWSChunkedEncodedBody()** (2 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **generateTestData()** (2 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **.Read()** (1 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **s3_signing_test.go** (1 connections) — `test/integration/s3_signing_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (13 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (10 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (9 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (7 shared connections)
- [Mock Backend Helpers](Mock_Backend_Helpers.md) (3 shared connections)
- [MinIO Test Helper](MinIO_Test_Helper.md) (2 shared connections)
- [SigV4 Signing Helper](SigV4_Signing_Helper.md) (2 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (1 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (1 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (1 shared connections)
- [Range Conformance Tests](Range_Conformance_Tests.md) (1 shared connections)
- [Performance Harness](Performance_Harness.md) (1 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3_signing_helper.go`
- `test/integration/s3_signing_test.go`

## Audit Trail

- EXTRACTED: 90 (93%)
- INFERRED: 7 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*