# AWS Chunked Body Tests

> 23 nodes · cohesion 0.20

## Key Concepts

- **CreateProxyClient()** (22 connections) — `test/integration/minio_test_helper.go`
- **comprehensive_chunked_test.go** (16 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TLSHTTPClient()** (12 connections) — `test/integration/minio_test_helper.go`
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
- **ChunkedReader** (3 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **NewChunkedReader()** (3 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **createAWSChunkedDataMultiChunk()** (2 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **createAWSChunkedEncodedBody()** (2 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **generateTestData()** (2 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **.Read()** (1 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **s3_signing_test.go** (1 connections) — `test/integration/s3_signing_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (13 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (10 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (8 shared connections)
- [MinIO Integration Test Helper](MinIO_Integration_Test_Helper.md) (5 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (4 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (3 shared connections)
- [Comprehensive Multipart Tests](Comprehensive_Multipart_Tests.md) (3 shared connections)
- [CTR Single-Part Tests](CTR_Single-Part_Tests.md) (3 shared connections)
- [Single-Part Throughput Tests](Single-Part_Throughput_Tests.md) (3 shared connections)
- [SigV4 Test Signer](SigV4_Test_Signer.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (1 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3_signing_helper.go`
- `test/integration/s3_signing_test.go`

## Audit Trail

- EXTRACTED: 104 (95%)
- INFERRED: 5 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*