# AWS-Chunked Reader Tests

> 50 nodes · cohesion 0.10

## Key Concepts

- **EnsureMinIOAndProxyAvailable()** (109 connections) — `test/integration/minio_test_helper.go`
- **TLSHTTPClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **CreateProxyClient()** (19 connections) — `test/integration/minio_test_helper.go`
- **comprehensive_chunked_test.go** (16 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **SignHTTPRequestForS3WithCredentials()** (13 connections) — `test/integration/s3_signing_helper.go`
- **object_subresource_refusal_test.go** (11 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestChunkedUploadDecoding()** (10 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **subrefPutObject()** (10 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestComprehensiveChunkedEncoding()** (9 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **downloadObjectSimple()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestChunkedEncodingCornerCases()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestPureHTTPChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestRealChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **uploadWithChunkedEncodingPureHTTP()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **subrefDigest()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefLegitimateParametersStillWork()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefMalformedPartNumberDoesNotOverwriteTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefSemicolonInTheQueryIsRefused()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefUnroutedSubResourcesDoNotDestroyTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestTbSlowDownloadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **TestTbSlowUploadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **SignHTTPRequestForS3()** (8 connections) — `test/integration/s3_signing_helper.go`
- **uploadWithRealChunkedEncoding()** (7 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **subrefRawWithBody()** (7 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefPresignedGetIsNotRefusedAsASubResource()** (7 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- *... and 25 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (30 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (28 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (23 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (23 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (13 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (11 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (10 shared connections)
- [Encryption Mode Proxy Instances](Encryption_Mode_Proxy_Instances.md) (9 shared connections)
- [Range Conformance](Range_Conformance.md) (7 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (6 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (5 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (5 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/bucket_subresource_documents_test.go`
- `test/integration/s3-methods/object_subresource_refusal_test.go`
- `test/integration/s3-methods/transfer_budget_test.go`
- `test/integration/s3_signing_helper.go`
- `test/integration/s3_signing_test.go`

## Audit Trail

- EXTRACTED: 297 (94%)
- INFERRED: 18 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*