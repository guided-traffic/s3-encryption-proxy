# Range Read Integration Tests

> 32 nodes · cohesion 0.16

## Key Concepts

- **EnsureMinIOAndProxyAvailable()** (84 connections) — `test/integration/minio_test_helper.go`
- **NewTestContextWithTimeout()** (67 connections) — `test/integration/minio_test_helper.go`
- **TestContext** (16 connections) — `test/integration/minio_test_helper.go`
- **object_subresource_refusal_test.go** (9 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestBackendErrorsKeepTheirStatusAndCode()** (8 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestLstListObjectsMissingBucket()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestHdrSequentialWhitespaceInASignedHeaderBreaksTheProxySignature()** (8 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrStorageHeadersAreAcceptedAndSilentlyDropped()** (8 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **subrefPutObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefLegitimateParametersStillWork()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefMalformedPartNumberDoesNotOverwriteTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefUnroutedSubResourcesDoNotDestroyTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **httpStatusOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestSubrefPresignedGetIsNotRefusedAsASubResource()** (7 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **s3-methods/error_mapping_test.go** (6 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **apiCodeOf()** (6 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **subrefDigest()** (6 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **subrefRawWithBody()** (6 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestRangeReadErrors()** (5 connections) — `test/integration/360-degree-variants/range_read_test.go`
- **TestConditionalRequestErrors()** (5 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestAWSChunkedIsNotStoredAsContentEncoding()** (5 connections) — `test/integration/s3-methods/object_metadata_consistency_test.go`
- **subrefRaw()** (5 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestRangeReadsOnEncryptedObjects()** (4 connections) — `test/integration/360-degree-variants/range_read_test.go`
- **errorsAs()** (4 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestObjectSizeIsConsistentAcrossHeadGetAndList()** (4 connections) — `test/integration/s3-methods/object_metadata_consistency_test.go`
- *... and 7 more nodes in this community*

## Relationships

- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (31 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (25 shared connections)
- [Multipart Conformance Tests](Multipart_Conformance_Tests.md) (23 shared connections)
- [DeleteObjects Batch Tests](DeleteObjects_Batch_Tests.md) (20 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (14 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (10 shared connections)
- [MinIO Integration Test Helper](MinIO_Integration_Test_Helper.md) (8 shared connections)
- [ListObjects Conformance Tests](ListObjects_Conformance_Tests.md) (7 shared connections)
- [Range Request Conformance Tests](Range_Request_Conformance_Tests.md) (7 shared connections)
- [Throughput Benchmark Suite](Throughput_Benchmark_Suite.md) (7 shared connections)
- [Conditional Request Tests](Conditional_Request_Tests.md) (4 shared connections)
- [Comprehensive Multipart Tests](Comprehensive_Multipart_Tests.md) (3 shared connections)

## Source Files

- `test/integration/360-degree-variants/range_read_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/error_mapping_test.go`
- `test/integration/s3-methods/listobjects_conformance_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`
- `test/integration/s3-methods/object_metadata_consistency_test.go`
- `test/integration/s3-methods/object_subresource_refusal_test.go`

## Audit Trail

- EXTRACTED: 236 (94%)
- INFERRED: 15 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*