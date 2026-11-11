# Chunked Encoding Tests

> 52 nodes · cohesion 0.07

## Key Concepts

- **EnsureMinIOAndProxyAvailable()** (122 connections) — `test/integration/minio_test_helper.go`
- **TLSHTTPClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **SignHTTPRequestForS3WithCredentials()** (13 connections) — `test/integration/s3_signing_helper.go`
- **subrefPutObject()** (10 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **downloadObjectSimple()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestChunkedEncodingCornerCases()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestPureHTTPChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestRealChunkedEncodingWithoutSDK()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **uploadWithChunkedEncodingPureHTTP()** (8 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestBackendErrorsKeepTheirStatusAndCode()** (8 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestLstListObjectsMissingBucket()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **subrefDigest()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefLegitimateParametersStillWork()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefMalformedPartNumberDoesNotOverwriteTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefSemicolonInTheQueryIsRefused()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefUnroutedSubResourcesDoNotDestroyTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestTbSlowDownloadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **TestTbSlowUploadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **TestVbRefusedCopiesLeaveNothingBehind()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestAWSV4SigningHelper()** (8 connections) — `test/integration/s3_signing_test.go`
- **uploadWithRealChunkedEncoding()** (7 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **apiCodeOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **httpStatusOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **hdrSignedPutQuery()** (7 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **subrefRawWithBody()** (7 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- *... and 27 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (49 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (45 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (35 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (33 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (16 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (15 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (13 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (11 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (11 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (10 shared connections)
- [S3 Methods: Range Conformance Test](S3_Methods-_Range_Conformance_Test.md) (7 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (6 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/360-degree-variants/range_read_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/bucket_subresource_documents_test.go`
- `test/integration/s3-methods/conditional_requests_test.go`
- `test/integration/s3-methods/error_mapping_test.go`
- `test/integration/s3-methods/listobjects_conformance_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`
- `test/integration/s3-methods/object_metadata_consistency_test.go`
- `test/integration/s3-methods/object_subresource_passthrough_test.go`
- `test/integration/s3-methods/object_subresource_refusal_test.go`
- `test/integration/s3-methods/transfer_budget_test.go`
- `test/integration/s3-methods/versioned_bucket_test.go`
- `test/integration/s3_signing_helper.go`
- `test/integration/s3_signing_test.go`

## Audit Trail

- EXTRACTED: 329 (92%)
- INFERRED: 29 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*