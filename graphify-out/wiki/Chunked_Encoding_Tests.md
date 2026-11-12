# Chunked Encoding Tests

> 54 nodes · cohesion 0.09

## Key Concepts

- **EnsureMinIOAndProxyAvailable()** (122 connections) — `test/integration/minio_test_helper.go`
- **NewTestContextWithTimeout()** (93 connections) — `test/integration/minio_test_helper.go`
- **object_subresource_refusal_test.go** (27 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TLSHTTPClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **SignHTTPRequestForS3WithCredentials()** (13 connections) — `test/integration/s3_signing_helper.go`
- **subrefPutObject()** (10 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **vbNewVersionedBucket()** (10 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestBackendErrorsKeepTheirStatusAndCode()** (8 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestLstListObjectsMissingBucket()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **subrefDigest()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefLegitimateParametersStillWork()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefMalformedPartNumberDoesNotOverwriteTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefSemicolonInTheQueryIsRefused()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestSubrefUnroutedSubResourcesDoNotDestroyTheObject()** (8 connections) — `test/integration/s3-methods/object_subresource_refusal_test.go`
- **TestTbSlowDownloadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **TestTbSlowUploadIsNotCutByAWallClock()** (8 connections) — `test/integration/s3-methods/transfer_budget_test.go`
- **TestVbClientDrivenMultipartEntityHeaders()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbDeleteMarkerAndVersionDelete()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbMultipartUploadLeavesExactlyOneVersion()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbRefusedCopiesLeaveNothingBehind()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbVersionIdAddressesTheVersionItNames()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestAWSV4SigningHelper()** (8 connections) — `test/integration/s3_signing_test.go`
- **uploadWithRealChunkedEncoding()** (7 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **apiCodeOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **httpStatusOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- *... and 29 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (50 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (45 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (33 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (30 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (24 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (22 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (21 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (21 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (19 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (13 shared connections)
- [S3 Methods: Range Conformance Test](S3_Methods-_Range_Conformance_Test.md) (8 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (6 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/360-degree-variants/range_read_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/bucket_subresource_documents_test.go`
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

- EXTRACTED: 407 (92%)
- INFERRED: 36 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*