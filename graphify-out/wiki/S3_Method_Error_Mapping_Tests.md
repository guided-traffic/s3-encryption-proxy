# S3 Method Error Mapping Tests

> 41 nodes · cohesion 0.13

## Key Concepts

- **RandomString()** (80 connections) — `test/integration/minio_test_helper.go`
- **net/http.Header** (37 connections)
- **object_headers_conformance_test.go** (20 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrNewDirectBucket()** (14 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrETagIsPresentAndStableAcrossRepeatedHeads()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrHeadReturnsTheSameHeaderSetAsGet()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrGetHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrHeadHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrUserMetadataRoundTripsLikeTheBackend()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEncryptionMetadataIsNeverVisibleToTheClient()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEntityHeadersSurvivePutGetAndHead()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrPutWithEntityHeaders()** (9 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestBackendErrorsKeepTheirStatusAndCode()** (8 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestLstListObjectsMissingBucket()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestHdrStorageHeadersReachTheBackend()** (8 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestVbRefusedCopiesLeaveNothingBehind()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **apiCodeOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **httpStatusOf()** (7 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestHdrSequentialWhitespaceInASignedHeaderIsAccepted()** (7 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **s3-methods/error_mapping_test.go** (6 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **HdrObjectHeaderNames()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestSubpassRetentionAndLegalHoldRoundTrip()** (6 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **ObjIntfailingWriter** (5 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **TestConditionalRequestErrors()** (5 connections) — `test/integration/s3-methods/error_mapping_test.go`
- **TestListBucketsOperation()** (5 connections) — `test/integration/s3-methods/list_buckets_test.go`
- *... and 16 more nodes in this community*

## Relationships

- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (29 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (19 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (15 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (14 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (12 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (9 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (7 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (7 shared connections)
- [Range Conformance](Range_Conformance.md) (6 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (5 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (4 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (4 shared connections)

## Source Files

- `internal/proxy/handlers/object/integrity_report_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/delete_object_test.go`
- `test/integration/s3-methods/error_mapping_test.go`
- `test/integration/s3-methods/list_buckets_test.go`
- `test/integration/s3-methods/listobjects_conformance_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`
- `test/integration/s3-methods/object_subresource_passthrough_test.go`
- `test/integration/s3-methods/versioned_bucket_test.go`

## Audit Trail

- EXTRACTED: 259 (97%)
- INFERRED: 9 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*