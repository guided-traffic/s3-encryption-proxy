# Ranged Read and Passthrough Tests

> 33 nodes · cohesion 0.22

## Key Concepts

- **EnsureMinIOAndProxyAvailable()** (122 connections) — `test/integration/minio_test_helper.go`
- **NewTestContext()** (27 connections) — `test/integration/minio_test_helper.go`
- **upload_checksum_test.go** (22 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckSend()** (19 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckPayload()** (13 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckEncode()** (11 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkChunkedTrailerOnBothPutRoutes()** (11 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkChunkedWithoutADeclaredLength()** (10 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkCompleteMultipartOverAWSChunked()** (10 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkDeleteObjectsOverAWSChunked()** (10 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkPlainPutHeaderDigests()** (10 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkPlainPutWithAWrongContentMD5IsRefused()** (10 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkUnimplementedAlgorithmIsRefused()** (10 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkChunkedWithoutADeclaredLengthAndNoChecksum()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkCompleteMultipartObjectChecksumIsNotCheckedAgainstTheDocument()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkDeclaredTrailerThatNeverArrivesIsRefused()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkDeleteObjectsRequiresADigest()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkUploadPartWithAWrongDigest()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckPayloadSHA()** (8 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckChunkedHeaders()** (7 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckFramed()** (7 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckRequireAbsent()** (7 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkCompleteMultipartDoesNotUnescapeIntoMarkup()** (7 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestRangeReadErrors()** (5 connections) — `test/integration/360-degree-variants/range_read_test.go`
- **TestRangeReadsOnEncryptedObjects()** (4 connections) — `test/integration/360-degree-variants/range_read_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (29 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (22 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (17 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (17 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (12 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (11 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (10 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (10 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (8 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (7 shared connections)
- [Range Conformance](Range_Conformance.md) (5 shared connections)
- [Segment Tamper](Segment_Tamper.md) (3 shared connections)

## Source Files

- `test/integration/360-degree-variants/range_read_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/passthrough_operations_test.go`
- `test/integration/s3-methods/upload_checksum_test.go`

## Audit Trail

- EXTRACTED: 269 (97%)
- INFERRED: 7 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*