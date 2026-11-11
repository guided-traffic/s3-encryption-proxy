# Delete and Checksum Integration

> 41 nodes · cohesion 0.16

## Key Concepts

- **RandomString()** (80 connections) — `test/integration/minio_test_helper.go`
- **upload_checksum_test.go** (47 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **NewTestContext()** (28 connections) — `test/integration/minio_test_helper.go`
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
- **vbNewVersionedBucket()** (10 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestCkChunkedWithoutADeclaredLengthAndNoChecksum()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkCompleteMultipartObjectChecksumIsNotCheckedAgainstTheDocument()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkDeclaredTrailerThatNeverArrivesIsRefused()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkDeleteObjectsRequiresADigest()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestCkUploadPartWithAWrongDigest()** (9 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **ckPayloadSHA()** (8 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- **TestVbClientDrivenMultipartEntityHeaders()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbDeleteMarkerAndVersionDelete()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbMultipartUploadLeavesExactlyOneVersion()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbVersionIdAddressesTheVersionItNames()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **ckChunkedHeaders()** (7 connections) — `test/integration/s3-methods/upload_checksum_test.go`
- *... and 16 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (41 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (33 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (28 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (12 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (9 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (8 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (8 shared connections)
- [S3 Methods: Range Conformance Test](S3_Methods-_Range_Conformance_Test.md) (7 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (4 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (3 shared connections)
- [Tampering Harness](Tampering_Harness.md) (3 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/delete_object_test.go`
- `test/integration/s3-methods/list_buckets_test.go`
- `test/integration/s3-methods/passthrough_operations_test.go`
- `test/integration/s3-methods/upload_checksum_test.go`
- `test/integration/s3-methods/versioned_bucket_test.go`

## Audit Trail

- EXTRACTED: 295 (98%)
- INFERRED: 5 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*