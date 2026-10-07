# Ranged Read and Passthrough Tests

> 35 nodes · cohesion 0.21

## Key Concepts

- **RandomString()** (65 connections) — `test/integration/minio_test_helper.go`
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
- **TestListBucketsOperation()** (5 connections) — `test/integration/s3-methods/list_buckets_test.go`
- **TestDeleteObjectFunctionality()** (4 connections) — `test/integration/s3-methods/delete_object_test.go`
- *... and 10 more nodes in this community*

## Relationships

- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (23 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (22 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (11 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (10 shared connections)
- [Range Conformance](Range_Conformance.md) (6 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (5 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (4 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (4 shared connections)
- [Conditional Requests](Conditional_Requests.md) (3 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (3 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (3 shared connections)
- [Shutdown](Shutdown.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/delete_object_test.go`
- `test/integration/s3-methods/list_buckets_test.go`
- `test/integration/s3-methods/passthrough_operations_test.go`
- `test/integration/s3-methods/upload_checksum_test.go`

## Audit Trail

- EXTRACTED: 217 (99%)
- INFERRED: 2 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*