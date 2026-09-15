# Streaming Upload and Sealed Checksum

> 25 nodes · cohesion 0.17

## Key Concepts

- **TestContext** (23 connections) — `test/integration/minio_test_helper.go`
- **vbNewVersionedBucket()** (10 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestCksSuffixRangeLargerThanTheObject()** (9 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **versioned_bucket_test.go** (9 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **sealed_checksum_test.go** (8 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestCksEveryWritePathSealsTheSameChecksum()** (8 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestCksPartNumberTenThousandIsRefused()** (8 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestVbClientDrivenMultipartEntityHeaders()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbDeleteMarkerAndVersionDelete()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbMultipartUploadLeavesExactlyOneVersion()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbVersionIdAddressesTheVersionItNames()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **CksAssertServedChecksum()** (7 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **vbPut()** (6 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestStreamingVsStandardPerformance()** (5 connections) — `test/integration/performance-test/streaming_test.go`
- **CksStoredLength()** (5 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **vbSHA()** (5 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **streaming_test.go** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **downloadAndVerifyWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **performMultipartUploadWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **TestStreamingMultipartUpload()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **CksDelete()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksPayload()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **.EnsureTestBucket()** (3 connections) — `test/integration/minio_test_helper.go`
- **vbPayload()** (3 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **CksExpected()** (2 connections) — `test/integration/s3-methods/sealed_checksum_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (16 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (12 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (10 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (9 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (5 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (4 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (4 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (2 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (2 shared connections)
- [Range Conformance](Range_Conformance.md) (1 shared connections)
- [Shutdown](Shutdown.md) (1 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/streaming_test.go`
- `test/integration/s3-methods/sealed_checksum_test.go`
- `test/integration/s3-methods/versioned_bucket_test.go`

## Audit Trail

- EXTRACTED: 109 (93%)
- INFERRED: 8 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*