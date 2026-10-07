# Streaming Upload and Sealed Checksum

> 17 nodes · cohesion 0.24

## Key Concepts

- **TestContext** (20 connections) — `test/integration/minio_test_helper.go`
- **vbNewVersionedBucket()** (10 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **versioned_bucket_test.go** (9 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbClientDrivenMultipartEntityHeaders()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbDeleteMarkerAndVersionDelete()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbMultipartUploadLeavesExactlyOneVersion()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestVbVersionIdAddressesTheVersionItNames()** (8 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **vbPut()** (6 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **TestStreamingVsStandardPerformance()** (5 connections) — `test/integration/performance-test/streaming_test.go`
- **vbSHA()** (5 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **streaming_test.go** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **downloadAndVerifyWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **performMultipartUploadWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **TestStreamingMultipartUpload()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **.EnsureTestBucket()** (3 connections) — `test/integration/minio_test_helper.go`
- **vbPayload()** (3 connections) — `test/integration/s3-methods/versioned_bucket_test.go`
- **.CleanupTestBucket()** (2 connections) — `test/integration/minio_test_helper.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (11 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (10 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (7 shared connections)
- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (6 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (3 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (3 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (2 shared connections)
- [Range Conformance](Range_Conformance.md) (1 shared connections)
- [Shutdown](Shutdown.md) (1 shared connections)
- [Encryption Mode Proxy Instances](Encryption_Mode_Proxy_Instances.md) (1 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (1 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/streaming_test.go`
- `test/integration/s3-methods/versioned_bucket_test.go`

## Audit Trail

- EXTRACTED: 75 (95%)
- INFERRED: 4 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*