# S3 Methods: Sealed Checksum Test

> 26 nodes · cohesion 0.15

## Key Concepts

- **sealed_checksum_test.go** (30 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestContext** (26 connections) — `test/integration/minio_test_helper.go`
- **CksCheckWritePath()** (11 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **testing.B** (9 connections)
- **TestCksSuffixRangeLargerThanTheObject()** (9 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **TestCksPartNumberTenThousandIsRefused()** (8 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **prepareBenchmarkBucket()** (7 connections) — `test/integration/performance-test/performance_test.go`
- **CksAssertServedChecksum()** (7 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **benchGetResponse()** (6 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **TestCksEveryWritePathSealsTheSameChecksum()** (6 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **BenchmarkStreamingDownload()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **BenchmarkStreamingUpload()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **EnsureBenchmarkEnvironment()** (5 connections) — `test/integration/performance-test/performance_test.go`
- **TestStreamingVsStandardPerformance()** (5 connections) — `test/integration/performance-test/streaming_test.go`
- **CksStored()** (5 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksStoredLength()** (5 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **BenchmarkGetResponseCopy()** (4 connections) — `internal/proxy/handlers/object/copy_bench_test.go`
- **downloadAndVerifyWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **performMultipartUploadWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **CksAssertChecksumSealed()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksDelete()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **CksPayload()** (4 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **.EnsureTestBucket()** (3 connections) — `test/integration/minio_test_helper.go`
- **CksExpected()** (3 connections) — `test/integration/s3-methods/sealed_checksum_test.go`
- **.CleanupTestBucket()** (2 connections) — `test/integration/minio_test_helper.go`
- *... and 1 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (29 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (13 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (9 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (8 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (6 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (4 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (3 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (2 shared connections)
- [Request: Checksum](Request-_Checksum.md) (1 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/object/copy_bench_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/performance_test.go`
- `test/integration/performance-test/streaming_test.go`
- `test/integration/s3-methods/sealed_checksum_test.go`

## Audit Trail

- EXTRACTED: 125 (93%)
- INFERRED: 10 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*