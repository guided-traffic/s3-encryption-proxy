# Large Multipart and DEK Cache Tests

> 36 nodes · cohesion 0.10

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.Client** (91 connections)
- **minio_test_helper.go** (35 connections) — `test/integration/minio_test_helper.go`
- **PurgeBucket()** (11 connections) — `test/integration/minio_test_helper.go`
- **createMinIOClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **createProxyClient()** (8 connections) — `test/integration/minio_test_helper.go`
- **TestDEKCacheReuploadRegression()** (7 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **NewS3Client()** (7 connections) — `test/integration/minio_test_helper.go`
- **dek_cache_reupload_test.go** (6 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **runReuploadCycle()** (6 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **CreateProxyClientWithEndpoint()** (6 connections) — `test/integration/minio_test_helper.go`
- **tlsHTTPClient()** (6 connections) — `test/integration/minio_test_helper.go`
- **WaitForHealthCheck()** (6 connections) — `test/integration/minio_test_helper.go`
- **HdrCleanupBucket()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestLargeMultipart500MB()** (5 connections) — `test/integration/180-degree-variants/large_multipart_upload_test.go`
- **requireDownloadHashEquals()** (5 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **ClearBucketObjects()** (5 connections) — `test/integration/minio_test_helper.go`
- **SkipIfMinIONotAvailable()** (5 connections) — `test/integration/minio_test_helper.go`
- **putMultipartTwoParts()** (4 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **putSinglePart()** (4 connections) — `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- **purgeIncompleteUploads()** (4 connections) — `test/integration/minio_test_helper.go`
- **purgeObjects()** (4 connections) — `test/integration/minio_test_helper.go`
- **purgeVersions()** (4 connections) — `test/integration/minio_test_helper.go`
- **SkipIfProxyNotAvailable()** (4 connections) — `test/integration/minio_test_helper.go`
- **CleanupTestBucket()** (3 connections) — `test/integration/minio_test_helper.go`
- **CompareObjectData()** (3 connections) — `test/integration/minio_test_helper.go`
- *... and 11 more nodes in this community*

## Relationships

- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (40 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (14 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (10 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (8 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (7 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (7 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (7 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (7 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (5 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (5 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (4 shared connections)
- [Integration Corpus Seed and Budget](Integration_Corpus_Seed_and_Budget.md) (4 shared connections)

## Source Files

- `test/integration/180-degree-variants/large_multipart_upload_test.go`
- `test/integration/360-degree-variants/dek_cache_reupload_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`

## Audit Trail

- EXTRACTED: 199 (96%)
- INFERRED: 8 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*