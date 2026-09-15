# Chunked Streaming Test Harness

> 112 nodes · cohesion 0.05

## Key Concepts

- **CreateTestBucket()** (28 connections) — `test/integration/minio_test_helper.go`
- **CreateMinIOClient()** (24 connections) — `test/integration/minio_test_helper.go`
- **CreateProxyClient()** (19 connections) — `test/integration/minio_test_helper.go`
- **comprehensive_chunked_test.go** (16 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **encryption_validation_helper.go** (16 connections) — `test/integration/encryption_validation_helper.go`
- **comprehensive_singlepart_test.go** (15 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **comprehensive_multipart_test.go** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestComprehensiveMultipartUpload()** (14 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **StartAESProviderProxyInstance()** (14 connections) — `test/integration/encryption-modes/aes_provider_test.go`
- **EnsureMinIOAvailable()** (14 connections) — `test/integration/minio_test_helper.go`
- **TestComprehensiveSinglePartUpload()** (13 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestExitProvider_ReadsBackAnEncryptedObject()** (13 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **exit_provider_test.go** (13 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **SetupTestBucket()** (13 connections) — `test/integration/minio_test_helper.go`
- **TestSinglePartUploadCornerCases()** (12 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestExitProvider_ReadsBackAMultipartObject()** (12 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **TestExitProvider_ClientDrivenPartIsNeverHeldWhole()** (11 connections) — `test/integration/encryption-modes/exit_provider_readback_test.go`
- **StartExitProviderProxyInstanceTuned()** (11 connections) — `test/integration/encryption-modes/exit_provider_test.go`
- **AssertDataIsEncryptedBasic()** (11 connections) — `test/integration/encryption_validation_helper.go`
- **ValidateEncryptedData()** (11 connections) — `test/integration/encryption_validation_helper.go`
- **TestChunkedUploadDecoding()** (10 connections) — `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- **TestMultipartUploadCorruption()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **TestStreamingMultipartUpload()** (10 connections) — `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- **downloadSinglePartFile()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- **TestSinglePartUploadVsMultipart()** (10 connections) — `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- *... and 87 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (70 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (40 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (19 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (11 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (9 shared connections)
- [Config Loading Coverage Tests](Config_Loading_Coverage_Tests.md) (6 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (4 shared connections)
- [Segment Tamper](Segment_Tamper.md) (3 shared connections)
- [Shutdown](Shutdown.md) (2 shared connections)
- [Server](Server.md) (2 shared connections)
- [Complete](Complete.md) (2 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (2 shared connections)

## Source Files

- `test/integration/360-degree-variants/comprehensive_chunked_test.go`
- `test/integration/360-degree-variants/comprehensive_multipart_test.go`
- `test/integration/360-degree-variants/comprehensive_singlepart_test.go`
- `test/integration/encryption-modes/aes_provider_test.go`
- `test/integration/encryption-modes/exit_provider_readback_test.go`
- `test/integration/encryption-modes/exit_provider_test.go`
- `test/integration/encryption-modes/test_helpers.go`
- `test/integration/encryption_validation_helper.go`
- `test/integration/minio_test_helper.go`

## Audit Trail

- EXTRACTED: 442 (87%)
- INFERRED: 64 (13%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*