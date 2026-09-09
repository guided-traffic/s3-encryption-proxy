# Config Accessor Tests

> 77 nodes · cohesion 0.05

## Key Concepts

- **testing.T** (1581 connections)
- **config_test.go** (16 connections) — `internal/config/config_test.go`
- **NewTestContext()** (16 connections) — `test/integration/minio_test_helper.go`
- **accessors_coverage_test.go** (9 connections) — `internal/config/accessors_coverage_test.go`
- **backendOptions()** (9 connections) — `internal/proxy/backend_client_test.go`
- **backend_client_test.go** (6 connections) — `internal/proxy/backend_client_test.go`
- **cors_test.go** (6 connections) — `internal/proxy/handlers/bucket/cors_test.go`
- **bucket_cors_test.go** (6 connections) — `test/integration/s3-methods/bucket_cors_test.go`
- **bucket_logging_test.go** (6 connections) — `test/integration/s3-methods/bucket_logging_test.go`
- **TestStreamingVsStandardPerformance()** (5 connections) — `test/integration/performance-test/streaming_test.go`
- **bucket_location_test.go** (5 connections) — `test/integration/s3-methods/bucket_location_test.go`
- **TestListBucketsOperation()** (5 connections) — `test/integration/s3-methods/list_buckets_test.go`
- **passthrough_operations_test.go** (5 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **streaming_test.go** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **downloadAndVerifyWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **performMultipartUploadWithSDK()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **TestStreamingMultipartUpload()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **TestDeleteObjectFunctionality()** (4 connections) — `test/integration/s3-methods/delete_object_test.go`
- **TestListBucketsPassthrough()** (4 connections) — `test/integration/s3-methods/list_buckets_test.go`
- **TestCfgIsS3ClientAuthEnabled()** (3 connections) — `internal/config/accessors_coverage_test.go`
- **TestBackendClientOptions_ChecksumsOnlyWhenRequired()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_InsecureSkipVerify()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_NoEndpointLeavesDefaults()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestBackendClientOptions_PathStyleAndEndpoint()** (3 connections) — `internal/proxy/backend_client_test.go`
- **TestCORSRequestBodyHandling()** (3 connections) — `internal/proxy/handlers/bucket/cors_test.go`
- *... and 52 more nodes in this community*

## Relationships

- [Object GET Handler Tests](Object_GET_Handler_Tests.md) (75 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (56 shared connections)
- [Multipart Session Tests](Multipart_Session_Tests.md) (55 shared connections)
- [Velero E2E Suite](Velero_E2E_Suite.md) (55 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (52 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (49 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (49 shared connections)
- [Multipart Session Lifecycle Tests](Multipart_Session_Lifecycle_Tests.md) (45 shared connections)
- [Bucket Handler Test Fakes](Bucket_Handler_Test_Fakes.md) (43 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (41 shared connections)
- [Encryption Metadata Management](Encryption_Metadata_Management.md) (38 shared connections)
- [Streaming IO Reader Tests](Streaming_IO_Reader_Tests.md) (30 shared connections)

## Source Files

- `internal/config/accessors_coverage_test.go`
- `internal/config/config_test.go`
- `internal/proxy/backend_client_test.go`
- `internal/proxy/handlers/bucket/cors_test.go`
- `internal/proxy/handlers_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/streaming_test.go`
- `test/integration/s3-methods/bucket_cors_test.go`
- `test/integration/s3-methods/bucket_location_test.go`
- `test/integration/s3-methods/bucket_logging_test.go`
- `test/integration/s3-methods/bucket_subresource_test.go`
- `test/integration/s3-methods/delete_object_test.go`
- `test/integration/s3-methods/list_buckets_test.go`
- `test/integration/s3-methods/passthrough_operations_test.go`

## Audit Trail

- EXTRACTED: 1678 (100%)
- INFERRED: 6 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*