# Passthrough Operation Tests

> 13 nodes · cohesion 0.22

## Key Concepts

- **NewTestContext()** (16 connections) — `test/integration/minio_test_helper.go`
- **TestListBucketsOperation()** (5 connections) — `test/integration/s3-methods/list_buckets_test.go`
- **passthrough_operations_test.go** (5 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **TestStreamingMultipartUpload()** (4 connections) — `test/integration/performance-test/streaming_test.go`
- **TestDeleteObjectFunctionality()** (4 connections) — `test/integration/s3-methods/delete_object_test.go`
- **TestListBucketsPassthrough()** (4 connections) — `test/integration/s3-methods/list_buckets_test.go`
- **TestPassthroughOperations_DeleteObjects()** (3 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **TestPassthroughOperations_GetObjectTorrent()** (3 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **TestPassthroughOperations_LegalHold()** (3 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **TestPassthroughOperations_Retention()** (3 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **TestPassthroughOperations_SelectObjectContent()** (3 connections) — `test/integration/s3-methods/passthrough_operations_test.go`
- **list_buckets_test.go** (2 connections) — `test/integration/s3-methods/list_buckets_test.go`
- **s3-methods/delete_object_test.go** (1 connections) — `test/integration/s3-methods/delete_object_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (10 shared connections)
- [MinIO Test Helper](MinIO_Test_Helper.md) (3 shared connections)
- [Encryption-at-Rest Integration Tests](Encryption-at-Rest_Integration_Tests.md) (3 shared connections)
- [Object Sub-Resource Refusals](Object_Sub-Resource_Refusals.md) (2 shared connections)
- [Streaming Performance Test](Streaming_Performance_Test.md) (2 shared connections)
- [Provider Mode Integration Tests](Provider_Mode_Integration_Tests.md) (1 shared connections)
- [360-Degree Singlepart Tests](360-Degree_Singlepart_Tests.md) (1 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/performance-test/streaming_test.go`
- `test/integration/s3-methods/delete_object_test.go`
- `test/integration/s3-methods/list_buckets_test.go`
- `test/integration/s3-methods/passthrough_operations_test.go`

## Audit Trail

- EXTRACTED: 36 (92%)
- INFERRED: 3 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*