# Helpers

> 6 nodes · cohesion 0.53

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsV2Input** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsV2Output** (5 connections)
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.ListObjectsV2()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (4 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (2 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)
- [MockS3Backend Attribute Operations](MockS3Backend_Attribute_Operations.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 18 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*