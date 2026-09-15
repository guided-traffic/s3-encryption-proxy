# Helpers

> 6 nodes · cohesion 0.53

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketAclOutput** (5 connections)
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketAclInput** (4 connections)
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (4 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (2 shared connections)
- [Subresource Documents](Subresource_Documents.md) (1 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (1 shared connections)
- [MockS3Backend Attribute Operations](MockS3Backend_Attribute_Operations.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 17 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*