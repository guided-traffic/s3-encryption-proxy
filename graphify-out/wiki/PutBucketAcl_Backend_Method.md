# PutBucketAcl Backend Method

> 6 nodes · cohesion 0.53

## Key Concepts

- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAclInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAclOutput** (4 connections)
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutBucketAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (4 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (4 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 16 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*