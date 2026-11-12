# Misc (17)

> 7 nodes · cohesion 0.67

## Key Concepts

- **.GetBucketAcl()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketAclOutput** (6 connections)
- **.GetBucketAcl()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketAclInput** (5 connections)
- **.GetBucketAcl()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketAcl()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketAcl()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Misc (15)](Misc_15.md) (5 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (2 shared connections)
- [Bucket: Subresource Documents (4)](Bucket-_Subresource_Documents_4.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (1 shared connections)
- [Misc (12)](Misc_12.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 21 (84%)
- INFERRED: 4 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*