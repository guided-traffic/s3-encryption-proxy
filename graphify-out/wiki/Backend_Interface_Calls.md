# Backend Interface Calls

> 36 nodes · cohesion 0.11

## Key Concepts

- **MockS3Backend** (57 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **MockS3Backend** (55 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.AbortMultipartUpload()** (10 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.GetBucketReplication()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.GetBucketVersioning()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.HeadObject()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput** (6 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadObjectInput** (6 connections)
- **MockKeyEncryptor** (6 connections) — `internal/orchestration/providers_test.go`
- **.AbortMultipartUpload()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketReplication()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketVersioning()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.HeadObject()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketReplicationInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketReplicationOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketVersioningInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketVersioningOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.HeadObjectOutput** (5 connections)
- **github.com/stretchr/testify/mock.Mock** (5 connections)
- **.AbortMultipartUpload()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketReplication()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketVersioning()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.HeadObject()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.AbortMultipartUpload()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- *... and 11 more nodes in this community*

## Relationships

- [Tampering Harness](Tampering_Harness.md) (28 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (14 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (6 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (3 shared connections)
- [Misc (33)](Misc_33.md) (2 shared connections)
- [Misc (4)](Misc_4.md) (2 shared connections)
- [Misc (6)](Misc_6.md) (2 shared connections)
- [Misc (30)](Misc_30.md) (2 shared connections)
- [Misc (2)](Misc_2.md) (2 shared connections)
- [Misc (17)](Misc_17.md) (2 shared connections)
- [Misc (35)](Misc_35.md) (2 shared connections)
- [Misc (28)](Misc_28.md) (2 shared connections)

## Source Files

- `internal/orchestration/providers_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 196 (92%)
- INFERRED: 18 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*