# Backend Interface Calls

> 21 nodes · cohesion 0.17

## Key Concepts

- **MockS3Backend** (55 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.ListMultipartUploads()** (9 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.PutBucketVersioning()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **MockKeyEncryptor** (6 connections) — `internal/orchestration/providers_test.go`
- **.ListMultipartUploads()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketVersioning()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.ListMultipartUploadsInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.ListMultipartUploadsOutput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketVersioningInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketVersioningOutput** (5 connections)
- **github.com/stretchr/testify/mock.Mock** (5 connections)
- **.ListMultipartUploads()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutBucketVersioning()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.ListMultipartUploads()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutBucketVersioning()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.ListMultipartUploads()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketVersioning()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.DecryptDEK()** (2 connections) — `internal/orchestration/providers_test.go`
- **.EncryptDEK()** (2 connections) — `internal/orchestration/providers_test.go`
- **.Fingerprint()** (1 connections) — `internal/orchestration/providers_test.go`
- **.SetFingerprint()** (1 connections) — `internal/orchestration/providers_test.go`

## Relationships

- [Misc (15)](Misc_15.md) (16 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (7 shared connections)
- [Misc (12)](Misc_12.md) (4 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (3 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (1 shared connections)
- [HeadObject Test Stubs](HeadObject_Test_Stubs.md) (1 shared connections)
- [Misc (33)](Misc_33.md) (1 shared connections)
- [Misc (4)](Misc_4.md) (1 shared connections)
- [Misc (6)](Misc_6.md) (1 shared connections)
- [Misc (30)](Misc_30.md) (1 shared connections)
- [Misc (2)](Misc_2.md) (1 shared connections)

## Source Files

- `internal/orchestration/providers_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 104 (92%)
- INFERRED: 9 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*