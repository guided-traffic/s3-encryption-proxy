# S3 Backend Mock

> 76 nodes · cohesion 0.05

## Key Concepts

- **MockS3Backend** (64 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **MockS3Backend** (64 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **MockS3Backend** (64 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **MockS3Backend** (63 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectInput** (6 connections)
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.CreateBucket()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketLifecycle()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketPolicy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteObjects()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListMultipartUploads()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPart()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateBucketInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateBucketOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketLifecycleInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketLifecycleOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketPolicyInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketPolicyOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectInput** (4 connections)
- *... and 51 more nodes in this community*

## Relationships

- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (82 shared connections)
- [Provider Manager Cache Tests](Provider_Manager_Cache_Tests.md) (4 shared connections)
- [GetBucketVersioning Backend Method](GetBucketVersioning_Backend_Method.md) (4 shared connections)
- [PutBucketVersioning Backend Method](PutBucketVersioning_Backend_Method.md) (4 shared connections)
- [GetBucketTagging Backend Method](GetBucketTagging_Backend_Method.md) (4 shared connections)
- [PutBucketTagging Backend Method](PutBucketTagging_Backend_Method.md) (4 shared connections)
- [GetBucketNotification Backend Method](GetBucketNotification_Backend_Method.md) (4 shared connections)
- [PutBucketNotification Backend Method](PutBucketNotification_Backend_Method.md) (4 shared connections)
- [GetBucketLifecycle Backend Method](GetBucketLifecycle_Backend_Method.md) (4 shared connections)
- [PutBucketLifecycle Backend Method](PutBucketLifecycle_Backend_Method.md) (4 shared connections)
- [PutBucketReplication Backend Method](PutBucketReplication_Backend_Method.md) (4 shared connections)
- [DeleteBucketReplication Backend Method](DeleteBucketReplication_Backend_Method.md) (4 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 395 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*