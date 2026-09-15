# MockS3Backend Tagging and Policy

> 23 nodes · cohesion 0.12

## Key Concepts

- **MockS3Backend** (55 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **MockKeyEncryptor** (6 connections) — `internal/orchestration/providers_test.go`
- **github.com/stretchr/testify/mock.Mock** (5 connections)
- **.DeleteObjectTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetBucketLocation()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketPolicy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketPolicyInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketPolicyOutput** (4 connections)
- **.DeleteObjectTagging()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketLocation()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutBucketPolicy()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteObjectTagging()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketLocation()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutBucketPolicy()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.DeleteObjectTagging()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetBucketLocation()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.PutBucketPolicy()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.Fingerprint()** (1 connections) — `internal/orchestration/providers_test.go`
- **.SetFingerprint()** (1 connections) — `internal/orchestration/providers_test.go`

## Relationships

- [Helpers](Helpers.md) (33 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (21 shared connections)
- [MockS3Backend Object Operations](MockS3Backend_Object_Operations.md) (9 shared connections)
- [MockS3Backend Attribute Operations](MockS3Backend_Attribute_Operations.md) (6 shared connections)
- [MockS3Backend Multipart Operations](MockS3Backend_Multipart_Operations.md) (4 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (3 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)

## Source Files

- `internal/orchestration/providers_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 109 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*