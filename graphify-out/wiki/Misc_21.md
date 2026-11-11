# Misc (21)

> 7 nodes · cohesion 0.67

## Key Concepts

- **.GetBucketNotificationConfiguration()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketNotificationConfigurationOutput** (6 connections)
- **.GetBucketNotificationConfiguration()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetBucketNotificationConfigurationInput** (5 connections)
- **.GetBucketNotificationConfiguration()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.GetBucketNotificationConfiguration()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetBucketNotificationConfiguration()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (2 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (2 shared connections)
- [Bucket: Subresource Documents (3)](Bucket-_Subresource_Documents_3.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)

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