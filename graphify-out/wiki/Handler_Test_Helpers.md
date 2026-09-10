# Handler Test Helpers

> 71 nodes · cohesion 0.04

## Key Concepts

- **MockS3Backend** (64 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **MockS3Backend** (64 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteObjectTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectLegalHold()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectRetention()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListMultipartUploads()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.ListParts()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketAccelerateConfiguration()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketReplication()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketRequestPayment()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectAcl()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectLegalHold()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectRetention()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObjectTagging()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.SelectObjectContent()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.CopyObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.DeleteObjectTagging()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAcl()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectLegalHold()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectRetention()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectTagging()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- *... and 46 more nodes in this community*

## Relationships

- [Mock Backend Helpers](Mock_Backend_Helpers.md) (50 shared connections)
- [Handler Fixture Helpers](Handler_Fixture_Helpers.md) (12 shared connections)
- [Mock: PutBucketLogging](Mock-_PutBucketLogging.md) (2 shared connections)
- [Mock: GetBucketVersioning](Mock-_GetBucketVersioning.md) (2 shared connections)
- [Mock: GetBucketTagging](Mock-_GetBucketTagging.md) (2 shared connections)
- [Mock: PutBucketTagging](Mock-_PutBucketTagging.md) (2 shared connections)
- [Mock: DeleteBucketTagging](Mock-_DeleteBucketTagging.md) (2 shared connections)
- [Mock: GetBucketNotification](Mock-_GetBucketNotification.md) (2 shared connections)
- [Mock: PutBucketNotification](Mock-_PutBucketNotification.md) (2 shared connections)
- [Mock: GetBucketLifecycle](Mock-_GetBucketLifecycle.md) (2 shared connections)
- [Mock: PutBucketLifecycle](Mock-_PutBucketLifecycle.md) (2 shared connections)
- [Mock: DeleteBucketLifecycle](Mock-_DeleteBucketLifecycle.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 230 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*