# Misc (12)

> 13 nodes · cohesion 0.28

## Key Concepts

- **MockS3Backend** (57 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.DeleteBucketWebsite()** (8 connections) — `internal/proxy/interfaces/s3_backend.go`
- **.DeleteBucketWebsite()** (5 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteOutput** (5 connections)
- **.DeleteBucketWebsite()** (5 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteBucketWebsite()** (5 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.DeleteBucketWebsite()** (5 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.GetObjectAttributes()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesInput** (3 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesOutput** (3 connections)

## Relationships

- [Misc (15)](Misc_15.md) (12 shared connections)
- [S3 Backend Mock](S3_Backend_Mock.md) (6 shared connections)
- [Backend Interface Calls](Backend_Interface_Calls.md) (4 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [PutBucketLogging Test Stubs](PutBucketLogging_Test_Stubs.md) (1 shared connections)
- [GetBucketVersioning Test Stubs](GetBucketVersioning_Test_Stubs.md) (1 shared connections)
- [Misc (40)](Misc_40.md) (1 shared connections)
- [Misc (11)](Misc_11.md) (1 shared connections)
- [Misc (21)](Misc_21.md) (1 shared connections)
- [Misc (38)](Misc_38.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`
- `internal/proxy/interfaces/s3_backend.go`

## Audit Trail

- EXTRACTED: 87 (96%)
- INFERRED: 4 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*