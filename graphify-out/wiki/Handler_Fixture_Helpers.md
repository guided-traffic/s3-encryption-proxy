# Handler Fixture Helpers

> 36 nodes · cohesion 0.08

## Key Concepts

- **MockS3Backend** (47 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **MockS3Backend** (46 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **MockKeyEncryptor** (6 connections) — `internal/orchestration/providers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput** (5 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadInput** (5 connections)
- **github.com/stretchr/testify/mock.Mock** (5 connections)
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.DeleteBucketWebsite()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutBucketCors()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.UploadPartCopy()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteOutput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketCorsInput** (4 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutBucketCorsOutput** (4 connections)
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.DeleteBucketWebsite()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutBucketCors()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.AbortMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.CreateMultipartUpload()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.DeleteBucketWebsite()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutBucketCors()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- *... and 11 more nodes in this community*

## Relationships

- [Mock Backend Helpers](Mock_Backend_Helpers.md) (34 shared connections)
- [Handler Test Helpers](Handler_Test_Helpers.md) (12 shared connections)
- [Provider Manager](Provider_Manager.md) (3 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (2 shared connections)
- [Multipart Handler Unit Tests](Multipart_Handler_Unit_Tests.md) (2 shared connections)
- [Mock: GetBucketAcl](Mock-_GetBucketAcl.md) (2 shared connections)
- [Mock: PutBucketAcl](Mock-_PutBucketAcl.md) (2 shared connections)
- [Mock: GetBucketCors](Mock-_GetBucketCors.md) (2 shared connections)
- [Mock: DeleteBucketCors](Mock-_DeleteBucketCors.md) (2 shared connections)
- [Mock: GetBucketVersioning](Mock-_GetBucketVersioning.md) (2 shared connections)
- [Mock: GetBucketAccelerate](Mock-_GetBucketAccelerate.md) (2 shared connections)
- [Mock: GetBucketRequestPayment](Mock-_GetBucketRequestPayment.md) (2 shared connections)

## Source Files

- `internal/orchestration/providers_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 170 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*