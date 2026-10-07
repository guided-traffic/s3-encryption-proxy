# ListBuckets Root Handler

> 13 nodes · cohesion 0.23

## Key Concepts

- **NewHandler()** (13 connections) — `internal/proxy/handlers/root/handler.go`
- **root/handler.go** (6 connections) — `internal/proxy/handlers/root/handler.go`
- **handler_test.go** (4 connections) — `internal/proxy/handlers/root/handler_test.go`
- **ListAllMyBucketsResult** (4 connections) — `internal/proxy/handlers/root/handler.go`
- **TestHandleListBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsError()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsMultipleBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestNewHandler()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestRtPxNewHandlerIsUsableImmediately()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- **S3Buckets** (3 connections) — `internal/proxy/handlers/root/handler.go`
- **github.com/sirupsen/logrus.FieldLogger** (2 connections)
- **S3Bucket** (2 connections) — `internal/proxy/handlers/root/handler.go`
- **S3Owner** (2 connections) — `internal/proxy/handlers/root/handler.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (5 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (4 shared connections)
- [ListBuckets Coverage Tests](ListBuckets_Coverage_Tests.md) (2 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (1 shared connections)
- [Router](Router.md) (1 shared connections)
- [XML Document Marshalling](XML_Document_Marshalling.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/handlers/root/handler_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Audit Trail

- EXTRACTED: 27 (82%)
- INFERRED: 6 (18%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*