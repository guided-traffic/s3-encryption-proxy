# ListBuckets Root Handler Tests

> 8 nodes · cohesion 0.36

## Key Concepts

- **NewHandler()** (13 connections) — `internal/proxy/handlers/root/handler.go`
- **handler_test.go** (4 connections) — `internal/proxy/handlers/root/handler_test.go`
- **github.com/sirupsen/logrus.FieldLogger** (3 connections)
- **TestHandleListBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsError()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestHandleListBucketsMultipleBuckets()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestNewHandler()** (3 connections) — `internal/proxy/handlers/root/handler_test.go`
- **TestRtPxNewHandlerIsUsableImmediately()** (3 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (5 shared connections)
- [Multipart Handler](Multipart_Handler.md) (4 shared connections)
- [ListBuckets Handler Tests](ListBuckets_Handler_Tests.md) (2 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (1 shared connections)
- [Error Response Tests](Error_Response_Tests.md) (1 shared connections)
- [ListBuckets XML Types](ListBuckets_XML_Types.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/root/handler.go`
- `internal/proxy/handlers/root/handler_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`

## Audit Trail

- EXTRACTED: 19 (76%)
- INFERRED: 6 (24%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*