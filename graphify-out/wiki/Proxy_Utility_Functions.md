# Proxy Utility Functions

> 18 nodes · cohesion 0.13

## Key Concepts

- **ReadRequestBody()** (7 connections) — `internal/proxy/utils/utils.go`
- **utils_test.go** (7 connections) — `internal/proxy/utils/utils_test.go`
- **utils.go** (6 connections) — `internal/proxy/utils/utils.go`
- **github.com/sirupsen/logrus.FieldLogger** (4 connections)
- **GetQueryParam()** (4 connections) — `internal/proxy/utils/utils.go`
- **TestGetQueryParam()** (3 connections) — `internal/proxy/server_test.go`
- **TestUtlGetQueryParam_NilMap()** (3 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **TestUtlParseMaxKeys_Boundaries()** (3 connections) — `internal/proxy/utils/utils_coverage_test.go`
- **ParseMaxKeys()** (3 connections) — `internal/proxy/utils/utils.go`
- **TestGetQueryParam()** (3 connections) — `internal/proxy/utils/utils_test.go`
- **TestHandleS3Error_Basic()** (3 connections) — `internal/proxy/utils/utils_test.go`
- **TestHandleS3Error_EncryptionKeyMissing()** (3 connections) — `internal/proxy/utils/utils_test.go`
- **TestParseMaxKeys()** (3 connections) — `internal/proxy/utils/utils_test.go`
- **TestReadRequestBody()** (3 connections) — `internal/proxy/utils/utils_test.go`
- **TestReadRequestBody_ErrorReader()** (3 connections) — `internal/proxy/utils/utils_test.go`
- **S3ErrorResponse** (3 connections) — `internal/proxy/utils/utils.go`
- **errorReader** (2 connections) — `internal/proxy/utils/utils_test.go`
- **.Read()** (1 connections) — `internal/proxy/utils/utils_test.go`

## Relationships

- [Proxy Utils Tests](Proxy_Utils_Tests.md) (9 shared connections)
- [Config Accessor Tests](Config_Accessor_Tests.md) (9 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)
- [Proxy Server Auth Error Tests](Proxy_Server_Auth_Error_Tests.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/server_test.go`
- `internal/proxy/utils/utils.go`
- `internal/proxy/utils/utils_coverage_test.go`
- `internal/proxy/utils/utils_test.go`

## Audit Trail

- EXTRACTED: 34 (77%)
- INFERRED: 10 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*