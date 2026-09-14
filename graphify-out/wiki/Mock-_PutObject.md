# Mock: PutObject

> 6 nodes · cohesion 0.53

## Key Concepts

- **github.com/aws/aws-sdk-go-v2/service/s3.PutObjectInput** (6 connections)
- **github.com/aws/aws-sdk-go-v2/service/s3.PutObjectOutput** (5 connections)
- **.PutObject()** (4 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **.PutObject()** (4 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **.PutObject()** (4 connections) — `internal/proxy/handlers/object/test_helpers_test.go`
- **.PutObject()** (4 connections) — `internal/proxy/handlers/root/test_helpers_test.go`

## Relationships

- [Mock Backend Helpers](Mock_Backend_Helpers.md) (4 shared connections)
- [Handler Test Helpers](Handler_Test_Helpers.md) (2 shared connections)
- [Handler Fixture Helpers](Handler_Fixture_Helpers.md) (2 shared connections)
- [Object PUT Handler Tests](Object_PUT_Handler_Tests.md) (1 shared connections)
- [Object Helper Functions](Object_Helper_Functions.md) (1 shared connections)
- [Object Header Conformance](Object_Header_Conformance.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/test_helpers_test.go`
- `internal/proxy/handlers/root/test_helpers_test.go`

## Audit Trail

- EXTRACTED: 19 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*