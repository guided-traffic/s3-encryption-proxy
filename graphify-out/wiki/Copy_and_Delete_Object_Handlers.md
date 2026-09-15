# Copy and Delete Object Handlers

> 21 nodes · cohesion 0.16

## Key Concepts

- **NewErrorWriter()** (91 connections) — `internal/proxy/response/errors.go`
- **errors_test.go** (8 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_ControlCharacterStaysWellFormed()** (6 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_HostileInputStaysWellFormedXML()** (6 connections) — `internal/proxy/response/errors_test.go`
- **object/delete_object_test.go** (5 connections) — `internal/proxy/handlers/object/delete_object_test.go`
- **decodeErrorDocument()** (5 connections) — `internal/proxy/response/errors_test.go`
- **TestCopyHandler_NotSupportedWithEncryption()** (3 connections) — `internal/proxy/handlers/multipart/copy_test.go`
- **TestHandler_CopyObjectHeaderDetection()** (3 connections) — `internal/proxy/handlers/object/copy_test.go`
- **TestHandler_CopyObjectNotSupported()** (3 connections) — `internal/proxy/handlers/object/copy_test.go`
- **TestHandleDeleteObject_InputValidation()** (3 connections) — `internal/proxy/handlers/object/delete_object_test.go`
- **TestHandleDeleteObject_S3Error()** (3 connections) — `internal/proxy/handlers/object/delete_object_test.go`
- **TestHandleDeleteObject_Success()** (3 connections) — `internal/proxy/handlers/object/delete_object_test.go`
- **TestHandleDeleteObject_VersionID()** (3 connections) — `internal/proxy/handlers/object/delete_object_test.go`
- **TestHandleDeleteObjectIntegration_BaseObjectOperations()** (3 connections) — `internal/proxy/handlers/object/delete_object_test.go`
- **TestErrorWriter_WriteNotSupportedWithEncryption()** (3 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_WriteNotSupportedWithEncryption_CopyObject()** (3 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_WriteNotSupportedWithEncryption_UploadPartCopy()** (3 connections) — `internal/proxy/response/errors_test.go`
- **TestErrorWriter_WriteNotSupportedWithEncryption_XMLFormat()** (3 connections) — `internal/proxy/response/errors_test.go`
- **errorDocument** (3 connections) — `internal/proxy/response/errors_test.go`
- **object/copy_test.go** (2 connections) — `internal/proxy/handlers/object/copy_test.go`
- **multipart/copy_test.go** (1 connections) — `internal/proxy/handlers/multipart/copy_test.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (39 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (15 shared connections)
- [S3 Error Document Writer](S3_Error_Document_Writer.md) (9 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (9 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (6 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (4 shared connections)
- [Error Mapping Coverage Tests](Error_Mapping_Coverage_Tests.md) (4 shared connections)
- [Bucket Crud](Bucket_Crud.md) (3 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (3 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/copy_test.go`
- `internal/proxy/handlers/object/copy_test.go`
- `internal/proxy/handlers/object/delete_object_test.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/errors_test.go`

## Audit Trail

- EXTRACTED: 103 (79%)
- INFERRED: 27 (21%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*