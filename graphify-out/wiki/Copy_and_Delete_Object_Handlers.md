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

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (30 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (15 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (9 shared connections)
- [S3 Error Document Writer](S3_Error_Document_Writer.md) (8 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (5 shared connections)
- [Multipart Handler Wiring](Multipart_Handler_Wiring.md) (5 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (4 shared connections)
- [CORS Middleware and SSE-C Stripping](CORS_Middleware_and_SSE-C_Stripping.md) (4 shared connections)
- [Error Mapping Coverage Tests](Error_Mapping_Coverage_Tests.md) (4 shared connections)
- [Proxy Server Lifecycle Tests](Proxy_Server_Lifecycle_Tests.md) (3 shared connections)
- [Bucket Lifecycle Handler](Bucket_Lifecycle_Handler.md) (2 shared connections)
- [Bucket Sub-Resource Handler Registry](Bucket_Sub-Resource_Handler_Registry.md) (1 shared connections)

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