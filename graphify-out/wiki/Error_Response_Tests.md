# Error Response Tests

> 21 nodes · cohesion 0.16

## Key Concepts

- **NewErrorWriter()** (76 connections) — `internal/proxy/response/errors.go`
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

- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (19 shared connections)
- [Config Env Expansion](Config_Env_Expansion.md) (15 shared connections)
- [Backend Error Mapping](Backend_Error_Mapping.md) (9 shared connections)
- [Bucket Website Handler](Bucket_Website_Handler.md) (6 shared connections)
- [Bucket Notification Handler](Bucket_Notification_Handler.md) (5 shared connections)
- [Bucket Replication Handler](Bucket_Replication_Handler.md) (5 shared connections)
- [Multipart Handler](Multipart_Handler.md) (5 shared connections)
- [Bucket Versioning Handler](Bucket_Versioning_Handler.md) (4 shared connections)
- [XML Response Helpers](XML_Response_Helpers.md) (4 shared connections)
- [Bucket CRUD Tests](Bucket_CRUD_Tests.md) (3 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [Multipart Handler Unit Tests](Multipart_Handler_Unit_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/copy_test.go`
- `internal/proxy/handlers/object/copy_test.go`
- `internal/proxy/handlers/object/delete_object_test.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/errors_test.go`

## Audit Trail

- EXTRACTED: 96 (83%)
- INFERRED: 19 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*