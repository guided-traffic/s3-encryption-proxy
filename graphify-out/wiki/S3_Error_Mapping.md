# S3 Error Mapping

> 31 nodes · cohesion 0.12

## Key Concepts

- **MapError()** (31 connections) — `internal/proxy/response/error_mapping.go`
- **response/error_mapping_test.go** (16 connections) — `internal/proxy/response/error_mapping_test.go`
- **sdkError()** (10 connections) — `internal/proxy/response/error_mapping_test.go`
- **discardLogger()** (9 connections) — `internal/proxy/response/error_mapping_test.go`
- **checksumVerdict()** (6 connections) — `internal/proxy/response/error_mapping.go`
- **TestMapError_NeverProducesInvalidStatus()** (6 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_BucketOnlyResource()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_ResponseDocument()** (5 connections) — `internal/proxy/response/error_mapping_test.go`
- **error_mapping.go** (4 connections) — `internal/proxy/response/error_mapping.go`
- **TestMapError_ConditionalGetKeepsIts304()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_DoesNotLeakBackendDetail()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_ErrorBehindANonErrorStatusBecomes500()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_SDKErrorChains()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_InternalErrorIsOpaque()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestWriteS3Error_NilError()** (4 connections) — `internal/proxy/response/error_mapping_test.go`
- **ErrorWriter.writeErrorDocument** (4 connections) — `docs/developer/errors.md`
- **.WriteChecksumVerdict()** (4 connections) — `internal/proxy/response/errors.go`
- **TestMapError_InternalErrorsStayGeneric()** (3 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_InternalMarkers()** (3 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_ResponseWithoutAPIError()** (3 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_TypedErrorWithoutResponse()** (3 connections) — `internal/proxy/response/error_mapping_test.go`
- **TestMapError_WebsiteConfiguration()** (3 connections) — `internal/proxy/response/error_mapping_test.go`
- **MappedError** (3 connections) — `internal/proxy/response/error_mapping.go`
- **One Function Renders the S3 Error Document** (2 connections) — `docs/developer/errors.md`
- **IsChecksumFailure()** (2 connections) — `internal/proxy/request/checksum.go`
- *... and 6 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (14 shared connections)
- [Error Mapping Coverage Tests](Error_Mapping_Coverage_Tests.md) (11 shared connections)
- [Copy and Delete Object Handlers](Copy_and_Delete_Object_Handlers.md) (9 shared connections)
- [Bucket Website and Create/Delete](Bucket_Website_and_Create-Delete.md) (3 shared connections)
- [Checksum](Checksum.md) (2 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (1 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (1 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (1 shared connections)
- [SigV4 Service Coverage Tests](SigV4_Service_Coverage_Tests.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)

## Source Files

- `docs/developer/errors.md`
- `internal/proxy/request/checksum.go`
- `internal/proxy/response/error_mapping.go`
- `internal/proxy/response/error_mapping_test.go`
- `internal/proxy/response/errors.go`

## Audit Trail

- EXTRACTED: 68 (68%)
- INFERRED: 32 (32%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*