# XML Document Marshalling

> 31 nodes · cohesion 0.08

## Key Concepts

- **encoding/xml.Name** (45 connections)
- **multipart/xml.go** (9 connections) — `internal/proxy/handlers/multipart/xml.go`
- **xml_coverage_test.go** (6 connections) — `internal/proxy/response/xml_coverage_test.go`
- **TestRespNewXMLWriter()** (4 connections) — `internal/proxy/response/xml_coverage_test.go`
- **listMultipartUploadsResult** (4 connections) — `internal/proxy/handlers/multipart/xml.go`
- **listPartsResult** (4 connections) — `internal/proxy/handlers/multipart/xml.go`
- **BkterrorDoc** (3 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **uploadEntry** (3 connections) — `internal/proxy/handlers/multipart/xml.go`
- **ObjMiscerrorDoc** (3 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **accelerateConfigurationDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **locationConstraintDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **requestPaymentConfigurationDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **versioningConfigurationDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **ownerEntry** (2 connections)
- **completeMultipartUploadResult** (2 connections) — `internal/proxy/handlers/multipart/xml.go`
- **completeResultDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **initiateMultipartUploadResult** (2 connections) — `internal/proxy/handlers/multipart/xml.go`
- **initiateResultDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **listPartsResultDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **MpuCompleteDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuInitiateDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuListPartsDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuUnmarshalableDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **partEntry** (2 connections) — `internal/proxy/handlers/multipart/xml.go`
- **RespLocationPayload** (2 connections) — `internal/proxy/response/xml_coverage_test.go`
- *... and 6 more nodes in this community*

## Relationships

- [Subresource Documents](Subresource_Documents.md) (8 shared connections)
- [Bucket XML Document Types](Bucket_XML_Document_Types.md) (7 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (6 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (3 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (3 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (3 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [Listing Document](Listing_Document.md) (2 shared connections)
- [ListBuckets Root Handler](ListBuckets_Root_Handler.md) (2 shared connections)
- [Error Mapping Coverage Tests](Error_Mapping_Coverage_Tests.md) (2 shared connections)
- [Complete](Complete.md) (1 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/subresource_documents.go`
- `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/multipart/xml.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 81 (98%)
- INFERRED: 2 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*