# Bucket XML Documents

> 26 nodes · cohesion 0.08

## Key Concepts

- **encoding/xml.Name** (45 connections)
- **listBucketResultV1** (4 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **listBucketResultV2** (4 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **objectEntry** (4 connections) — `internal/proxy/handlers/bucket/listing_document.go`
- **s3Error** (4 connections) — `internal/proxy/response/errors.go`
- **BkterrorDoc** (3 connections) — `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- **CompleteMultipartUpload** (3 connections) — `internal/proxy/handlers/multipart/complete.go`
- **ObjMiscerrorDoc** (3 connections) — `internal/proxy/handlers/object/dispatch_coverage_test.go`
- **accelerateConfigurationDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **locationConstraintDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **requestPaymentConfigurationDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **versioningConfigurationDocument** (2 connections) — `internal/proxy/handlers/bucket/subresource_documents.go`
- **commonPrefix** (2 connections)
- **CompletedPart** (2 connections) — `internal/proxy/handlers/multipart/complete.go`
- **completeResultDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **initiateResultDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **listPartsResultDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_test.go`
- **MpuCompleteDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuInitiateDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuListPartsDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **MpuUnmarshalableDoc** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **RespLocationPayload** (2 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespTagPayload** (2 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RespTruncatingPayload** (2 connections) — `internal/proxy/response/xml_coverage_test.go`
- **RtPxlistBucketsDoc** (2 connections) — `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (16 shared connections)
- [Bucket Sub-Resource Documents](Bucket_Sub-Resource_Documents.md) (6 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (5 shared connections)
- [Multipart: Xml](Multipart-_Xml.md) (4 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (3 shared connections)
- [Bucket: Subresource Documents](Bucket-_Subresource_Documents.md) (2 shared connections)
- [DeleteObjects Handling](DeleteObjects_Handling.md) (2 shared connections)
- [Bucket Handler Tests](Bucket_Handler_Tests.md) (1 shared connections)
- [Bucket: Subresource Documents (4)](Bucket-_Subresource_Documents_4.md) (1 shared connections)
- [Bucket: Subresource Documents (2)](Bucket-_Subresource_Documents_2.md) (1 shared connections)
- [Bucket: Subresource Documents (5)](Bucket-_Subresource_Documents_5.md) (1 shared connections)
- [Bucket: Subresource Documents (3)](Bucket-_Subresource_Documents_3.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/bucket/listing_document.go`
- `internal/proxy/handlers/bucket/subresource_documents.go`
- `internal/proxy/handlers/bucket/subresource_matrix_coverage_test.go`
- `internal/proxy/handlers/multipart/complete.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- `internal/proxy/handlers/multipart/multipart_test.go`
- `internal/proxy/handlers/object/dispatch_coverage_test.go`
- `internal/proxy/handlers/root/listbuckets_coverage_test.go`
- `internal/proxy/response/errors.go`
- `internal/proxy/response/xml_coverage_test.go`

## Audit Trail

- EXTRACTED: 78 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*