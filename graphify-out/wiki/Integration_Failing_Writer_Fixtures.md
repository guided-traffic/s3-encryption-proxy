# Integration Failing Writer Fixtures

> 32 nodes · cohesion 0.15

## Key Concepts

- **net/http.Header** (37 connections)
- **object_headers_conformance_test.go** (20 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrNewDirectBucket()** (14 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrETagIsPresentAndStableAcrossRepeatedHeads()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrHeadReturnsTheSameHeaderSetAsGet()** (12 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrGetHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrHeadHeaders()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrUserMetadataRoundTripsLikeTheBackend()** (11 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEncryptionMetadataIsNeverVisibleToTheClient()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrEntityHeadersSurvivePutGetAndHead()** (10 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrPutWithEntityHeaders()** (9 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrStorageHeadersReachTheBackend()** (8 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **hdrSignedPutQuery()** (7 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestHdrSequentialWhitespaceInASignedHeaderIsAccepted()** (7 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrCleanupBucket()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrObjectHeaderNames()** (6 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **TestSubpassMalformedSubResourceDocumentIsMalformedXML()** (6 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **TestSubpassObjectTaggingRoundTrip()** (6 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **TestSubpassRetentionAndLegalHoldRoundTrip()** (6 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- **ObjIntfailingWriter** (5 connections) — `internal/proxy/handlers/object/integrity_report_test.go`
- **HdrCaptureResponseHeaders()** (5 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **HdrUserMetadata()** (5 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3.Options** (4 connections)
- **hdrSignedPut()** (4 connections) — `test/integration/s3-methods/object_headers_conformance_test.go`
- **object_subresource_passthrough_test.go** (4 connections) — `test/integration/s3-methods/object_subresource_passthrough_test.go`
- *... and 7 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (16 shared connections)
- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (13 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (11 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (10 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (6 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (5 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (3 shared connections)
- [Monitoring Middleware Tests](Monitoring_Middleware_Tests.md) (3 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (3 shared connections)
- [Backend Client](Backend_Client.md) (2 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (2 shared connections)
- [Health Probe Handler](Health_Probe_Handler.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/object/integrity_report_test.go`
- `test/integration/s3-methods/object_headers_conformance_test.go`
- `test/integration/s3-methods/object_subresource_passthrough_test.go`

## Audit Trail

- EXTRACTED: 169 (96%)
- INFERRED: 7 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*