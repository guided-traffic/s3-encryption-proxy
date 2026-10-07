# Multipart Conformance Suite

> 39 nodes · cohesion 0.20

## Key Concepts

- **NewTestContextWithTimeout()** (80 connections) — `test/integration/minio_test_helper.go`
- **multipart_conformance_test.go** (27 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuTargets()** (18 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuCreate()** (16 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuThreePartRoundTrip()** (15 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuKey()** (14 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuPartsUploadedOutOfOrder()** (14 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuComplete()** (13 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuPart()** (13 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuHeldPartResentAtStreamingSize()** (13 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuPayload()** (12 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuAbortRemovesTheUpload()** (12 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuCompleteWithBadPartReferences()** (12 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuCompleteWithPartsOutOfOrder()** (12 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuInspect()** (11 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuCompleteWithEmptyPartList()** (11 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuListParts()** (11 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuPartTooSmallInNonFinalPosition()** (11 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuPartRef()** (9 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuListMultipartUploads()** (9 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuUploadPartWithInvalidPartNumber()** (8 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestMpuUploadPartWithUnknownUploadID()** (8 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuTarget** (7 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuGetBody()** (7 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **TestRangeReadErrors()** (5 connections) — `test/integration/360-degree-variants/range_read_test.go`
- *... and 14 more nodes in this community*

## Relationships

- [AWS-Chunked Reader Tests](AWS-Chunked_Reader_Tests.md) (28 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (23 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (10 shared connections)
- [Integration Failing Writer Fixtures](Integration_Failing_Writer_Fixtures.md) (10 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (8 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (7 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (7 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (5 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (5 shared connections)
- [Performance](Performance.md) (4 shared connections)
- [Conditional Requests](Conditional_Requests.md) (3 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (3 shared connections)

## Source Files

- `test/integration/360-degree-variants/range_read_test.go`
- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/multipart_conformance_test.go`
- `test/integration/s3-methods/object_metadata_consistency_test.go`

## Audit Trail

- EXTRACTED: 258 (98%)
- INFERRED: 5 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*