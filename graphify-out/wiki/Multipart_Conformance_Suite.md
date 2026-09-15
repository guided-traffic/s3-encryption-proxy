# Multipart Conformance Suite

> 36 nodes · cohesion 0.23

## Key Concepts

- **NewTestContextWithTimeout()** (93 connections) — `test/integration/minio_test_helper.go`
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
- **TestAWSChunkedIsNotStoredAsContentEncoding()** (5 connections) — `test/integration/s3-methods/object_metadata_consistency_test.go`
- *... and 11 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (21 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (17 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (15 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (13 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (10 shared connections)
- [DeleteObjects Batch Documents](DeleteObjects_Batch_Documents.md) (10 shared connections)
- [Encryption-at-Rest Assertions](Encryption-at-Rest_Assertions.md) (10 shared connections)
- [ListObjects Conformance Fixtures](ListObjects_Conformance_Fixtures.md) (8 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (7 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (5 shared connections)
- [Performance](Performance.md) (4 shared connections)
- [Conditional Requests](Conditional_Requests.md) (3 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/multipart_conformance_test.go`
- `test/integration/s3-methods/object_metadata_consistency_test.go`

## Audit Trail

- EXTRACTED: 264 (98%)
- INFERRED: 5 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*