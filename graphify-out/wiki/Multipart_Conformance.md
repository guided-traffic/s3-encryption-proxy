# Multipart Conformance

> 30 nodes · cohesion 0.28

## Key Concepts

- **multipart_conformance_test.go** (51 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuTargets()** (19 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
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
- **MpuDigest()** (4 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- **MpuShape** (3 connections) — `test/integration/s3-methods/multipart_conformance_test.go`
- *... and 5 more nodes in this community*

## Relationships

- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (24 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (23 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (17 shared connections)
- [Misc (15)](Misc_15.md) (4 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (4 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (3 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (2 shared connections)
- [Misc (3)](Misc_3.md) (1 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/multipart_conformance_test.go`

## Audit Trail

- EXTRACTED: 202 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*