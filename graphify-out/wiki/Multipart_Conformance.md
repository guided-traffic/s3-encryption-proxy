# Multipart Conformance

> 31 nodes · cohesion 0.29

## Key Concepts

- **NewTestContextWithTimeout()** (93 connections) — `test/integration/minio_test_helper.go`
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
- *... and 6 more nodes in this community*

## Relationships

- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (35 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (25 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (18 shared connections)
- [DeleteObjects Conformance](DeleteObjects_Conformance.md) (10 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (10 shared connections)
- [ListObjects Conformance](ListObjects_Conformance.md) (8 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (8 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (8 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (7 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (5 shared connections)
- [Tampering Harness](Tampering_Harness.md) (5 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (3 shared connections)

## Source Files

- `test/integration/minio_test_helper.go`
- `test/integration/s3-methods/multipart_conformance_test.go`

## Audit Trail

- EXTRACTED: 277 (98%)
- INFERRED: 6 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*