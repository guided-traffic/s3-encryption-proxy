# ListObjects Conformance

> 34 nodes · cohesion 0.15

## Key Concepts

- **listobjects_conformance_test.go** (64 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstNewRefFixture()** (12 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstPurgeBucket()** (12 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListingDocumentOnTheWire()** (12 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListingSizeMatchesHeadAndGet()** (11 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstPut()** (10 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListingEncodingTypeRoundTrip()** (10 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListingETagMatchesHeadAndGet()** (9 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListingUnderReportsForeignObjects()** (9 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstNewBulkFixture()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstHeadBucket()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstBody()** (7 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstProxyGet()** (7 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstRawRequest()** (7 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2MatchesMinIO()** (7 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstGet()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstKeysOf()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstListSizes()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstMultipartPut()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListingPagesAndFilters()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstCiphertextSize()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstListETags()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstPrefixesOf()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV1MatchesMinIO()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **lstBulkFixture** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- *... and 9 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (31 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (25 shared connections)
- [Chunked Encoding Tests](Chunked_Encoding_Tests.md) (11 shared connections)
- [Multipart Conformance](Multipart_Conformance.md) (8 shared connections)
- [Tampering Harness](Tampering_Harness.md) (7 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (7 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (3 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (2 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (2 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (1 shared connections)
- [S3 Methods: Range Conformance Test](S3_Methods-_Range_Conformance_Test.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/listobjects_conformance_test.go`

## Audit Trail

- EXTRACTED: 185 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*