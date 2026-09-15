# ListObjects Conformance Fixtures

> 34 nodes · cohesion 0.15

## Key Concepts

- **listobjects_conformance_test.go** (32 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
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

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (25 shared connections)
- [Ranged Read and Passthrough Tests](Ranged_Read_and_Passthrough_Tests.md) (8 shared connections)
- [Multipart Conformance Suite](Multipart_Conformance_Suite.md) (8 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (7 shared connections)
- [S3 Method Error Mapping Tests](S3_Method_Error_Mapping_Tests.md) (7 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (7 shared connections)
- [Streaming Upload and Sealed Checksum](Streaming_Upload_and_Sealed_Checksum.md) (2 shared connections)
- [Authentication Integration Tests](Authentication_Integration_Tests.md) (2 shared connections)
- [Segmented GCM](Segmented_GCM.md) (1 shared connections)
- [Chunked Streaming Test Harness](Chunked_Streaming_Test_Harness.md) (1 shared connections)

## Source Files

- `test/integration/s3-methods/listobjects_conformance_test.go`

## Audit Trail

- EXTRACTED: 153 (99%)
- INFERRED: 1 (1%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*