# ListObjects Conformance Tests

> 28 nodes · cohesion 0.17

## Key Concepts

- **listobjects_conformance_test.go** (21 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstNewFixtureContext()** (15 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **.cleanup()** (12 connections) — `internal/orchestration/streaming_io.go`
- **LstKeysOf()** (10 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstSetup()** (9 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2XMLEscaping()** (8 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2MatchesMinIO()** (7 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2SizeIsCiphertextDeviation()** (7 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstNewRecordingClient()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV1MatchesMinIO()** (6 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstFixture** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsResponseDocumentDeviation()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2EncodingTypeIgnoredDeviation()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2MaxKeysZeroIgnoredDeviation()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2Pagination()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2StartAfterIgnoredDeviation()** (5 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstRecorder** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstRecordingTransport** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstBody()** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstPrefixesOf()** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **LstSizeOf()** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **TestLstListObjectsV2FetchOwnerIgnoredDeviation()** (4 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **.RoundTrip()** (3 connections) — `test/integration/s3-methods/listobjects_conformance_test.go`
- **github.com/aws/aws-sdk-go-v2/service/s3/types.Object** (2 connections)
- **.Close()** (2 connections) — `internal/orchestration/streaming_io.go`
- *... and 3 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (14 shared connections)
- [Range Read Integration Tests](Range_Read_Integration_Tests.md) (7 shared connections)
- [Streaming Encryption Readers](Streaming_Encryption_Readers.md) (3 shared connections)
- [Encryption At Rest Tests](Encryption_At_Rest_Tests.md) (3 shared connections)
- [S3 Backend Interface Types](S3_Backend_Interface_Types.md) (2 shared connections)
- [AES and RSA Provider Tests](AES_and_RSA_Provider_Tests.md) (2 shared connections)
- [Object Header Conformance Tests](Object_Header_Conformance_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [AWS Chunked Body Tests](AWS_Chunked_Body_Tests.md) (1 shared connections)
- [HMAC and DEK Cache Tests](HMAC_and_DEK_Cache_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/streaming_io.go`
- `test/integration/s3-methods/listobjects_conformance_test.go`

## Audit Trail

- EXTRACTED: 91 (91%)
- INFERRED: 9 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*