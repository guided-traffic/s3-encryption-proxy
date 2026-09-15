# aws-chunked Streaming Decoder

> 23 nodes · cohesion 0.23

## Key Concepts

- **newStreamingAWSChunkedReader()** (25 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **testLogger()** (24 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **streaming_decoder_coverage_test.go** (13 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **streaming_aws_decoder_test.go** (7 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestReqStreamingAWSChunkedReader_OversizedDestinationBuffer()** (6 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestStreamingAWSChunkedReader_RoundTrip()** (5 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestStreamingAWSChunkedReader_SmallReads()** (5 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestReqStreamingAWSChunkedReader_EmptyDestinationBuffer()** (5 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_ReadAfterEOF()** (5 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestStreamingAWSChunkedReader_Errors()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestStreamingAWSChunkedReader_MultipleTrailers()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestStreamingAWSChunkedReader_SizeMismatch()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestReqStreamingAWSChunkedReader_BlankLineBetweenChunks()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_BlankLineThenEOF()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_BlankLineThenInvalidSize()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_ChunkHeaderVariants()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_ChunkTerminatorErrors()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_NegativeChunkSize()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_TrailerDrain()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_TruncationIsUnexpectedEOF()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_UpstreamErrorPropagates()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **.Read()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **ReqfailAfterReader** (2 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (17 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (5 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (4 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (2 shared connections)
- [Streaming Aws Decoder](Streaming_Aws_Decoder.md) (2 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (1 shared connections)
- [Checksum](Checksum.md) (1 shared connections)

## Source Files

- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`
- `internal/proxy/request/streaming_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 52 (57%)
- INFERRED: 40 (43%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*