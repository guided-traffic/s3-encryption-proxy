# Streaming AWS Chunked Decoder Tests

> 23 nodes · cohesion 0.23

## Key Concepts

- **testLogger()** (29 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **newStreamingAWSChunkedReader()** (23 connections) — `internal/proxy/request/streaming_aws_decoder.go`
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

- [Config Accessor Tests](Config_Accessor_Tests.md) (17 shared connections)
- [HTTP Chunked Decoder Tests](HTTP_Chunked_Decoder_Tests.md) (10 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Request Body Parser Tests](Request_Body_Parser_Tests.md) (3 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [Streaming AWS Chunked Reader](Streaming_AWS_Chunked_Reader.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)

## Source Files

- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`
- `internal/proxy/request/streaming_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 51 (54%)
- INFERRED: 44 (46%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*