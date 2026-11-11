# Request: Streaming Decoder Coverage Test

> 25 nodes · cohesion 0.14

## Key Concepts

- **newStreamingAWSChunkedReader()** (25 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **testLogger()** (24 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **ChkverifyingParser()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **ChkpayloadHash()** (5 connections) — `internal/proxy/request/checksum_test.go`
- **TestStreamingAWSChunkedReader_RoundTrip()** (5 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestStreamingAWSChunkedReader_SmallReads()** (5 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestReqStreamingAWSChunkedReader_OversizedDestinationBuffer()** (5 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestChkPayloadHashIsNotVerifiedUnlessConfigured()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsVerifiedBesideAnotherDigest()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsVerifiedWhenConfigured()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashNeverSatisfiesTheDeleteObjectsRule()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestStreamingAWSChunkedReader_Errors()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestStreamingAWSChunkedReader_MultipleTrailers()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestStreamingAWSChunkedReader_SizeMismatch()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestReqStreamingAWSChunkedReader_BlankLineBetweenChunks()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_BlankLineThenEOF()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_BlankLineThenInvalidSize()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_ChunkHeaderVariants()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_ChunkTerminatorErrors()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_EmptyDestinationBuffer()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_NegativeChunkSize()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_ReadAfterEOF()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_TrailerDrain()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_TruncationIsUnexpectedEOF()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **TestReqStreamingAWSChunkedReader_UpstreamErrorPropagates()** (4 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (25 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (22 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (6 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (3 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (3 shared connections)
- [Request: Parser Test](Request-_Parser_Test.md) (3 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)
- [Request: Streaming Aws Decoder](Request-_Streaming_Aws_Decoder.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`
- `internal/proxy/request/streaming_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 65 (61%)
- INFERRED: 42 (39%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*