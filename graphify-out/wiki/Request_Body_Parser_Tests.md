# Request Body Parser Tests

> 33 nodes · cohesion 0.15

## Key Concepts

- **testParser()** (28 connections) — `internal/proxy/request/parser_test.go`
- **parser_test.go** (19 connections) — `internal/proxy/request/parser_test.go`
- **randomPayload()** (19 connections) — `internal/proxy/request/parser_test.go`
- **newChunkedRequest()** (13 connections) — `internal/proxy/request/framing_test.go`
- **parser_coverage_test.go** (13 connections) — `internal/proxy/request/parser_coverage_test.go`
- **ReqnewTransferChunkedRequest()** (8 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqReadBody_HTTPTransferChunked()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_HTTPTransferChunkedDisabled()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqStreamingReader_PassThrough()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **readAllSized()** (6 connections) — `internal/proxy/request/parser.go`
- **TestReqReadBody_AWSChunkedTakesPrecedenceOverTransferEncoding()** (5 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_ForgedDecodedContentLength()** (5 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_And_StreamingReader_Agree()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_AWSChunkedDisabled()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_AWSChunkedFramings()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_ReadsBodyOnce()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestStreamingReader_AWSChunkedFramings()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReqReadAllSized_HintBoundaries()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_HTTPTransferChunkedBodyReadError()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_HTTPTransferChunkedMalformed()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_AWSChunked_PayloadContainsCRLF()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_IdentityBody()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestReqReadBody_IdentityBodyReadError()** (3 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_ZeroLengthBody()** (3 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqStreamingReader_MalformedFramingErrors()** (3 connections) — `internal/proxy/request/parser_coverage_test.go`
- *... and 8 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (29 shared connections)
- [HTTP Chunked Decoder Tests](HTTP_Chunked_Decoder_Tests.md) (6 shared connections)
- [Content Length Helper Tests](Content_Length_Helper_Tests.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Streaming AWS Chunked Decoder Tests](Streaming_AWS_Chunked_Decoder_Tests.md) (3 shared connections)
- [Chunk Framing Test Helpers](Chunk_Framing_Test_Helpers.md) (2 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (2 shared connections)
- [Failing Reader Test Fakes](Failing_Reader_Test_Fakes.md) (2 shared connections)
- [Bucket Sub-Resource Tests](Bucket_Sub-Resource_Tests.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)

## Source Files

- `internal/proxy/request/framing_test.go`
- `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/parser_coverage_test.go`
- `internal/proxy/request/parser_test.go`

## Audit Trail

- EXTRACTED: 89 (67%)
- INFERRED: 44 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*