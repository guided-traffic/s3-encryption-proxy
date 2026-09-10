# Request Parser Tests

> 90 nodes · cohesion 0.05

## Key Concepts

- **testParser()** (28 connections) — `internal/proxy/request/parser_test.go`
- **testLogger()** (27 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **newStreamingAWSChunkedReader()** (23 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **parser_test.go** (18 connections) — `internal/proxy/request/parser_test.go`
- **randomPayload()** (18 connections) — `internal/proxy/request/parser_test.go`
- **newChunkedRequest()** (13 connections) — `internal/proxy/request/framing_test.go`
- **NewHTTPChunkedDecoder()** (13 connections) — `internal/proxy/request/http_chunked_decoder.go`
- **parser_coverage_test.go** (13 connections) — `internal/proxy/request/parser_coverage_test.go`
- **streaming_decoder_coverage_test.go** (13 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **http_chunked_decoder_coverage_test.go** (10 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **ReqnewTransferChunkedRequest()** (7 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **streaming_aws_decoder_test.go** (7 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **newTestRequest()** (6 connections) — `internal/proxy/request/helpers_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_RoundTrip()** (6 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqReadBody_HTTPTransferChunked()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_HTTPTransferChunkedDisabled()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqStreamingReader_PassThrough()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **readAllSized()** (6 connections) — `internal/proxy/request/parser.go`
- **TestReqStreamingAWSChunkedReader_OversizedDestinationBuffer()** (6 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **HTTPChunkedDecoder** (6 connections) — `internal/proxy/request/http_chunked_decoder.go`
- **NewChunkedDecoderBase()** (5 connections) — `internal/proxy/request/chunked_decoder.go`
- **framing_test.go** (5 connections) — `internal/proxy/request/framing_test.go`
- **ReqbuildHTTPChunked()** (5 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ImplementsInterface()** (5 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_PayloadLooksLikeFraming()** (5 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- *... and 65 more nodes in this community*

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (56 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (10 shared connections)
- [Multipart Handler](Multipart_Handler.md) (7 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (3 shared connections)
- [Bucket NotImplemented Tests](Bucket_NotImplemented_Tests.md) (2 shared connections)
- [Proxy Server Tests](Proxy_Server_Tests.md) (1 shared connections)
- [AWS-Chunked Decoder](AWS-Chunked_Decoder.md) (1 shared connections)

## Source Files

- `internal/proxy/request/chunked_decoder.go`
- `internal/proxy/request/framing_test.go`
- `internal/proxy/request/helpers_test.go`
- `internal/proxy/request/http_chunked_decoder.go`
- `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/parser_coverage_test.go`
- `internal/proxy/request/parser_test.go`
- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`
- `internal/proxy/request/streaming_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 188 (66%)
- INFERRED: 97 (34%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*