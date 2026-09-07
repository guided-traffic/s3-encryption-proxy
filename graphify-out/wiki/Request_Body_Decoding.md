# Request Body Decoding

> 129 nodes · cohesion 0.04

## Key Concepts

- **.ReadBody()** (38 connections) — `internal/proxy/request/parser.go`
- **testLogger()** (29 connections) — `internal/proxy/handlers/bucket/test_helpers_test.go`
- **testParser()** (27 connections) — `internal/proxy/request/parser_test.go`
- **request.(*Parser).ReadBody** (26 connections) — `internal/proxy/request/parser.go`
- **newStreamingAWSChunkedReader()** (23 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **parser_test.go** (19 connections) — `internal/proxy/request/parser_test.go`
- **randomPayload()** (19 connections) — `internal/proxy/request/parser_test.go`
- **NewHTTPChunkedDecoder()** (14 connections) — `internal/proxy/request/http_chunked_decoder.go`
- **isAWSChunkedRequest()** (14 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **parser_coverage_test.go** (13 connections) — `internal/proxy/request/parser_coverage_test.go`
- **streaming_decoder_coverage_test.go** (13 connections) — `internal/proxy/request/streaming_decoder_coverage_test.go`
- **http_chunked_decoder_coverage_test.go** (12 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **.ProcessChunkedData()** (12 connections) — `internal/proxy/request/http_chunked_decoder.go`
- **newChunkedRequest()** (11 connections) — `internal/proxy/request/framing_test.go`
- **ProcessChunkedData (buffered decode)** (11 connections) — `internal/proxy/request/http_chunked_decoder.go`
- **readAllSized()** (10 connections) — `internal/proxy/request/parser.go`
- **request.Parser.StreamingReader** (10 connections) — `internal/proxy/request/parser.go`
- **.StreamingReader()** (10 connections) — `internal/proxy/request/parser.go`
- **streamingAWSChunkedReader.Read** (10 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **TestReqHTTPChunkedDecoder_CreateOptimalReader()** (9 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReadBody_And_StreamingReader_Agree()** (9 connections) — `internal/proxy/request/parser_test.go`
- **readChunkHeader (hex size, trailer drain)** (9 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **ReqbuildHTTPChunked()** (8 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_Malformed()** (8 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_RoundTrip()** (8 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- *... and 104 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/internal/proxy/request/helpers_test.go`
- `internal/proxy/handlers/bucket/test_helpers_test.go`
- `internal/proxy/middleware/s3auth_robust.go`
- `internal/proxy/request/chunked_decoder.go`
- `internal/proxy/request/framing_test.go`
- `internal/proxy/request/http_chunked_decoder.go`
- `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/parser_coverage_test.go`
- `internal/proxy/request/parser_test.go`
- `internal/proxy/request/request_decoder.go`
- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`
- `internal/proxy/request/streaming_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 418 (50%)
- INFERRED: 411 (50%)
- AMBIGUOUS: 1 (0%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*