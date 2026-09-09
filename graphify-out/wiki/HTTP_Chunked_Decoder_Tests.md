# HTTP Chunked Decoder Tests

> 13 nodes · cohesion 0.31

## Key Concepts

- **NewHTTPChunkedDecoder()** (15 connections) — `internal/proxy/request/http_chunked_decoder.go`
- **http_chunked_decoder_coverage_test.go** (12 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_CreateOptimalReader()** (7 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **ReqbuildHTTPChunked()** (6 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_RoundTrip()** (6 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ImplementsInterface()** (5 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_PayloadLooksLikeFraming()** (5 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_RequiresChunkedDecoding()** (5 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_GetName()** (4 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_Malformed()** (4 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_MissingTrailingCRLF()** (4 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_NoHugePreallocation()** (4 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`
- **TestReqHTTPChunkedDecoder_ProcessChunkedData_Terminators()** (4 connections) — `internal/proxy/request/http_chunked_decoder_coverage_test.go`

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (10 shared connections)
- [Streaming AWS Chunked Decoder Tests](Streaming_AWS_Chunked_Decoder_Tests.md) (10 shared connections)
- [Request Body Parser Tests](Request_Body_Parser_Tests.md) (6 shared connections)
- [HTTP Chunked Decoder](HTTP_Chunked_Decoder.md) (4 shared connections)
- [Content Length Helper Tests](Content_Length_Helper_Tests.md) (1 shared connections)
- [Multipart Handler Construction](Multipart_Handler_Construction.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)

## Source Files

- `internal/proxy/request/http_chunked_decoder.go`
- `internal/proxy/request/http_chunked_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 29 (51%)
- INFERRED: 28 (49%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*