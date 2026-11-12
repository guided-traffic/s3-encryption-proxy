# Request: Parser Test

> 26 nodes · cohesion 0.14

## Key Concepts

- **testParser()** (23 connections) — `internal/proxy/request/parser_test.go`
- **randomPayload()** (14 connections) — `internal/proxy/request/parser_test.go`
- **newChunkedRequest()** (12 connections) — `internal/proxy/request/framing_test.go`
- **mustStream()** (7 connections) — `internal/proxy/request/helpers_test.go`
- **TestReqStreamingReader_PassThrough()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_And_StreamingReader_Agree()** (6 connections) — `internal/proxy/request/parser_test.go`
- **TestStreamingReader_AWSChunkedFramings()** (6 connections) — `internal/proxy/request/parser_test.go`
- **newTestRequest()** (5 connections) — `internal/proxy/request/helpers_test.go`
- **TestReqReadBody_ForgedDecodedContentLength()** (5 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_AWSChunkedFramings()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_AWSChunkedIsAlwaysDecoded()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_ReadsBodyOnce()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReqDecodedVsPlaintextContentLength_DivergeOnlyWhereDocumented()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqPlaintextContentLength()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqStreamingReader_MalformedFramingErrors()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_AWSChunked_PayloadContainsCRLF()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_IdentityBody()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestStreamingReader_NilBody()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestIsAWSChunkedRequest_Headers()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **TestReqReadBody_IdentityBodyReadError()** (3 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadBody_ZeroLengthBody()** (3 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestDecodedContentLength()** (3 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_AWSChunked_MalformedFraming()** (3 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_NilBody()** (3 connections) — `internal/proxy/request/parser_test.go`
- **TestResetBody()** (3 connections) — `internal/proxy/request/parser_test.go`
- *... and 1 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (26 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (24 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/request/framing_test.go`
- `internal/proxy/request/helpers_test.go`
- `internal/proxy/request/parser_coverage_test.go`
- `internal/proxy/request/parser_test.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`

## Audit Trail

- EXTRACTED: 72 (70%)
- INFERRED: 31 (30%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*