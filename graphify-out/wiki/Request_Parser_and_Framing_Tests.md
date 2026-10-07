# Request Parser and Framing Tests

> 42 nodes · cohesion 0.10

## Key Concepts

- **testParser()** (23 connections) — `internal/proxy/request/parser_test.go`
- **parser_test.go** (19 connections) — `internal/proxy/request/parser_test.go`
- **randomPayload()** (14 connections) — `internal/proxy/request/parser_test.go`
- **newChunkedRequest()** (12 connections) — `internal/proxy/request/framing_test.go`
- **parser_coverage_test.go** (9 connections) — `internal/proxy/request/parser_coverage_test.go`
- **mustStream()** (7 connections) — `internal/proxy/request/helpers_test.go`
- **readAllSized()** (7 connections) — `internal/proxy/request/parser.go`
- **TestReqStreamingReader_PassThrough()** (6 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_And_StreamingReader_Agree()** (6 connections) — `internal/proxy/request/parser_test.go`
- **TestStreamingReader_AWSChunkedFramings()** (6 connections) — `internal/proxy/request/parser_test.go`
- **framing_test.go** (5 connections) — `internal/proxy/request/framing_test.go`
- **newTestRequest()** (5 connections) — `internal/proxy/request/helpers_test.go`
- **TestReqReadBody_ForgedDecodedContentLength()** (5 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_AWSChunkedFramings()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_AWSChunkedIsAlwaysDecoded()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_ReadsBodyOnce()** (5 connections) — `internal/proxy/request/parser_test.go`
- **TestReqDecodedVsPlaintextContentLength_DivergeOnlyWhereDocumented()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqPlaintextContentLength()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadAllSized_HintBoundaries()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqReadDocumentAppliesTheConfiguredCeiling()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReqStreamingReader_MalformedFramingErrors()** (4 connections) — `internal/proxy/request/parser_coverage_test.go`
- **TestReadBody_AWSChunked_PayloadContainsCRLF()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestReadBody_IdentityBody()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestStreamingReader_NilBody()** (4 connections) — `internal/proxy/request/parser_test.go`
- **TestIsAWSChunkedRequest_Headers()** (4 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- *... and 17 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (28 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (5 shared connections)
- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (4 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (2 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (1 shared connections)
- [ListBuckets Coverage Tests](ListBuckets_Coverage_Tests.md) (1 shared connections)
- [Upload Length Guards and Exit Provider](Upload_Length_Guards_and_Exit_Provider.md) (1 shared connections)

## Source Files

- `internal/proxy/request/framing_test.go`
- `internal/proxy/request/helpers_test.go`
- `internal/proxy/request/parser.go`
- `internal/proxy/request/parser_coverage_test.go`
- `internal/proxy/request/parser_test.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`

## Audit Trail

- EXTRACTED: 94 (72%)
- INFERRED: 37 (28%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*