# Checksum Verifier

> 54 nodes · cohesion 0.09

## Key Concepts

- **newStreamingAWSChunkedReader()** (25 connections) — `internal/proxy/request/streaming_aws_decoder.go`
- **testLogger()** (24 connections) — `internal/proxy/request/streaming_aws_decoder_test.go`
- **chkParser()** (23 connections) — `internal/proxy/request/checksum_test.go`
- **chkPayload()** (19 connections) — `internal/proxy/request/checksum_test.go`
- **chkEncode()** (15 connections) — `internal/proxy/request/checksum_test.go`
- **chkIdentityRequest()** (14 connections) — `internal/proxy/request/checksum_test.go`
- **chkChunkedRequest()** (10 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerBlockIsBounded()** (9 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerDigestsAreVerified()** (9 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkAWSChunkedIsAlwaysDecoded()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkHeaderDigestsAreVerified()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **BenchmarkChkVerifyingRead()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **chkFramed()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **ChkverifyingParser()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkHeaderAndTrailerForOneAlgorithm()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkRepeatedTrailerDeclarationHeaders()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSHA512AndAmzMD5AreVerified()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerWithoutFinalCRLFIsCaptured()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkAlgorithmNameHeadersAreNotDigests()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkNothingDeclaredIsNotWrapped()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSeveralAlgorithmsAtOnce()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSmallReadSizes()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTheLastByteIsHeldUntilTheVerdict()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerSignatureIsNotAChecksum()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkUnimplementedAlgorithmIsRefused()** (6 connections) — `internal/proxy/request/checksum_test.go`
- *... and 29 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (54 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (43 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (8 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (5 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (4 shared connections)
- [Request: Parser Test](Request-_Parser_Test.md) (3 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (2 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (1 shared connections)
- [S3Enc: Helpers Test](S3Enc-_Helpers_Test.md) (1 shared connections)
- [Keyencryption: Aes Test](Keyencryption-_Aes_Test.md) (1 shared connections)
- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (1 shared connections)
- [Request: Streaming Aws Decoder](Request-_Streaming_Aws_Decoder.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/framing_test.go`
- `internal/proxy/request/streaming_aws_decoder.go`
- `internal/proxy/request/streaming_aws_decoder_test.go`
- `internal/proxy/request/streaming_decoder_coverage_test.go`

## Audit Trail

- EXTRACTED: 197 (78%)
- INFERRED: 55 (22%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*