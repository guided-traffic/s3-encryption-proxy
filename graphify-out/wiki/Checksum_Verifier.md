# Checksum Verifier

> 48 nodes · cohesion 0.11

## Key Concepts

- **chkParser()** (23 connections) — `internal/proxy/request/checksum_test.go`
- **chkPayload()** (19 connections) — `internal/proxy/request/checksum_test.go`
- **chkEncode()** (15 connections) — `internal/proxy/request/checksum_test.go`
- **chkIdentityRequest()** (14 connections) — `internal/proxy/request/checksum_test.go`
- **UtlCaptureLogger()** (12 connections) — `internal/proxy/response/errors_coverage_test.go`
- **chkChunkedRequest()** (10 connections) — `internal/proxy/request/checksum_test.go`
- **UtlDecodeLog()** (10 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlParseErrorBody()** (10 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestChkTrailerBlockIsBounded()** (9 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerDigestsAreVerified()** (9 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkAWSChunkedIsAlwaysDecoded()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkHeaderDigestsAreVerified()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **TestRespWriteS3Error_DoesNotLeakBackendDetail()** (8 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_StatusDrivesLogLevel()** (8 connections) — `internal/proxy/response/errors_coverage_test.go`
- **UtlFindLog()** (8 connections) — `internal/proxy/response/errors_coverage_test.go`
- **BenchmarkChkVerifyingRead()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **chkFramed()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkHeaderAndTrailerForOneAlgorithm()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkRepeatedTrailerDeclarationHeaders()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSHA512AndAmzMD5AreVerified()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerWithoutFinalCRLFIsCaptured()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestRespWriteS3Error_InternalTextStaysInternal()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_NilError()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_ResourceComposition()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- **TestRespWriteS3Error_WriteFailureIsLogged()** (7 connections) — `internal/proxy/response/errors_coverage_test.go`
- *... and 23 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (45 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (32 shared connections)
- [Sub-Resource Handler Tests](Sub-Resource_Handler_Tests.md) (11 shared connections)
- [Request: Streaming Decoder Coverage Test](Request-_Streaming_Decoder_Coverage_Test.md) (6 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (4 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (3 shared connections)
- [Request Middleware Plumbing](Request_Middleware_Plumbing.md) (2 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)
- [S3 Methods: Sealed Checksum Test](S3_Methods-_Sealed_Checksum_Test.md) (1 shared connections)
- [Multipart Handlers and Manager](Multipart_Handlers_and_Manager.md) (1 shared connections)
- [S3Enc: Helpers Test](S3Enc-_Helpers_Test.md) (1 shared connections)
- [Bucket XML Documents](Bucket_XML_Documents.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/framing_test.go`
- `internal/proxy/response/errors_coverage_test.go`
- `test/e2e/harness/exec.go`

## Audit Trail

- EXTRACTED: 203 (89%)
- INFERRED: 26 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*