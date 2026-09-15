# Checksum Verifier Tests

> 31 nodes · cohesion 0.24

## Key Concepts

- **checksum_test.go** (41 connections) — `internal/proxy/request/checksum_test.go`
- **chkParser()** (23 connections) — `internal/proxy/request/checksum_test.go`
- **chkPayload()** (19 connections) — `internal/proxy/request/checksum_test.go`
- **chkEncode()** (15 connections) — `internal/proxy/request/checksum_test.go`
- **chkIdentityRequest()** (14 connections) — `internal/proxy/request/checksum_test.go`
- **chkChunkedRequest()** (10 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerBlockIsBounded()** (9 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkAWSChunkedIsAlwaysDecoded()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkHeaderDigestsAreVerified()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerDigestsAreVerified()** (8 connections) — `internal/proxy/request/checksum_test.go`
- **BenchmarkChkVerifyingRead()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **chkFramed()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkHeaderAndTrailerForOneAlgorithm()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkRepeatedTrailerDeclarationHeaders()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerWithoutFinalCRLFIsCaptured()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkAlgorithmNameHeadersAreNotDigests()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSeveralAlgorithmsAtOnce()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSHA512AndAmzMD5AreVerified()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkSmallReadSizes()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTheLastByteIsHeldUntilTheVerdict()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkTrailerSignatureIsNotAChecksum()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkUnimplementedAlgorithmIsRefused()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkUnimplementedTrailerAlgorithmIsRefused()** (6 connections) — `internal/proxy/request/checksum_test.go`
- **writeChunks()** (6 connections) — `internal/proxy/request/framing_test.go`
- **TestChkChecksumControlHeadersAreNotRefused()** (5 connections) — `internal/proxy/request/checksum_test.go`
- *... and 6 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (22 shared connections)
- [Checksum](Checksum.md) (12 shared connections)
- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (5 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (4 shared connections)
- [Crc64nvme](Crc64nvme.md) (3 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Performance](Performance.md) (1 shared connections)
- [Exec](Exec.md) (1 shared connections)
- [Request Parser and Framing Tests](Request_Parser_and_Framing_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`
- `internal/proxy/request/framing_test.go`

## Audit Trail

- EXTRACTED: 148 (91%)
- INFERRED: 15 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*