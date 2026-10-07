# Checksum

> 19 nodes · cohesion 0.18

## Key Concepts

- **checksum.go** (16 connections) — `internal/proxy/request/checksum.go`
- **declaredChecksums()** (10 connections) — `internal/proxy/request/checksum.go`
- **DeclaresChecksum()** (7 connections) — `internal/proxy/request/checksum.go`
- **checksumReader** (6 connections) — `internal/proxy/request/checksum.go`
- **declaration** (5 connections) — `internal/proxy/request/checksum.go`
- **hash.Hash** (4 connections)
- **declaredPayloadHash()** (4 connections) — `internal/proxy/request/checksum.go`
- **decodeDigest()** (4 connections) — `internal/proxy/request/checksum.go`
- **checksumAlgorithm** (4 connections) — `internal/proxy/request/checksum.go`
- **.finish()** (4 connections) — `internal/proxy/request/checksum.go`
- **TestChkPayloadHashIgnoresEverythingThatIsNotADigest()** (3 connections) — `internal/proxy/request/checksum_test.go`
- **ChecksumError** (3 connections) — `internal/proxy/request/checksum.go`
- **malformed()** (2 connections) — `internal/proxy/request/checksum.go`
- **mismatch()** (2 connections) — `internal/proxy/request/checksum.go`
- **Verdict()** (2 connections) — `internal/proxy/request/checksum.go`
- **.Read()** (2 connections) — `internal/proxy/request/checksum.go`
- **.Error()** (1 connections) — `internal/proxy/request/checksum.go`
- **.Unwrap()** (1 connections) — `internal/proxy/request/checksum.go`
- **.Verdict()** (1 connections) — `internal/proxy/request/checksum.go`

## Relationships

- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (6 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (3 shared connections)
- [Crc64nvme](Crc64nvme.md) (2 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)
- [Streaming Aws Decoder](Streaming_Aws_Decoder.md) (1 shared connections)
- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (1 shared connections)
- [Error Conventions](Error_Conventions.md) (1 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (1 shared connections)
- [Payload Hash Verification Tests](Payload_Hash_Verification_Tests.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum.go`
- `internal/proxy/request/checksum_test.go`

## Audit Trail

- EXTRACTED: 46 (90%)
- INFERRED: 5 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*