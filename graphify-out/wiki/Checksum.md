# Checksum

> 18 nodes · cohesion 0.19

## Key Concepts

- **checksum.go** (14 connections) — `internal/proxy/request/checksum.go`
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
- **.Read()** (2 connections) — `internal/proxy/request/checksum.go`
- **.Error()** (1 connections) — `internal/proxy/request/checksum.go`
- **.Unwrap()** (1 connections) — `internal/proxy/request/checksum.go`
- **.Verdict()** (1 connections) — `internal/proxy/request/checksum.go`

## Relationships

- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (6 shared connections)
- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (3 shared connections)
- [Crc64nvme](Crc64nvme.md) (2 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (2 shared connections)
- [Multipart Semantics and ETag Marker](Multipart_Semantics_and_ETag_Marker.md) (1 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (1 shared connections)
- [Response Header Helpers](Response_Header_Helpers.md) (1 shared connections)
- [Checksum](Checksum.md) (1 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum.go`
- `internal/proxy/request/checksum_test.go`

## Audit Trail

- EXTRACTED: 43 (90%)
- INFERRED: 5 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*