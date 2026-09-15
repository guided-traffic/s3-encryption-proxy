# Checksum

> 5 nodes · cohesion 0.50

## Key Concepts

- **ChkverifyingParser()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **ChkpayloadHash()** (5 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsVerifiedBesideAnotherDigest()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsVerifiedWhenConfigured()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashNeverSatisfiesTheDeleteObjectsRule()** (4 connections) — `internal/proxy/request/checksum_test.go`

## Relationships

- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (6 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Replication and ACL Handlers](Replication_and_ACL_Handlers.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (1 shared connections)
- [Checksum](Checksum.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`

## Audit Trail

- EXTRACTED: 16 (84%)
- INFERRED: 3 (16%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*