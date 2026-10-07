# Payload Hash Verification Tests

> 6 nodes · cohesion 0.40

## Key Concepts

- **ChkverifyingParser()** (7 connections) — `internal/proxy/request/checksum_test.go`
- **ChkpayloadHash()** (5 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsNotVerifiedUnlessConfigured()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsVerifiedBesideAnotherDigest()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashIsVerifiedWhenConfigured()** (4 connections) — `internal/proxy/request/checksum_test.go`
- **TestChkPayloadHashNeverSatisfiesTheDeleteObjectsRule()** (4 connections) — `internal/proxy/request/checksum_test.go`

## Relationships

- [Checksum Verifier Tests](Checksum_Verifier_Tests.md) (7 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (5 shared connections)
- [Bucket ACL and Accelerate Handlers](Bucket_ACL_and_Accelerate_Handlers.md) (1 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (1 shared connections)
- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (1 shared connections)
- [Checksum](Checksum.md) (1 shared connections)

## Source Files

- `internal/proxy/request/checksum_test.go`

## Audit Trail

- EXTRACTED: 19 (86%)
- INFERRED: 3 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*