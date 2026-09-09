# Multipart Session Tests

> 68 nodes · cohesion 0.13

## Key Concepts

- **OrcPartAESConfig()** (48 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **OrcPartPayload()** (42 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **OrcPartNewMultipartOps()** (33 connections) — `internal/orchestration/multipart_coverage_test.go`
- **singlepart_coverage_test.go** (33 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **OrcPartReader()** (32 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **orchestration/multipart_coverage_test.go** (30 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcPartInitiate()** (27 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcPartNewManager()** (26 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **OrcPartProcessPart()** (16 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcPartSHA256()** (13 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **TestOrcPartMultipartHMACCoversPartsInAscendingOrder()** (12 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcPartEncryptGCMBytes()** (10 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **TestOrcPartDecryptDataWithMetadataClosesTheBackendBody()** (10 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **TestOrcPartDecryptMultipartWithoutHMACMode()** (9 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartMultipartLifecycleRoundTrip()** (9 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartMultipartTamperedPartIsRejected()** (9 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartRetriedPartNumberParksUntilTheSessionEnds()** (9 connections) — `internal/orchestration/multipart_coverage_test.go`
- **OrcPartEncryptCTRBytes()** (9 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **TestOrcPartDecryptGCMStreamVerifiesAttachedHMAC()** (9 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **TestOrcPartDecryptMultipartRejectsBrokenMetadata()** (8 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartDecryptMultipartWithAnEmptyUnwrappedDEK()** (8 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartFailedPartStrandsTheBufferedFollowers()** (8 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartPendingPartsAreReleasedByEveryTeardownPath()** (8 connections) — `internal/orchestration/multipart_coverage_test.go`
- **TestOrcPartDecryptGCMStreamWithoutHMACSkipsVerification()** (8 connections) — `internal/orchestration/singlepart_coverage_test.go`
- **TestOrcPartEmptyMetadataPrefixServesCiphertextAsPlaintext()** (8 connections) — `internal/orchestration/singlepart_coverage_test.go`
- *... and 43 more nodes in this community*

## Relationships

- [Config Accessor Tests](Config_Accessor_Tests.md) (55 shared connections)
- [Multipart Session State](Multipart_Session_State.md) (7 shared connections)
- [Configuration Accessors](Configuration_Accessors.md) (4 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (2 shared connections)
- [HMAC Manager Tests](HMAC_Manager_Tests.md) (1 shared connections)
- [DEK Cache and Providers](DEK_Cache_and_Providers.md) (1 shared connections)
- [Encryption Metadata Management](Encryption_Metadata_Management.md) (1 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [Manager Construction Tests](Manager_Construction_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/multipart_coverage_test.go`
- `internal/orchestration/singlepart_coverage_test.go`

## Audit Trail

- EXTRACTED: 305 (81%)
- INFERRED: 71 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*