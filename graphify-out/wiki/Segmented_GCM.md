# Segmented GCM

> 10 nodes · cohesion 0.27

## Key Concepts

- **CiphertextSize()** (21 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **PlaintextSize()** (7 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Invariant 2: The Stored Length Is a Pure Function of the Plaintext Length** (6 connections) — `docs/developer/storage-format.md`
- **SegmentSize** (6 connections) — `docs/developer/storage-format.md`
- **TestSegOversizeRefused()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSizeFunctionsRoundTrip()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **TestSegSizeGuardRejectsUnreachableLengths()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_test.go`
- **maxWindowOverAsk** (1 connections) — `docs/developer/storage-format.md`
- **SegmentOverhead** (1 connections) — `docs/developer/storage-format.md`
- **TrailerSize** (1 connections) — `docs/developer/storage-format.md`

## Relationships

- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (5 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (4 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (3 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Object GET Coverage Tests](Object_GET_Coverage_Tests.md) (2 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (2 shared connections)
- [Storage Format Invariants](Storage_Format_Invariants.md) (1 shared connections)
- [Bucket Handler Error Fixtures](Bucket_Handler_Error_Fixtures.md) (1 shared connections)
- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (1 shared connections)
- [Multipart Handler Constructors](Multipart_Handler_Constructors.md) (1 shared connections)
- [Checksum and ETag Echo Tests](Checksum_and_ETag_Echo_Tests.md) (1 shared connections)

## Source Files

- `docs/developer/storage-format.md`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_test.go`

## Audit Trail

- EXTRACTED: 33 (77%)
- INFERRED: 10 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*