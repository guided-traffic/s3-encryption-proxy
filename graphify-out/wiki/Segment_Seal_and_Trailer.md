# Segment Seal and Trailer

> 37 nodes · cohesion 0.08

## Key Concepts

- **Checksum** (26 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (15 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **SealedPart** (13 connections) — `internal/orchestration/segmented.go`
- **reader** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **SegmentedUpload** (9 connections) — `internal/orchestration/segmented.go`
- **PartStoredLen()** (5 connections) — `internal/orchestration/segmented.go`
- **objectTail** (5 connections) — `internal/proxy/handlers/object/tail.go`
- **.SealPart()** (5 connections) — `internal/orchestration/segmented.go`
- **Codec** (5 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.Checksum()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.SealStreamingPart()** (4 connections) — `internal/orchestration/segmented.go`
- **.Checksum()** (4 connections) — `internal/orchestration/segmented.go`
- **.OpenTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.consumeTail()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.openInto()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (3 connections) — `internal/orchestration/segmented.go`
- **.Trailer()** (3 connections) — `internal/orchestration/segmented.go`
- **.openTrailer()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealTrailer()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.sealTrailer()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.SealTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.Checksum()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- *... and 12 more nodes in this community*

## Relationships

- [Dataencryption: Segmented Gcm Range](Dataencryption-_Segmented_Gcm_Range.md) (7 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (7 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (7 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (4 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (3 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/proxy/handlers/object/tail.go`
- `pkg/encryption/dataencryption/export_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 88 (90%)
- INFERRED: 10 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*