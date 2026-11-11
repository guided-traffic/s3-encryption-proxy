# Segment Seal and Trailer

> 38 nodes · cohesion 0.08

## Key Concepts

- **Checksum** (26 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **Codec** (15 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **SealedPart** (13 connections) — `internal/orchestration/segmented.go`
- **SegmentedUpload** (9 connections) — `internal/orchestration/segmented.go`
- **.Append()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **PartStoredLen()** (5 connections) — `internal/orchestration/segmented.go`
- **objectTail** (5 connections) — `internal/proxy/handlers/object/tail.go`
- **.BodyWithTrailer()** (5 connections) — `internal/orchestration/segmented.go`
- **.Complete()** (5 connections) — `internal/orchestration/segmented_session.go`
- **.SealPart()** (5 connections) — `internal/orchestration/segmented.go`
- **Codec** (5 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.Checksum()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Body()** (4 connections) — `internal/orchestration/segmented.go`
- **.SealStreamingPart()** (4 connections) — `internal/orchestration/segmented.go`
- **.Checksum()** (4 connections) — `internal/orchestration/segmented.go`
- **crc32Combine()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **FinalPart** (3 connections) — `internal/orchestration/segmented_session.go`
- **.Checksum()** (3 connections) — `internal/orchestration/segmented.go`
- **.Trailer()** (3 connections) — `internal/orchestration/segmented.go`
- **gf2MatrixSquare()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixTimes()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.openTrailer()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.OpenTrailerForTest()** (2 connections) — `pkg/encryption/dataencryption/export_test.go`
- **.SealTrailer()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- *... and 13 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (10 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (8 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (7 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (7 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (4 shared connections)
- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (3 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (2 shared connections)
- [Dataencryption: Segmented Gcm Io (2)](Dataencryption-_Segmented_Gcm_Io_2.md) (2 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (2 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (2 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (1 shared connections)
- [Multipart Checksum Answers](Multipart_Checksum_Answers.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `internal/orchestration/segmented_session.go`
- `internal/proxy/handlers/object/tail.go`
- `pkg/encryption/dataencryption/export_test.go`
- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 91 (86%)
- INFERRED: 15 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*