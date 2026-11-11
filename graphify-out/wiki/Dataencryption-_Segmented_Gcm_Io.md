# Dataencryption: Segmented Gcm Io

> 9 nodes · cohesion 0.39

## Key Concepts

- **Writer** (13 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.flushSegment()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.FinishPart()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.sealFrom()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Write()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.tracksChecksum()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **Codec** (1 connections)

## Relationships

- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (4 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (1 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 15 (71%)
- INFERRED: 6 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*