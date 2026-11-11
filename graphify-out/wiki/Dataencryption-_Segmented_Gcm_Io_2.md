# Dataencryption: Segmented Gcm Io (2)

> 7 nodes · cohesion 0.48

## Key Concepts

- **reader** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.fill()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.consumeTail()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.openInto()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Checksum()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Relationships

- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (2 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm_io.go`

## Audit Trail

- EXTRACTED: 11 (73%)
- INFERRED: 4 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*