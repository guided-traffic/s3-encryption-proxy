# CRC32C Combine Math

> 4 nodes · cohesion 0.67

## Key Concepts

- **.Append()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **crc32Combine()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixSquare()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **gf2MatrixTimes()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (3 shared connections)
- [Segment Seal and Trailer](Segment_Seal_and_Trailer.md) (1 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (1 shared connections)
- [Object: Storage Headers](Object-_Storage_Headers.md) (1 shared connections)
- [Orchestration: Segmented Session](Orchestration-_Segmented_Session.md) (1 shared connections)
- [GET Response Writing](GET_Response_Writing.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`

## Audit Trail

- EXTRACTED: 8 (67%)
- INFERRED: 4 (33%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*