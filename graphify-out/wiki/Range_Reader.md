# Range Reader

> 12 nodes · cohesion 0.21

## Key Concepts

- **rangeReader** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **Window** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.NewRangeReader()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmented_gcm_range.go** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmentCount()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **.next()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmentStoredLen()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.finish()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **Codec** (1 connections)
- **Codec** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`

## Relationships

- [Segment Codec Tests](Segment_Codec_Tests.md) (5 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (2 shared connections)
- [Segmented Object Entry Points](Segmented_Object_Entry_Points.md) (2 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (1 shared connections)
- [Segment Codec Core](Segment_Codec_Core.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`

## Audit Trail

- EXTRACTED: 23 (92%)
- INFERRED: 2 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*