# Segmented GCM Range Reader

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

- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (5 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (4 shared connections)
- [Segmented GCM](Segmented_GCM.md) (1 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`

## Audit Trail

- EXTRACTED: 23 (92%)
- INFERRED: 2 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*