# Dataencryption: Segmented Gcm Range

> 5 nodes · cohesion 0.50

## Key Concepts

- **rangeReader** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.finish()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **Codec** (1 connections)

## Relationships

- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (2 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm_range.go`

## Audit Trail

- EXTRACTED: 8 (89%)
- INFERRED: 1 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*