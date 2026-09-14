# Part Codec Tests

> 10 nodes · cohesion 0.40

## Key Concepts

- **partCodec()** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **segmented_gcm_part_test.go** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **sealInParts()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegPartWriterRoundTrip()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegSealTrailerMatchesSequentialWriter()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegOpenTrailerRejectsTampering()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegPartWriterOffsetIsAuthenticated()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegPartWriterRefusesShortMiddlePart()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **TestSegPartWriterRefusesUnalignedOffset()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_part_test.go`
- **Codec** (2 connections)

## Relationships

- [Config Env Expansion](Config_Env_Expansion.md) (8 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (2 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm_part_test.go`

## Audit Trail

- EXTRACTED: 26 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*