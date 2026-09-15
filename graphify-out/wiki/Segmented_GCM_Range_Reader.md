# Segmented GCM Range Reader

> 23 nodes · cohesion 0.14

## Key Concepts

- **PlanRange()** (15 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmented_gcm_range_test.go** (10 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **rangeReader** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **Window** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **TestSegRangeExhaustive()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **PlanRange()** (5 connections) — `internal/orchestration/segmented.go`
- **TestSegRangeSegmentFromAnotherOffsetFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeShortWindowFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTailVerifiesTheAuthenticatedLength()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeTamperedSegmentFails()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **.NewRangeReader()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmented_gcm_range.go** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **segmentStoredLen()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **TestSegRangeAmplificationBound()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeMidObjectDoesNotCarryTheTrailer()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeOverflowGuard()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **TestSegRangeRefusals()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **.finish()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **.Read()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **min64()** (2 connections) — `pkg/encryption/dataencryption/segmented_gcm_range_test.go`
- **.Close()** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`
- **Codec** (1 connections)
- **Codec** (1 connections) — `pkg/encryption/dataencryption/segmented_gcm_range.go`

## Relationships

- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (10 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (9 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (5 shared connections)
- [Segmented GCM](Segmented_GCM.md) (3 shared connections)
- [Ranged GET Path and Window](Ranged_GET_Path_and_Window.md) (2 shared connections)
- [Segmented Session Tests](Segmented_Session_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`
- `pkg/encryption/dataencryption/segmented_gcm_range.go`
- `pkg/encryption/dataencryption/segmented_gcm_range_test.go`

## Audit Trail

- EXTRACTED: 45 (68%)
- INFERRED: 21 (32%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*