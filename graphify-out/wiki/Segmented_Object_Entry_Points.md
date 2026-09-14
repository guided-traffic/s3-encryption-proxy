# Segmented Object Entry Points

> 10 nodes · cohesion 0.33

## Key Concepts

- **Manager** (7 connections) — `internal/orchestration/segmented.go`
- **.codecFor()** (6 connections) — `internal/orchestration/segmented.go`
- **.newSegmentedObject()** (5 connections) — `internal/orchestration/segmented.go`
- **.NewSegmentedWrite()** (5 connections) — `internal/orchestration/segmented.go`
- **.OpenSegmentedRange()** (5 connections) — `internal/orchestration/segmented.go`
- **io.ReadCloser** (4 connections)
- **.OpenSegmented()** (4 connections) — `internal/orchestration/segmented.go`
- **SegmentedWrite** (4 connections) — `internal/orchestration/segmented.go`
- **.NewSegmentedUpload()** (3 connections) — `internal/orchestration/segmented.go`
- **.IsSegmentedObject()** (2 connections) — `internal/orchestration/segmented.go`

## Relationships

- [Copy Benchmarks](Copy_Benchmarks.md) (5 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (3 shared connections)
- [Range Reader](Range_Reader.md) (2 shared connections)
- [Segment Codec Core](Segment_Codec_Core.md) (2 shared connections)
- [Sealed Part Arithmetic](Sealed_Part_Arithmetic.md) (2 shared connections)
- [Codec Streaming IO](Codec_Streaming_IO.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`

## Audit Trail

- EXTRACTED: 30 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*