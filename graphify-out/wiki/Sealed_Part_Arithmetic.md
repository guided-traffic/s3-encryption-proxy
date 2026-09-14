# Sealed Part Arithmetic

> 10 nodes · cohesion 0.29

## Key Concepts

- **SegmentedUpload** (8 connections) — `internal/orchestration/segmented.go`
- **SealedPart** (7 connections) — `internal/orchestration/segmented.go`
- **segmented.go** (6 connections) — `internal/orchestration/segmented.go`
- **PlanRange()** (5 connections) — `internal/orchestration/segmented.go`
- **.BodyWithTrailer()** (4 connections) — `internal/orchestration/segmented.go`
- **.SealPart()** (4 connections) — `internal/orchestration/segmented.go`
- **PartStoredLen()** (3 connections) — `internal/orchestration/segmented.go`
- **.Body()** (3 connections) — `internal/orchestration/segmented.go`
- **.Trailer()** (2 connections) — `internal/orchestration/segmented.go`
- **.Metadata()** (1 connections) — `internal/orchestration/segmented.go`

## Relationships

- [Segment Codec Core](Segment_Codec_Core.md) (4 shared connections)
- [Object Operations Handler](Object_Operations_Handler.md) (2 shared connections)
- [Segmented Object Entry Points](Segmented_Object_Entry_Points.md) (2 shared connections)
- [Segment Codec Tests](Segment_Codec_Tests.md) (2 shared connections)
- [Multipart Session Table](Multipart_Session_Table.md) (2 shared connections)
- [Copy Benchmarks](Copy_Benchmarks.md) (2 shared connections)
- [Multipart Handler Tests](Multipart_Handler_Tests.md) (1 shared connections)
- [Range Reader](Range_Reader.md) (1 shared connections)
- [Segmented Orchestration Tests](Segmented_Orchestration_Tests.md) (1 shared connections)

## Source Files

- `internal/orchestration/segmented.go`

## Audit Trail

- EXTRACTED: 29 (97%)
- INFERRED: 1 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*