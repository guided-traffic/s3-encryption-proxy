# Short-Part Budget and Memory

> 10 nodes · cohesion 0.20

## Key Concepts

- **What One In-Flight Request Costs in Memory** (9 connections) — `docs/developer/performance.md`
- **uploadStreamedPart** (4 connections) — `docs/developer/multipart.md`
- **A Permanent State Is a 4xx, a Transient Failure a 5xx** (3 connections) — `docs/developer/errors.md`
- **The Process-Wide Short-Part Budget** (3 connections) — `docs/developer/multipart.md`
- **readHeldPart** (2 connections) — `docs/developer/performance.md`
- **RecordStreamedPart** (1 connections) — `docs/developer/multipart.md`
- **SegmentedSession.SealStreamingPart** (1 connections) — `docs/developer/multipart.md`
- **readWholePart** (1 connections) — `docs/developer/performance.md`
- **Parser.ReadBodyLimited** (1 connections) — `docs/developer/multipart.md`
- **Parser.StreamingReader** (1 connections) — `docs/developer/multipart.md`

## Relationships

- [Error Conventions](Error_Conventions.md) (1 shared connections)
- [S3 Error Mapping](S3_Error_Mapping.md) (1 shared connections)
- [Entity Tag Marker](Entity_Tag_Marker.md) (1 shared connections)
- [Object Metadata Coverage Tests](Object_Metadata_Coverage_Tests.md) (1 shared connections)
- [Client-Driven Multipart Paths](Client-Driven_Multipart_Paths.md) (1 shared connections)
- [aws-chunked Streaming Decoder](aws-chunked_Streaming_Decoder.md) (1 shared connections)
- [Object Response Header Helpers](Object_Response_Header_Helpers.md) (1 shared connections)
- [Performance Measurement Rules](Performance_Measurement_Rules.md) (1 shared connections)

## Source Files

- `docs/developer/errors.md`
- `docs/developer/multipart.md`
- `docs/developer/performance.md`

## Audit Trail

- EXTRACTED: 16 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*