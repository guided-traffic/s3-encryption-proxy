# Multipart Counting Readers

> 5 nodes · cohesion 0.40

## Key Concepts

- **MpuCountingReader** (4 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **countingBody** (3 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.Read()** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.Read()** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.Read64()** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`

## Relationships

- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (3 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/multipart_coverage_test.go`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*