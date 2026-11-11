# Object: Range (2)

> 7 nodes · cohesion 0.33

## Key Concepts

- **Ranged GET window planning** (9 connections) — `docs/developer/request-paths.md`
- **provisionalWindow()** (6 connections) — `internal/proxy/handlers/object/range.go`
- **Range header decided twice (parseRangeSpec classifies, parseByteRange resolves)** (5 connections) — `docs/developer/request-paths.md`
- **parseRangeSpec()** (5 connections) — `internal/proxy/handlers/object/range.go`
- **closeDrained()** (4 connections) — `internal/proxy/handlers/object/range.go`
- **TestObjGetParseRangeSpec()** (3 connections) — `internal/proxy/handlers/object/rangeread_coverage_test.go`
- **rangeSpec** (3 connections) — `internal/proxy/handlers/object/range.go`

## Relationships

- [Bucket Sub-Resource Handlers](Bucket_Sub-Resource_Handlers.md) (7 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (4 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (3 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (1 shared connections)
- [Object: Range](Object-_Range.md) (1 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (1 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (1 shared connections)
- [Object Checksum and Tagging Tests](Object_Checksum_and_Tagging_Tests.md) (1 shared connections)

## Source Files

- `docs/developer/request-paths.md`
- `internal/proxy/handlers/object/range.go`
- `internal/proxy/handlers/object/rangeread_coverage_test.go`

## Audit Trail

- EXTRACTED: 26 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*