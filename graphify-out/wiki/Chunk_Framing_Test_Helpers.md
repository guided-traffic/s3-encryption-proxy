# Chunk Framing Test Helpers

> 5 nodes · cohesion 0.40

## Key Concepts

- **framing_test.go** (5 connections) — `internal/proxy/request/framing_test.go`
- **writeChunks()** (2 connections) — `internal/proxy/request/framing_test.go`
- **framing** (2 connections) — `internal/proxy/request/framing_test.go`
- **chunkedHeaders()** (1 connections) — `internal/proxy/request/framing_test.go`
- **crc32Trailer()** (1 connections) — `internal/proxy/request/framing_test.go`

## Relationships

- [Request Body Parser Tests](Request_Body_Parser_Tests.md) (2 shared connections)
- [Proxy Utils Tests](Proxy_Utils_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/request/framing_test.go`

## Audit Trail

- EXTRACTED: 7 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*