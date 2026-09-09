# Failing Reader Test Fakes

> 4 nodes · cohesion 0.50

## Key Concepts

- **countingReader** (3 connections) — `internal/proxy/request/parser_test.go`
- **.Read()** (2 connections) — `internal/proxy/request/parser_test.go`
- **errReader** (2 connections) — `internal/proxy/request/parser_test.go`
- **.Read()** (2 connections) — `internal/proxy/request/parser_test.go`

## Relationships

- [Request Body Parser Tests](Request_Body_Parser_Tests.md) (2 shared connections)
- [Manager Envelope Encryption](Manager_Envelope_Encryption.md) (1 shared connections)

## Source Files

- `internal/proxy/request/parser_test.go`

## Audit Trail

- EXTRACTED: 6 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*