# Failing Listener Test Fixture

> 7 nodes · cohesion 0.29

## Key Concepts

- **RtPxfailingListener** (6 connections) — `internal/proxy/server_coverage_test.go`
- **sync.Once** (3 connections)
- **RtPxnewFailingListener()** (3 connections) — `internal/proxy/server_coverage_test.go`
- **.Accept()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **.Addr()** (2 connections) — `internal/proxy/server_coverage_test.go`
- **net.Addr** (1 connections)
- **.Close()** (1 connections) — `internal/proxy/server_coverage_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (3 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (1 shared connections)
- [Backend TLS Trust](Backend_TLS_Trust.md) (1 shared connections)
- [Misc](Misc.md) (1 shared connections)

## Source Files

- `internal/proxy/server_coverage_test.go`

## Audit Trail

- EXTRACTED: 12 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*