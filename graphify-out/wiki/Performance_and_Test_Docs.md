# Performance and Test Docs

> 31 nodes · cohesion 0.07

## Key Concepts

- **Developer: Testing** (25 connections) — `docs/developer/testing.md`
- **Developer: Performance** (18 connections) — `docs/developer/performance.md`
- **A client suite asserts the target behaviour** (6 connections) — `docs/developer/testing.md`
- **PUT routes on plaintext length, never wire length** (5 connections) — `docs/developer/request-paths.md`
- **Conformance suite (any backend)** (5 connections) — `docs/developer/testing.md`
- **Three-Leg Upload Comparison** (4 connections) — `docs/developer/performance.md`
- **The Memory Instrument Is the One Asserted Figure** (3 connections) — `docs/developer/performance.md`
- **test/perf baseline records, never asserts throughput** (3 connections) — `docs/developer/testing.md`
- **S3EP_PERF_ALT_PROXY second proxy** (2 connections) — `docs/developer/performance.md`
- **Two Transports Inside One Ratio (HTTP proxy leg vs HTTPS backend leg)** (2 connections) — `docs/developer/performance.md`
- **What Ruins a Before/After Comparison** (2 connections) — `docs/developer/performance.md`
- **BACKEND DEVIATION log instead of a skip** (2 connections) — `docs/developer/testing.md`
- **CI: semantic-release needs every suite** (2 connections) — `docs/developer/testing.md`
- **Conformance cost rule and Budget.Authorize** (2 connections) — `docs/developer/testing.md`
- **conformance-run.sh writes its own proxy configuration** (2 connections) — `docs/developer/testing.md`
- **encryption-modes starts the proxy in process** (2 connections) — `docs/developer/testing.md`
- **One tool, one e2e job** (2 connections) — `docs/developer/testing.md`
- **Paid-run bucket policy (scoped sub-user)** (2 connections) — `docs/developer/testing.md`
- **e2e verdict table (Still broken section)** (2 connections) — `docs/developer/testing.md`
- **rclone e2e suite R1-R7** (2 connections) — `docs/operations/clients/rclone.md`
- **The After Column (perf-baseline 20260911T103132Z-cc62c05)** (1 connections) — `docs/developer/performance.md`
- **Record the Before Column First** (1 connections) — `docs/developer/performance.md`
- **The In-Process Crypto Floor Rules the Cipher Out** (1 connections) — `docs/developer/performance.md`
- **A Per-Request Log Line Is Debug** (1 connections) — `docs/developer/performance.md`
- **Report what was measured, on what machine, against which column, and what the instrument could not separate** (1 connections) — `docs/developer/performance.md`
- *... and 6 more nodes in this community*

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (11 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (5 shared connections)
- [S3 API Behaviour](S3_API_Behaviour.md) (4 shared connections)
- [Client Library and Storage Format](Client_Library_and_Storage_Format.md) (4 shared connections)
- [Request Documents and Owner Guard](Request_Documents_and_Owner_Guard.md) (2 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (2 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (2 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (1 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (1 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (1 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)
- [Configuration Loading](Configuration_Loading.md) (1 shared connections)

## Source Files

- `docs/developer/performance.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `docs/operations/clients/rclone.md`

## Audit Trail

- EXTRACTED: 66 (93%)
- INFERRED: 5 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*