# Integration Test Layers

> 17 nodes · cohesion 0.12

## Key Concepts

- **Graceful shutdown ends open uploads** (5 connections) — `docs/operations/configuration.md`
- **Integration suites under test/integration** (4 connections) — `docs/developer/testing.md`
- **The exit provider needs no license** (3 connections) — `docs/operations/configuration.md`
- **GET /livez** (3 connections) — `docs/operations/monitoring.md`
- **A probe counts only when unsigned and query-free** (3 connections) — `docs/operations/monitoring.md`
- **encryption-modes starts the proxy in process** (2 connections) — `docs/developer/testing.md`
- **shutdown integration package** (2 connections) — `docs/developer/testing.md`
- **TLS integration run reaches the trailer decoder** (2 connections) — `docs/developer/testing.md`
- **Shipped configuration examples** (2 connections) — `docs/operations/configuration.md`
- **backend status reports what real traffic showed** (2 connections) — `docs/operations/monitoring.md`
- **GET /readyz** (2 connections) — `docs/operations/monitoring.md`
- **What an unauthenticated request is told** (2 connections) — `docs/operations/s3-api.md`
- **MinIO accepts SSE-C only over TLS** (2 connections) — `docs/tickets/026-sse-c-passthrough.md`
- **AbortIncompleteMultipartUpload lifecycle rule** (1 connections) — `docs/operations/configuration.md`
- **optimizations.multipart_session_idle_timeout** (1 connections) — `docs/operations/configuration.md`
- **x-amz-request-id is the proxy's own identifier** (1 connections) — `docs/operations/s3-api.md`
- **TestContext** (1 connections) — `docs/developer/testing.md`

## Relationships

- [Storage Format Integrity Guarantees](Storage_Format_Integrity_Guarantees.md) (1 shared connections)
- [Integrity Operator Notes](Integrity_Operator_Notes.md) (1 shared connections)
- [ADR Web: Auth, Checksums, Config](ADR_Web-_Auth,_Checksums,_Config.md) (1 shared connections)
- [Testing](Testing.md) (1 shared connections)

## Source Files

- `docs/developer/testing.md`
- `docs/operations/configuration.md`
- `docs/operations/monitoring.md`
- `docs/operations/s3-api.md`
- `docs/tickets/026-sse-c-passthrough.md`

## Audit Trail

- EXTRACTED: 15 (71%)
- INFERRED: 6 (29%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*