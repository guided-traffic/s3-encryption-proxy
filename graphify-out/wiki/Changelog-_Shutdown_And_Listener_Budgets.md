# Changelog: Shutdown And Listener Budgets

> 7 nodes · cohesion 0.33

## Key Concepts

- **shutdown_timeout as one budget: drain, multipart sweep, listener close (ADR 0029)** (6 connections) — `CHANGELOG.md`
- **multipart_session_idle_timeout counted from last part (ADR 0028)** (4 connections) — `CHANGELOG.md`
- **Listener budgets read/write/read_header/idle_timeout (ADR 0015)** (3 connections) — `CHANGELOG.md`
- **Chart refuses replicaCount > 1 and autoscaling** (2 connections) — `CHANGELOG.md`
- **Release 5.0.2: multipart idle clock moves while a part arrives** (2 connections) — `CHANGELOG.md`
- **Drain guard: 503 ServiceUnavailable with Retry-After during shutdown** (1 connections) — `CHANGELOG.md`
- **Graceful shutdown with request tracking (1.18.0)** (1 connections) — `CHANGELOG.md`

## Relationships

- [Request: Streaming Decoder Coverage Test](Request-_Streaming_Decoder_Coverage_Test.md) (3 shared connections)
- [Changelog: Configuration Refusals](Changelog-_Configuration_Refusals.md) (1 shared connections)
- [Misc (31)](Misc_31.md) (1 shared connections)

## Source Files

- `CHANGELOG.md`

## Audit Trail

- EXTRACTED: 10 (83%)
- INFERRED: 2 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*