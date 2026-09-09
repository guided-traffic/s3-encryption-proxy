# Performance Audit Round Two

> 21 nodes · cohesion 0.13

## Key Concepts

- **Ticket 012: Performance improvements round 2** (23 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Ticket 021: Performance thresholds relative to a MinIO baseline** (7 connections) — `docs/tickets/021-relative-performance-thresholds.md`
- **Tier 1.2: the 30s blanket Read/WriteTimeout (N-8)** (5 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 1.4 / D-29: pooled copy buffer versus io.ReaderFrom** (4 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Per-tier measurement protocol (pprof through a shared network namespace)** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 2.2: destructive aws-chunked body sniff** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 2.3: exact-size part buffers and a channel pool** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 2: upload-path streaming rewrite (io.ReadAll residual)** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **A ratio against a plain-MinIO leg removes common-mode runner noise** (3 connections) — `docs/tickets/021-relative-performance-thresholds.md`
- **SKIP_PERFORMANCE_CHECKS disarms every assertion in CI** (3 connections) — `docs/tickets/021-relative-performance-thresholds.md`
- **The 42% crypto floor was 10 points of backend TLS** (2 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Rejected then reversed: segmented AEAD format change** (2 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 3.2: ranged GET via AES-CTR counter seek** (2 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 4.2: fill the 128 KiB pooled buffer before writing to the client** (2 connections) — `docs/tickets/012-performance-audit-round2.md`
- **D-22: pprof on its own loopback listener** (2 connections) — `docs/tickets/015-configuration-hygiene.md`
- **The comparison bucket is never cleaned, so repeat runs measure a fuller MinIO** (2 connections) — `docs/tickets/021-relative-performance-thresholds.md`
- **P-2: the pooled-buffer flag dependence did not exist** (2 connections) — `docs/tickets/024-coverage-round-findings.md`
- **N-9: a client that hung up mid-body committed a short object that verified** (2 connections) — `docs/tickets/README.md`
- **Tier 1.3: dead code and per-GET Info logs** (1 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 4.1: SDK transport defaults discarded on insecure_skip_verify** (1 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Tier 5.2: GCM []byte fast path** (1 connections) — `docs/tickets/012-performance-audit-round2.md`

## Relationships

- [Coverage Round Findings](Coverage_Round_Findings.md) (5 shared connections)
- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (4 shared connections)
- [Upload Checksum Verification](Upload_Checksum_Verification.md) (2 shared connections)
- [Vault KMS Provider Ticket](Vault_KMS_Provider_Ticket.md) (2 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (2 shared connections)
- [Helm Chart Fix Ticket](Helm_Chart_Fix_Ticket.md) (2 shared connections)
- [Configuration Hygiene Ticket](Configuration_Hygiene_Ticket.md) (2 shared connections)
- [S3 Surface Fidelity Ticket](S3_Surface_Fidelity_Ticket.md) (1 shared connections)
- [Stale DEK Cache Ticket](Stale_DEK_Cache_Ticket.md) (1 shared connections)
- [Orchestration README Staleness](Orchestration_README_Staleness.md) (1 shared connections)

## Source Files

- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/015-configuration-hygiene.md`
- `docs/tickets/021-relative-performance-thresholds.md`
- `docs/tickets/024-coverage-round-findings.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 44 (90%)
- INFERRED: 5 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*