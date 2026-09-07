# Ticket Decisions and Findings

> 204 nodes · cohesion 0.02

## Key Concepts

- **Ticket 024: the coverage round, what raising coverage found** (39 connections) — `docs/tickets/024-coverage-round-findings.md`
- **Ticket 022: S3 surface fidelity** (30 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **Ticket 013: Storage format v2** (29 connections) — `docs/tickets/013-storage-format-v2.md`
- **Ticket 025: Tink KEK provider with a real KMS, HashiCorp Vault first** (24 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **D series: decisions taken** (21 connections) — `docs/tickets/README.md`
- **Ticket index** (17 connections) — `docs/tickets/README.md`
- **Ticket 015: Configuration hygiene** (14 connections) — `docs/tickets/015-configuration-hygiene.md`
- **Ticket 023: Major release v4, the breaking-change bundle** (14 connections) — `docs/tickets/023-major-v4.md`
- **N series: threat-model findings** (11 connections) — `docs/tickets/README.md`
- **Ticket 012: Performance audit round 2** (10 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Item 1 (S-8): PUT drops the storage headers and answers 200** (10 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **F series: fixes that landed** (10 connections) — `docs/tickets/README.md`
- **Ticket 014: Upload checksum verification** (9 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **P series: parked items** (9 connections) — `docs/tickets/README.md`
- **S series: pre-merge sweep findings** (9 connections) — `docs/tickets/README.md`
- **v4 candidates: client-visible changes that should ride along** (8 connections) — `docs/tickets/023-major-v4.md`
- **Stale ticket spots found by the sweep** (8 connections) — `docs/tickets/023-major-v4.md`
- **Ownership: which ticket actually fixes what** (8 connections) — `docs/tickets/024-coverage-round-findings.md`
- **P-1: the DEK is unwrapped twice on every GCM GET** (8 connections) — `docs/tickets/024-coverage-round-findings.md`
- **What runs first: 013 is the ticket that unblocks the rest** (8 connections) — `docs/tickets/README.md`
- **Ticket 019: Handler unit coverage** (7 connections) — `docs/tickets/019-handler-unit-coverage.md`
- **Item 5: the example configs still carry working key material** (7 connections) — `docs/tickets/022-s3-surface-fidelity.md`
- **TinkProvider** (7 connections) — `pkg/encryption/keyencryption/tink.go`
- **NewTinkProviderFromConfig()** (7 connections) — `pkg/encryption/keyencryption/tink.go`
- **Ticket 016: Helm chart fixes** (6 connections) — `docs/tickets/016-helm-chart-fixes.md`
- *... and 179 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `/Users/hfi/repos/s3-encryption-proxy/pkg/encryption/dataencryption/aes_gcm.go`
- `docs/tickets/011-dek-cache-stale-on-reupload.md`
- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/013-storage-format-v2.md`
- `docs/tickets/014-upload-checksum-verification.md`
- `docs/tickets/015-configuration-hygiene.md`
- `docs/tickets/016-helm-chart-fixes.md`
- `docs/tickets/017-filename-encryption.md`
- `docs/tickets/019-handler-unit-coverage.md`
- `docs/tickets/020-dev-license-expiry.md`
- `docs/tickets/021-relative-performance-thresholds.md`
- `docs/tickets/022-s3-surface-fidelity.md`
- `docs/tickets/023-major-v4.md`
- `docs/tickets/024-coverage-round-findings.md`
- `docs/tickets/025-tink-kms-hcvault.md`
- `docs/tickets/README.md`
- `internal/config/config.go`
- `internal/config/validation_coverage_test.go`
- `internal/proxy/mock_s3_backend.go`
- `pkg/encryption/dataencryption/aes_ctr.go`

## Audit Trail

- EXTRACTED: 804 (91%)
- INFERRED: 63 (7%)
- AMBIGUOUS: 14 (2%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*