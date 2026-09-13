# Performance Findings Round 1

> 14 nodes · cohesion 0.14

## Key Concepts

- **pre-v2 Baseline Findings** (11 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Item 4.3 GOMEMLIMIT** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Item 6.1 Baseline Without Backend TLS** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **Item 5 Refuse A Plain-HTTP Backend Under An Encrypting Provider** (3 connections) — `docs/tickets/015-configuration-hygiene.md`
- **RSA Unwrap Is Four Orders Of Magnitude Off The Local Provider** (3 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Item 6.3 Small-Object Request-Rate Ceiling** (2 connections) — `docs/tickets/012-performance-audit-round2.md`
- **P-11 Plain-HTTP Backend Cannot Take A Streaming Upload** (2 connections) — `docs/tickets/README.md`
- **The HMAC Is The Entire Difference** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **The Container Memory Limit Is Nowhere Near Reached** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Ranged Reads: The Alignment Before-Column** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **The Proxy Barely Gets Faster With More Clients** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **The GCM Profile Rows Are TLS Records, Not Object Crypto** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **Two Measurement Bugs Found Before The Run** (2 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- **pre-v2 Baseline Run Record** (1 connections) — `perf-baseline/20260909T175340Z-9f3fbd1/REPORT.md`

## Relationships

- [Upload Deficit Investigation](Upload_Deficit_Investigation.md) (5 shared connections)
- [Storage Format Ticket](Storage_Format_Ticket.md) (4 shared connections)
- [Open Ticket Backlog](Open_Ticket_Backlog.md) (2 shared connections)
- [Upload Checksum Ticket](Upload_Checksum_Ticket.md) (1 shared connections)
- [KMS and Vault Ticket](KMS_and_Vault_Ticket.md) (1 shared connections)
- [Coverage and Surface Tickets](Coverage_and_Surface_Tickets.md) (1 shared connections)

## Source Files

- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/015-configuration-hygiene.md`
- `docs/tickets/README.md`
- `perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md`
- `perf-baseline/20260909T175340Z-9f3fbd1/REPORT.md`

## Audit Trail

- EXTRACTED: 25 (93%)
- INFERRED: 2 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*