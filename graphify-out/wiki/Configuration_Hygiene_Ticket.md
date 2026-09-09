# Configuration Hygiene Ticket

> 9 nodes · cohesion 0.28

## Key Concepts

- **Ticket 015: Configuration hygiene** (16 connections) — `docs/tickets/015-configuration-hygiene.md`
- **N-5: four dead s3_security knobs and the failed-attempt map** (7 connections) — `docs/tickets/015-configuration-hygiene.md`
- **Per-IP rate limiting is the wrong tool for an S3 proxy** (3 connections) — `docs/tickets/015-configuration-hygiene.md`
- **encryption.verify_upload_digests, void before it was built** (2 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **D-24: keep the failure map with trusted-proxy CIDRs and eviction** (2 connections) — `docs/tickets/015-configuration-hygiene.md`
- **E-3: integrity_verification defaults to off while the docs recommend strict** (2 connections) — `docs/tickets/015-configuration-hygiene.md`
- **Item 1: missing checksum/config annotation, so a config change does not roll pods** (2 connections) — `docs/tickets/016-helm-chart-fixes.md`
- **Test-only enable_rate_limiting: false for Velero's per-pod-IP bursts** (2 connections) — `test/e2e/velero/values-proxy.yaml`
- **E-1: max_clock_skew_seconds ignored on the Authorization-header path** (1 connections) — `docs/tickets/015-configuration-hygiene.md`

## Relationships

- [Helm Chart Fix Ticket](Helm_Chart_Fix_Ticket.md) (4 shared connections)
- [Coverage Round Findings](Coverage_Round_Findings.md) (3 shared connections)
- [Upload Checksum Verification](Upload_Checksum_Verification.md) (2 shared connections)
- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (2 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (2 shared connections)
- [S3 Surface Fidelity Ticket](S3_Surface_Fidelity_Ticket.md) (2 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (2 shared connections)

## Source Files

- `docs/tickets/014-upload-checksum-verification.md`
- `docs/tickets/015-configuration-hygiene.md`
- `docs/tickets/016-helm-chart-fixes.md`
- `test/e2e/velero/values-proxy.yaml`

## Audit Trail

- EXTRACTED: 23 (85%)
- INFERRED: 4 (15%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*