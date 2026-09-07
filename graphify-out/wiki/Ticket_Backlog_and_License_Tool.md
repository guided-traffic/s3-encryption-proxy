# Ticket Backlog and License Tool

> 207 nodes · cohesion 0.02

## Key Concepts

- **Ticket 013: storage format v2, segmented AES-GCM** (23 connections) — `docs/tickets/013-storage-format-v2.md`
- **main()** (16 connections) — `cmd/license-tool/main.go`
- **main_coverage_test.go** (15 connections) — `cmd/license-tool/main_coverage_test.go`
- **Ticket 012: performance audit round 2** (13 connections) — `docs/tickets/012-performance-audit-round2.md`
- **TestLicTMainHappyPath()** (11 connections) — `cmd/license-tool/main_coverage_test.go`
- **Ticket 010: streaming throughput performance improvements** (10 connections) — `docs/tickets/010-performance-improvements.md`
- **collectLicenseInfo()** (10 connections) — `cmd/license-tool/main.go`
- **Ticket 014: verify client upload checksums** (9 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **Ticket 015: configuration hygiene, dead knobs out** (9 connections) — `docs/tickets/015-configuration-hygiene.md`
- **TestLicTCollectLicenseInfo()** (9 connections) — `cmd/license-tool/main_coverage_test.go`
- **generateJWT()** (8 connections) — `cmd/license-tool/main.go`
- **Ticket 018: ListObjectsV2, a real S3 document and plaintext sizes** (7 connections) — `docs/tickets/018-listobjectsv2-document.md`
- **Ticket 020: development license expiry and a CI check** (7 connections) — `docs/tickets/020-dev-license-expiry.md`
- **Quick-win summary (~1400 lines)** (7 connections) — `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- **main.go** (7 connections) — `cmd/license-tool/main.go`
- **LicTcaptureStdout()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **LicTwithStdin()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTEndToEnd()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTGenerateJWT()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **TestLicTLoadPrivateKey()** (7 connections) — `cmd/license-tool/main_coverage_test.go`
- **parseDuration()** (7 connections) — `cmd/license-tool/main.go`
- **H-5 integrity_verification does not refuse a tampered aes-ctr object** (7 connections) — `SECURITY_ARCHITECTURE.md`
- **H-7 dead security configuration knobs** (7 connections) — `SECURITY_ARCHITECTURE.md`
- **The three rules that decide every open question** (7 connections) — `SECURITY_ARCHITECTURE.md`
- **Root cause: cache key is (fingerprint, objectKey) with no invalidation** (6 connections) — `docs/tickets/011-dek-cache-stale-on-reupload.md`
- *... and 182 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `CHANGELOG.md`
- `CLAUDE.md`
- `CONTRIBUTING.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `cmd/keygen/main.go`
- `cmd/license-tool/main.go`
- `cmd/license-tool/main_coverage_test.go`
- `cmd/s3-encryption-proxy/main.go`
- `deploy/helm/s3-encryption-proxy/README.md`
- `docs/architecture/ARCHITECTURE_ANALYSIS.md`
- `docs/architecture/callgraph_main_entrypoint.svg`
- `docs/tickets/010-performance-improvements.md`
- `docs/tickets/011-dek-cache-stale-on-reupload.md`
- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/013-storage-format-v2.md`
- `docs/tickets/014-upload-checksum-verification.md`
- `docs/tickets/015-configuration-hygiene.md`
- `docs/tickets/016-helm-chart-fixes.md`
- `docs/tickets/017-filename-encryption.md`

## Audit Trail

- EXTRACTED: 518 (74%)
- INFERRED: 173 (25%)
- AMBIGUOUS: 7 (1%)

---

*Part of the graphify knowledge wiki. See [[index]] to navigate.*