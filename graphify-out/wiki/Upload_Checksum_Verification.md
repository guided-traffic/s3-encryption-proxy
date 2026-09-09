# Upload Checksum Verification

> 11 nodes · cohesion 0.29

## Key Concepts

- **Ticket 014: Verify client upload checksums** (14 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **Never forwarded, never stored, never echoed** (5 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **verifyingReader around the parser's inner reader** (5 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **Sealed plaintext CRC32C served as x-amz-checksum-crc32c** (4 connections) — `docs/tickets/013-storage-format-v2.md`
- **aws-chunked trailer capture instead of drain** (4 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **Tier 1.1: disable AWS SDK flexible checksums** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **CRC64NVME slicing-by-8 table rebuild trap** (3 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **Measured primitive throughput on Apple M5 Pro, one core, 64 KiB blocks** (3 connections) — `docs/tickets/023-major-v5.md`
- **The client-to-proxy leg is where plaintext still exists** (2 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **Later: a plaintext response checksum** (2 connections) — `docs/tickets/014-upload-checksum-verification.md`
- **P-5: one body reader for every handler** (1 connections) — `docs/tickets/014-upload-checksum-verification.md`

## Relationships

- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (4 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (2 shared connections)
- [S3 Surface Fidelity Ticket](S3_Surface_Fidelity_Ticket.md) (2 shared connections)
- [Configuration Hygiene Ticket](Configuration_Hygiene_Ticket.md) (2 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (2 shared connections)
- [Coverage Round Findings](Coverage_Round_Findings.md) (2 shared connections)

## Source Files

- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/013-storage-format-v2.md`
- `docs/tickets/014-upload-checksum-verification.md`
- `docs/tickets/023-major-v5.md`

## Audit Trail

- EXTRACTED: 27 (90%)
- INFERRED: 3 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*