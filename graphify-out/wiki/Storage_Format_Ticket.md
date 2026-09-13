# Storage Format Ticket

> 16 nodes · cohesion 0.21

## Key Concepts

- **Ticket 013 Storage Format v2** (25 connections) — `docs/tickets/013-storage-format-v2.md`
- **Segmented AES-256-GCM Chain Format** (14 connections) — `docs/tickets/013-storage-format-v2.md`
- **Sealed Trailer With Length And CRC32C** (6 connections) — `docs/tickets/013-storage-format-v2.md`
- **Four Encryption Metadata Keys** (4 connections) — `docs/tickets/013-storage-format-v2.md`
- **Random Inline Nonces Per Segment** (4 connections) — `docs/tickets/013-storage-format-v2.md`
- **The Segment Codec, Measured** (4 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Item 2d Sealed Checksum Read Side And Tail-First Read** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **Plaintext Size As A Pure Function Of Stored Size** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **A 1.7x That Was Nearly A 1.0x** (3 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- **Associated Data: formatID, Object Key, Index** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **Rejected: AES-CTR Plus Per-Segment HMAC** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **Rejected: Tink AES-GCM-HKDF Derived Nonces** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **Rejected: XChaCha20-Poly1305** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **Item 16 Documentation Remainder** (1 connections) — `docs/tickets/013-storage-format-v2.md`
- **Rejected: Storing A Per-Object Part Layout** (1 connections) — `docs/tickets/013-storage-format-v2.md`
- **Segment-Codec Run Record** (1 connections) — `perf-baseline/20260909T212247Z-9f3fbd1/REPORT.md`

## Relationships

- [Upload Deficit Investigation](Upload_Deficit_Investigation.md) (5 shared connections)
- [Upload Checksum Ticket](Upload_Checksum_Ticket.md) (5 shared connections)
- [Open Ticket Backlog](Open_Ticket_Backlog.md) (5 shared connections)
- [Performance Findings Round 1](Performance_Findings_Round_1.md) (4 shared connections)
- [KMS and Vault Ticket](KMS_and_Vault_Ticket.md) (2 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (2 shared connections)
- [Coverage and Surface Tickets](Coverage_and_Surface_Tickets.md) (2 shared connections)
- [Helm Chart Fixes Ticket](Helm_Chart_Fixes_Ticket.md) (1 shared connections)
- [Finding Label Index](Finding_Label_Index.md) (1 shared connections)

## Source Files

- `docs/tickets/013-storage-format-v2.md`
- `perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md`
- `perf-baseline/20260909T212247Z-9f3fbd1/REPORT.md`

## Audit Trail

- EXTRACTED: 50 (96%)
- INFERRED: 2 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*