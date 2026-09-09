# Segmented Storage Format V2

> 20 nodes · cohesion 0.18

## Key Concepts

- **Ticket 013: Storage format v2 — segmented AES-GCM** (39 connections) — `docs/tickets/013-storage-format-v2.md`
- **s3ep-gcm-seg-v2 segment chain format** (15 connections) — `docs/tickets/013-storage-format-v2.md`
- **N-1: an object without proxy metadata is InvalidObjectState 403** (6 connections) — `docs/tickets/013-storage-format-v2.md`
- **Three rules of the hostile-backend threat model** (5 connections) — `docs/tickets/013-storage-format-v2.md`
- **AAD = formatID + clientObjectKey + index** (4 connections) — `docs/tickets/013-storage-format-v2.md`
- **One client part is one backend part, checked at Complete** (4 connections) — `docs/tickets/013-storage-format-v2.md`
- **40-byte sealed trailer (length + CRC32C)** (4 connections) — `docs/tickets/013-storage-format-v2.md`
- **Rejected alternatives: CTR+per-segment HMAC, stored part layout, refuse ranges** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **The bucket stays out of the AAD (D-33)** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **optimizations.multipart_short_part_buffer_size** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **Precondition: no production users, so no v1 read path and no migration** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **Random inline nonces instead of Tink's derived nonces** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **Ranged read amplification bounded at 2S + framing** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **Short last part is re-uploaded with the trailer appended** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **Plaintext size as a pure function of the stored size** (3 connections) — `docs/tickets/013-storage-format-v2.md`
- **N-7: kopia sets DisableMultipart, so auto-multipart carries all kopia data** (3 connections) — `docs/tickets/README.md`
- **none-provider-fingerprint forgery under an encrypting provider** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **Tail-first whole-object GET and HEAD** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **Offset-explicit segment codec API** (2 connections) — `docs/tickets/013-storage-format-v2.md`
- **H-2: the backend can switch integrity checking off with one header** (2 connections) — `docs/tickets/024-coverage-round-findings.md`

## Relationships

- [Coverage Round Findings](Coverage_Round_Findings.md) (10 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (6 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (5 shared connections)
- [S3 Surface Fidelity Ticket](S3_Surface_Fidelity_Ticket.md) (5 shared connections)
- [Orchestration README Staleness](Orchestration_README_Staleness.md) (4 shared connections)
- [Upload Checksum Verification](Upload_Checksum_Verification.md) (4 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (4 shared connections)
- [Vault KMS Provider Ticket](Vault_KMS_Provider_Ticket.md) (3 shared connections)
- [Configuration Hygiene Ticket](Configuration_Hygiene_Ticket.md) (2 shared connections)
- [Stale DEK Cache Ticket](Stale_DEK_Cache_Ticket.md) (1 shared connections)

## Source Files

- `docs/tickets/013-storage-format-v2.md`
- `docs/tickets/024-coverage-round-findings.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 67 (86%)
- INFERRED: 11 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*