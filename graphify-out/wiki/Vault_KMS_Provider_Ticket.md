# Vault KMS Provider Ticket

> 13 nodes · cohesion 0.21

## Key Concepts

- **Vault as a key provider — open decisions, parked** (11 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **KEK fingerprint becomes HKDF-Expand over the KEK** (5 connections) — `docs/tickets/013-storage-format-v2.md`
- **A rewrap campaign is a full server-side rewrite, not a metadata edit** (4 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Talk to Vault's Transit engine directly, replacing the Tink stub** (4 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Tier 5.1: GCM GET unwraps the DEK twice** (3 connections) — `docs/tickets/012-performance-audit-round2.md`
- **The fingerprint identifies mount and key name, never the version** (3 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Rotation has three mechanisms and they must never be confused** (3 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Tier 3.1: metadata at initiate, delete the self-CopyObject, >5 GiB failure** (2 connections) — `docs/tickets/012-performance-audit-round2.md`
- **P-1: the DEK is unwrapped twice on every GCM GET** (2 connections) — `docs/tickets/024-coverage-round-findings.md`
- **S-1: the AES KEK fingerprint is a crackable hash of a possibly human-chosen key** (2 connections) — `docs/tickets/024-coverage-round-findings.md`
- **Vault availability becomes proxy availability** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Key custody is what this buys, and only that** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **The demo Vault needs fixing regardless** (1 connections) — `docs/tickets/025-tink-kms-hcvault.md`

## Relationships

- [Coverage Round Findings](Coverage_Round_Findings.md) (4 shared connections)
- [Segmented Storage Format V2](Segmented_Storage_Format_V2.md) (3 shared connections)
- [Performance Audit Round Two](Performance_Audit_Round_Two.md) (2 shared connections)
- [Major V5 Work List](Major_V5_Work_List.md) (2 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)

## Source Files

- `docs/tickets/012-performance-audit-round2.md`
- `docs/tickets/013-storage-format-v2.md`
- `docs/tickets/024-coverage-round-findings.md`
- `docs/tickets/025-tink-kms-hcvault.md`

## Audit Trail

- EXTRACTED: 25 (89%)
- INFERRED: 3 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*