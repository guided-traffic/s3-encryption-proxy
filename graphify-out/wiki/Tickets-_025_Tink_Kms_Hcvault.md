# Tickets: 025 Tink Kms Hcvault

> 13 nodes · cohesion 0.21

## Key Concepts

- **Ticket 025: Vault as a key provider (parked)** (17 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **HashiCorp Vault Transit KEK provider (parked)** (4 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **DEK cache: 1024-entry LRU with no expiry** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Provider registry shutdown path (manager -> registry -> provider)** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Thread request context to the key provider** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Rewrap campaign is a full server-side rewrite, not a metadata edit** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Three rotation mechanisms: rotate, retire version, move key** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Token-only Vault authentication in first release** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Missing request coalescing around DEK unwrap** (2 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Demo Vault compose defects (unpinned image, obsolete login)** (1 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Optional key_scope fingerprint salt** (1 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Explicit allow_plaintext_transport for demo Vault** (1 connections) — `docs/tickets/025-tink-kms-hcvault.md`
- **Tink stub and module removed; type tink refused by name** (1 connections) — `docs/tickets/025-tink-kms-hcvault.md`

## Relationships

- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (2 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (2 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (1 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)
- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (1 shared connections)

## Source Files

- `docs/tickets/025-tink-kms-hcvault.md`

## Audit Trail

- EXTRACTED: 23 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*