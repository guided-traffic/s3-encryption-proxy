# Performance and Test Docs

> 47 nodes · cohesion 0.05

## Key Concepts

- **ADR 0022: Tickets are work lists that get archived** (20 connections) — `docs/tickets/README.md`
- **CLAUDE.md AI coding instructions** (18 connections) — `CLAUDE.md`
- **ADR 0035: The README advertises, the reference lives under docs** (14 connections) — `CLAUDE.md`
- **ADR 0038: The security architecture is one page per perspective** (13 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- **CONTRIBUTING guide** (9 connections) — `CONTRIBUTING.md`
- **One stored format s3ep-gcm-seg-v2** (4 connections) — `CLAUDE.md`
- **Pull request requirements (fifteen required checks)** (4 connections) — `CONTRIBUTING.md`
- **Test layers (unit, integration, TLS, Velero, client e2e, conformance)** (4 connections) — `CONTRIBUTING.md`
- **A ticket is closed by moving it into the archive; extraction is the close (D4)** (4 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **Documentation has five homes (ADR, developer, operations, security, tickets)** (3 connections) — `CLAUDE.md`
- **Nothing outside the ticket directory references a ticket (D5)** (3 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **Five documentation homes; a statement goes to exactly one (D7)** (3 connections) — `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- **ADRs hold every decision, current state only, no code references** (2 connections) — `CLAUDE.md`
- **Three build tags: integration, conformance, e2e** (2 connections) — `CLAUDE.md`
- **Go version spelled out in exactly two files (Containerfile, go.mod)** (2 connections) — `CLAUDE.md`
- **Renovate 'Go toolchain' group bumps both literals and tools/go.mod together** (2 connections) — `CLAUDE.md`
- **A ticket is a work list, archived when work lands; nothing outside cites it** (2 connections) — `CLAUDE.md`
- **Conventional commits drive the release version** (2 connections) — `CONTRIBUTING.md`
- **release:major label guard for breaking changes** (2 connections) — `CONTRIBUTING.md`
- **Linters run via go tool from tools/go.mod** (2 connections) — `CONTRIBUTING.md`
- **An ADR carries no references into the code (D8)** (2 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **An ADR states the current decision only; rewritten, never superseded (D9)** (2 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **Status section says what is implemented vs only decided (D11)** (2 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **Every page ends with what it does not cover; a gap lives beside its mechanism (D2)** (2 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- **Stable H-<n> identifier for open gaps; closed gaps become prose (D3)** (2 connections) — `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- *... and 22 more nodes in this community*

## Relationships

- [Monitoring and Licence Removal](Monitoring_and_Licence_Removal.md) (7 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (5 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (4 shared connections)
- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (4 shared connections)
- [Release Process and Doc Homes](Release_Process_and_Doc_Homes.md) (4 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (3 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (3 shared connections)
- [Misc (7)](Misc_7.md) (1 shared connections)
- [Whole-Object Read Window](Whole-Object_Read_Window.md) (1 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `CONTRIBUTING.md`
- `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- `docs/adr/0038-the-security-architecture-is-one-page-per-perspective.md`
- `docs/adr/README.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 84 (91%)
- INFERRED: 8 (9%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*