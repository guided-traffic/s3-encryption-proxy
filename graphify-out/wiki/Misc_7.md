# Misc (7)

> 15 nodes · cohesion 0.14

## Key Concepts

- **Integrity is not configurable (inseparable from decryption)** (5 connections) — `CLAUDE.md`
- **Label index (N-, S-, P-, F- series)** (5 connections) — `docs/tickets/README.md`
- **Fixes F-1 to F-25** (4 connections) — `docs/tickets/README.md`
- **Threat-model findings N-1 to N-10** (4 connections) — `docs/tickets/README.md`
- **N-1: foreign objects fell back to pass-through (closed, fail-closed)** (3 connections) — `docs/tickets/README.md`
- **Encryption happens once, in orchestration.Manager** (2 connections) — `DEVELOPER.md`
- **F-11: allowlist of base-operation parameters replaces denylist** (2 connections) — `docs/tickets/README.md`
- **N-10: Helm chart shipped a working default KEK** (2 connections) — `docs/tickets/README.md`
- **S-1/S-6: unrouted DELETE sub-resource deleted the bucket** (2 connections) — `docs/tickets/README.md`
- **Sweep findings S-1 to S-15** (2 connections) — `docs/tickets/README.md`
- **Upload leg: every declared checksum verified against plaintext then dropped** (1 connections) — `CLAUDE.md`
- **F-13: every XML response body built with encoding/xml** (1 connections) — `docs/tickets/README.md`
- **F-14: utils.CleanupContext for cleanup outliving the request** (1 connections) — `docs/tickets/README.md`
- **N-4: Velero kopia repository default password** (1 connections) — `docs/tickets/README.md`
- **Parked items P-1 to P-13** (1 connections) — `docs/tickets/README.md`

## Relationships

- [Performance and Test Docs](Performance_and_Test_Docs.md) (1 shared connections)
- [Filename Encryption Ticket](Filename_Encryption_Ticket.md) (1 shared connections)
- [Exit Provider and Session Lifecycle](Exit_Provider_and_Session_Lifecycle.md) (1 shared connections)
- [Planned Work: SSE-C and HA](Planned_Work-_SSE-C_and_HA.md) (1 shared connections)
- [Key Hierarchy and Threat Rules](Key_Hierarchy_and_Threat_Rules.md) (1 shared connections)
- [Integrity and Tail-First Read](Integrity_and_Tail-First_Read.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `DEVELOPER.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 18 (86%)
- INFERRED: 3 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*