# Breaking Change Guard

> 12 nodes · cohesion 0.20

## Key Concepts

- **Breaking Change Guard** (6 connections) — `.github/workflows/breaking-change-guard.yml`
- **Version Dry Run job** (5 connections) — `.github/workflows/version-dry-run.yml`
- **Release 4.0.0** (4 connections) — `CHANGELOG.md`
- **What an attacker who takes the proxy gets** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **ADR 0018: a major release is declared by a label** (2 connections) — `.github/workflows/breaking-change-guard.yml`
- **release:major label** (2 connections) — `.github/workflows/breaking-change-guard.yml`
- **BREAKING: metadata_key_prefix must match ^[a-z0-9-]+$** (2 connections) — `CHANGELOG.md`
- **BREAKING: /debug/pprof on its own loopback listener** (2 connections) — `CHANGELOG.md`
- **check-breaking-changes.sh detector** (1 connections) — `.github/workflows/breaking-change-guard.yml`
- **Pull-request title and body inspection** (1 connections) — `.github/workflows/breaking-change-guard.yml`
- **npm clean-install --ignore-scripts under a write token** (1 connections) — `.github/workflows/version-dry-run.yml`
- **No multi-tenancy** (1 connections) — `SECURITY_ARCHITECTURE.md`

## Relationships

- [Release Workflow Jobs](Release_Workflow_Jobs.md) (2 shared connections)
- [Envelope Encryption Architecture](Envelope_Encryption_Architecture.md) (2 shared connections)

## Source Files

- `.github/workflows/breaking-change-guard.yml`
- `.github/workflows/version-dry-run.yml`
- `CHANGELOG.md`
- `SECURITY_ARCHITECTURE.md`

## Audit Trail

- EXTRACTED: 11 (65%)
- INFERRED: 6 (35%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*