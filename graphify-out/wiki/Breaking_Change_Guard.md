# Breaking Change Guard

> 10 nodes · cohesion 0.24

## Key Concepts

- **Breaking Change Guard** (6 connections) — `.github/workflows/breaking-change-guard.yml`
- **Version Dry Run job** (5 connections) — `.github/workflows/version-dry-run.yml`
- **Release 4.0.0** (4 connections) — `CHANGELOG.md`
- **ADR 0018: a major release is declared by a label** (2 connections) — `.github/workflows/breaking-change-guard.yml`
- **release:major label** (2 connections) — `.github/workflows/breaking-change-guard.yml`
- **check-breaking-changes.sh detector** (1 connections) — `.github/workflows/breaking-change-guard.yml`
- **Pull-request title and body inspection** (1 connections) — `.github/workflows/breaking-change-guard.yml`
- **npm clean-install --ignore-scripts under a write token** (1 connections) — `.github/workflows/version-dry-run.yml`
- **BREAKING: metadata_key_prefix must match ^[a-z0-9-]+$** (1 connections) — `CHANGELOG.md`
- **BREAKING: /debug/pprof on its own loopback listener** (1 connections) — `CHANGELOG.md`

## Relationships

- [Release Workflow](Release_Workflow.md) (2 shared connections)

## Source Files

- `.github/workflows/breaking-change-guard.yml`
- `.github/workflows/version-dry-run.yml`
- `CHANGELOG.md`

## Audit Trail

- EXTRACTED: 10 (77%)
- INFERRED: 3 (23%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*