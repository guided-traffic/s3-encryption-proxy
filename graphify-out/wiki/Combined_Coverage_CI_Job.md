# Combined Coverage CI Job

> 8 nodes · cohesion 0.29

## Key Concepts

- **Combined Coverage job** (4 connections) — `.github/workflows/release.yml`
- **Combined coverage merge (GOCOVERDIR)** (3 connections) — `.github/workflows/release.yml`
- **Unit Tests job** (3 connections) — `.github/workflows/release.yml`
- **The Go version lives in exactly two files** (3 connections) — `CLAUDE.md`
- **Assign on Renovate pipeline failure** (2 connections) — `.github/workflows/renovate-assign-on-failure.yml`
- **Renovate Application job** (2 connections) — `.github/workflows/renovate.yml`
- **Test and Release workflow** (1 connections) — `.github/workflows/release.yml`
- **Combined unit and integration coverage commands** (1 connections) — `CONTRIBUTING.md`

## Relationships

- [Release Workflow Jobs](Release_Workflow_Jobs.md) (2 shared connections)
- [TLS Integration CI Job](TLS_Integration_CI_Job.md) (1 shared connections)

## Source Files

- `.github/workflows/release.yml`
- `.github/workflows/renovate-assign-on-failure.yml`
- `.github/workflows/renovate.yml`
- `CLAUDE.md`
- `CONTRIBUTING.md`

## Audit Trail

- EXTRACTED: 7 (64%)
- INFERRED: 4 (36%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*