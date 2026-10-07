# Pipeline

> 7 nodes · cohesion 0.29

## Key Concepts

- **Semantic-Release (dry run) job** (5 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **Semantic-release toolchain composite action** (2 connections) — `.github/actions/semantic-release-toolchain/action.yml`
- **Breaking-change marker inspection (commits, title, body)** (2 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **ignore-scripts on the pull-request gate** (1 connections) — `.github/actions/semantic-release-toolchain/action.yml`
- **The dry run must not drift from the release** (1 connections) — `.github/actions/semantic-release-toolchain/action.yml`
- **Two checkouts: named branch for same-repo, merge ref for forks** (1 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **release:major label is the declaration of a major** (1 connections) — `.github/workflows/semantic-release-dry-run.yml`

## Relationships

- [CI Pipeline and Renovate Jobs](CI_Pipeline_and_Renovate_Jobs.md) (1 shared connections)

## Source Files

- `.github/actions/semantic-release-toolchain/action.yml`
- `.github/workflows/semantic-release-dry-run.yml`

## Audit Trail

- EXTRACTED: 7 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*