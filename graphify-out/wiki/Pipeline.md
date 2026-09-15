# Pipeline

> 12 nodes · cohesion 0.20

## Key Concepts

- **Semantic Release job (main only)** (9 connections) — `.github/workflows/test-pipeline.yml`
- **Semantic-Release (dry run) job** (5 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **Semantic-release toolchain composite action** (3 connections) — `.github/actions/semantic-release-toolchain/action.yml`
- **Breaking-change marker inspection (commits, title, body)** (2 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **E2E rclone (minio) job** (2 connections) — `.github/workflows/test-pipeline.yml`
- **E2E s3cmd (minio) job** (2 connections) — `.github/workflows/test-pipeline.yml`
- **One tool, one e2e job, and each one gates the release** (2 connections) — `.github/workflows/test-pipeline.yml`
- **ignore-scripts on the pull-request gate** (1 connections) — `.github/actions/semantic-release-toolchain/action.yml`
- **The dry run must not drift from the release** (1 connections) — `.github/actions/semantic-release-toolchain/action.yml`
- **Two checkouts: named branch for same-repo, merge ref for forks** (1 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **release:major label is the declaration of a major** (1 connections) — `.github/workflows/semantic-release-dry-run.yml`
- **E2E Velero (kind) job** (1 connections) — `.github/workflows/test-pipeline.yml`

## Relationships

- [Conformance Paid](Conformance_Paid.md) (1 shared connections)
- [Docker Compose Demo](Docker_Compose_Demo.md) (1 shared connections)
- [Configmap](Configmap.md) (1 shared connections)
- [Push](Push.md) (1 shared connections)

## Source Files

- `.github/actions/semantic-release-toolchain/action.yml`
- `.github/workflows/semantic-release-dry-run.yml`
- `.github/workflows/test-pipeline.yml`

## Audit Trail

- EXTRACTED: 16 (94%)
- INFERRED: 1 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*