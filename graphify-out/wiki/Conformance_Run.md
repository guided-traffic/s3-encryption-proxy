# Conformance Run

> 14 nodes · cohesion 0.19

## Key Concepts

- **conformance-run.sh** (12 connections) — `scripts/conformance-run.sh`
- **Conformance matrix job (minio, localstack)** (4 connections) — `.github/workflows/test-pipeline.yml`
- **Conformance (paid backends) job** (3 connections) — `.github/workflows/conformance-paid.yml`
- **pull_image()** (3 connections) — `scripts/conformance-run.sh`
- **conformance-run.sh script** (3 connections) — `scripts/conformance-run.sh`
- **start_localstack()** (3 connections) — `scripts/conformance-run.sh`
- **start_minio()** (3 connections) — `scripts/conformance-run.sh`
- **Billed backends run on a schedule, never on push or pull_request** (1 connections) — `.github/workflows/conformance-paid.yml`
- **Secrets read through env, never interpolated into script text** (1 connections) — `.github/workflows/conformance-paid.yml`
- **cleanup()** (1 connections) — `scripts/conformance-run.sh`
- **field()** (1 connections) — `scripts/conformance-run.sh`
- **S3EP_CONFORMANCE_BACKEND_NAME** (1 connections) — `scripts/conformance-run.sh`
- **S3EP_CONFORMANCE_PROXY_ENDPOINT** (1 connections) — `scripts/conformance-run.sh`
- **S3EP_CONFORMANCE_SEGMENT_SIZE** (1 connections) — `scripts/conformance-run.sh`

## Relationships

- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (1 shared connections)
- [CI Pipeline and Renovate Jobs](CI_Pipeline_and_Renovate_Jobs.md) (1 shared connections)
- [Configuration](Configuration.md) (1 shared connections)
- [Testing](Testing.md) (1 shared connections)

## Source Files

- `.github/workflows/conformance-paid.yml`
- `.github/workflows/test-pipeline.yml`
- `scripts/conformance-run.sh`

## Audit Trail

- EXTRACTED: 21 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*