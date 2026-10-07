# CI Pipeline and Renovate Jobs

> 30 nodes · cohesion 0.09

## Key Concepts

- **Semantic Release job** (17 connections) — `.github/workflows/test-pipeline.yml`
- **Supported clients (Velero, rclone, s3cmd)** (9 connections) — `docs/operations/README.md`
- **coverage-summary.py** (6 connections) — `.github/scripts/coverage-summary.py`
- **Combined Coverage job** (4 connections) — `.github/workflows/test-pipeline.yml`
- **main()** (4 connections) — `.github/scripts/coverage-summary.py`
- **Self-hosted Renovate job** (3 connections) — `.github/workflows/renovate.yml`
- **E2E rclone (minio) job** (3 connections) — `.github/workflows/test-pipeline.yml`
- **E2E s3cmd (minio) job** (3 connections) — `.github/workflows/test-pipeline.yml`
- **E2E Velero (kind) job** (3 connections) — `.github/workflows/test-pipeline.yml`
- **Demo docker compose stack** (3 connections) — `docker-compose.demo.yml`
- **Velero** (3 connections) — `docs/operations/clients/velero.md`
- **read_profile()** (3 connections) — `.github/scripts/coverage-summary.py`
- **Assign on Renovate Pipeline Failure job** (2 connections) — `.github/workflows/renovate-assign-on-failure.yml`
- **Malware Scan job (ClamAV)** (2 connections) — `.github/workflows/test-pipeline.yml`
- **Unit Tests job** (2 connections) — `.github/workflows/test-pipeline.yml`
- **module_path()** (2 connections) — `.github/scripts/coverage-summary.py`
- **percent()** (2 connections) — `.github/scripts/coverage-summary.py`
- **Test pipeline workflow (test-pipeline.yml)** (1 connections) — `.github/workflows/test-pipeline.yml`
- **GoSec Security Scan job** (1 connections) — `.github/workflows/test-pipeline.yml`
- **Vulnerability Check job** (1 connections) — `.github/workflows/test-pipeline.yml`
- **Helm Chart job** (1 connections) — `.github/workflows/test-pipeline.yml`
- **Code Linting job** (1 connections) — `.github/workflows/test-pipeline.yml`
- **Race Detector job** (1 connections) — `.github/workflows/test-pipeline.yml`
- **One tool, one e2e job** (1 connections) — `docs/developer/testing.md`
- **BackupStorageLocation over HTTPS with path style** (1 connections) — `docs/operations/clients/velero.md`
- *... and 5 more nodes in this community*

## Relationships

- [Demo Stack and Integration Jobs](Demo_Stack_and_Integration_Jobs.md) (3 shared connections)
- [Client E2E Verdicts](Client_E2E_Verdicts.md) (2 shared connections)
- [Renovate Dependency Configuration](Renovate_Dependency_Configuration.md) (1 shared connections)
- [Pipeline](Pipeline.md) (1 shared connections)
- [Push](Push.md) (1 shared connections)
- [Conformance Run](Conformance_Run.md) (1 shared connections)
- [Release and Test Discipline ADRs](Release_and_Test_Discipline_ADRs.md) (1 shared connections)

## Source Files

- `.github/scripts/coverage-summary.py`
- `.github/workflows/renovate-assign-on-failure.yml`
- `.github/workflows/renovate.yml`
- `.github/workflows/test-pipeline.yml`
- `docker-compose.demo.yml`
- `docs/developer/testing.md`
- `docs/operations/README.md`
- `docs/operations/clients/velero.md`
- `test/e2e/velero/manifests/minio.yaml`

## Audit Trail

- EXTRACTED: 39 (83%)
- INFERRED: 8 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*