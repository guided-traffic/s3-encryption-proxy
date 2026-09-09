# Release Workflow Jobs

> 15 nodes · cohesion 0.14

## Key Concepts

- **Semantic Release job** (13 connections) — `.github/workflows/release.yml`
- **Build Docker Image job** (3 connections) — `.github/workflows/push.yml`
- **Release Helm Chart to GitHub Pages job** (3 connections) — `.github/workflows/push.yml`
- **Code Linting job** (3 connections) — `.github/workflows/release.yml`
- **SBOM, provenance and Docker Scout scan** (2 connections) — `.github/workflows/push.yml`
- **GoSec Security Scan job** (2 connections) — `.github/workflows/release.yml`
- **Malware Scan (ClamAV) job** (2 connections) — `.github/workflows/release.yml`
- **golangci-lint v2 schema version key** (2 connections) — `.golangci.yml`
- **Helm repo index on gh-pages** (1 connections) — `.github/workflows/push.yml`
- **Coverage badge committed with the release** (1 connections) — `.github/workflows/release.yml`
- **e2e-velero as a release gate** (1 connections) — `.github/workflows/release.yml`
- **Pinned golangci-lint v2 module path** (1 connections) — `.github/workflows/release.yml`
- **Vulnerability Check job** (1 connections) — `.github/workflows/release.yml`
- **staticcheck checks minus ST and QF** (1 connections) — `.golangci.yml`
- **gosec G101 and G115 excluded in test files** (1 connections) — `.golangci.yml`

## Relationships

- [Combined Coverage CI Job](Combined_Coverage_CI_Job.md) (2 shared connections)
- [Breaking Change Guard](Breaking_Change_Guard.md) (2 shared connections)
- [Dead Configuration Keys](Dead_Configuration_Keys.md) (1 shared connections)
- [Velero E2E CI Job](Velero_E2E_CI_Job.md) (1 shared connections)
- [TLS Integration CI Job](TLS_Integration_CI_Job.md) (1 shared connections)

## Source Files

- `.github/workflows/push.yml`
- `.github/workflows/release.yml`
- `.golangci.yml`

## Audit Trail

- EXTRACTED: 16 (73%)
- INFERRED: 6 (27%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*