# Push

> 4 nodes · cohesion 0.50

## Key Concepts

- **Build Docker Image job (release:published)** (3 connections) — `.github/workflows/push.yml`
- **Release Helm Chart to GitHub Pages job** (2 connections) — `.github/workflows/push.yml`
- **SBOM, provenance and Docker Scout on the released image** (1 connections) — `.github/workflows/push.yml`
- **s3-encryption-proxy Helm chart (5.0.0)** (1 connections) — `deploy/helm/s3-encryption-proxy/Chart.yaml`

## Relationships

- [Pipeline](Pipeline.md) (1 shared connections)

## Source Files

- `.github/workflows/push.yml`
- `deploy/helm/s3-encryption-proxy/Chart.yaml`

## Audit Trail

- EXTRACTED: 3 (75%)
- INFERRED: 1 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*