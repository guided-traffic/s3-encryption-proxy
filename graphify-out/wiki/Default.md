# Default

> 7 nodes · cohesion 0.29

## Key Concepts

- **values.yaml (chart defaults)** (4 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **config/default.yaml (the configuration the image starts with)** (2 connections) — `config/default.yaml`
- **values-production.yaml** (2 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **Chart version, appVersion and image tag rewritten from the release tag** (1 connections) — `.github/workflows/push.yml`
- **The image default is aes, not exit, so a missing key refuses the start** (1 connections) — `config/default.yaml`
- **values-development.yaml** (1 connections) — `deploy/helm/s3-encryption-proxy/values-development.yaml`
- **values-monitoring.yaml** (1 connections) — `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`

## Relationships

- No strong cross-community connections detected

## Source Files

- `.github/workflows/push.yml`
- `config/default.yaml`
- `deploy/helm/s3-encryption-proxy/values-development.yaml`
- `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`
- `deploy/helm/s3-encryption-proxy/values-production.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 5 (83%)
- INFERRED: 1 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*