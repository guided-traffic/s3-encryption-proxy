# Default

> 7 nodes · cohesion 0.29

## Key Concepts

- **values.yaml (chart defaults)** (5 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **The image default is aes, not exit, so a missing key refuses the start** (2 connections) — `config/default.yaml`
- **config/default.yaml (the configuration the image starts with)** (2 connections) — `config/default.yaml`
- **values-production.yaml** (2 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **Chart version, appVersion and image tag rewritten from the release tag** (1 connections) — `.github/workflows/push.yml`
- **values-development.yaml** (1 connections) — `deploy/helm/s3-encryption-proxy/values-development.yaml`
- **values-monitoring.yaml** (1 connections) — `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`

## Relationships

- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (1 shared connections)
- [Configmap](Configmap.md) (1 shared connections)

## Source Files

- `.github/workflows/push.yml`
- `config/default.yaml`
- `deploy/helm/s3-encryption-proxy/values-development.yaml`
- `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`
- `deploy/helm/s3-encryption-proxy/values-production.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 6 (75%)
- INFERRED: 2 (25%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*