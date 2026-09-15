# Values

> 5 nodes · cohesion 0.40

## Key Concepts

- **s3-encryption-proxy.probe helper** (4 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **livenessProbe on /livez** (2 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **proxy-healthcheck sidecar polling /livez** (2 connections) — `docker-compose.demo.yml`
- **probes.scheme derived from tls.enabled in the rendered config** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **readinessProbe on /readyz (the lifecycle signal)** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`

## Relationships

- [Deployment](Deployment.md) (1 shared connections)
- [Docker Compose Demo](Docker_Compose_Demo.md) (1 shared connections)

## Source Files

- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`
- `docker-compose.demo.yml`

## Audit Trail

- EXTRACTED: 5 (83%)
- INFERRED: 1 (17%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*