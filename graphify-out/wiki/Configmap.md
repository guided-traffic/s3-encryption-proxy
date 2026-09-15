# Configmap

> 12 nodes · cohesion 0.18

## Key Concepts

- **configmap.yaml (renders config.yaml)** (5 connections) — `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- **helm-unittest suite: deployment, service and configmap** (5 connections) — `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- **serviceTLS (TLS at the proxy's own Service)** (4 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **servicetls-certificate.yaml (cert-manager Certificate for the Service)** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml`
- **Helm Chart job** (2 connections) — `.github/workflows/test-pipeline.yml`
- **Helm chart README** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **s3-encryption-proxy.validateTLS** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **service.yaml** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- **s3-encryption-proxy.serviceDNSNames (four computed Service names)** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml`
- **Injected blocks are added, never merged into .Values.config** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- **checksum/config hashes the RENDERED ConfigMap** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **Ingress Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`

## Relationships

- [Deployment](Deployment.md) (3 shared connections)
- [Pipeline](Pipeline.md) (1 shared connections)
- [Default](Default.md) (1 shared connections)
- [AES Example](AES_Example.md) (1 shared connections)

## Source Files

- `.github/workflows/test-pipeline.yml`
- `deploy/helm/s3-encryption-proxy/README.md`
- `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`
- `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- `deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml`
- `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 16 (89%)
- INFERRED: 2 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*