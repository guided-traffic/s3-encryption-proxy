# Helm Chart Deployment

> 46 nodes · cohesion 0.06

## Key Concepts

- **Proxy Deployment Template** (12 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **Proxy ConfigMap Template** (7 connections) — `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- **Default Chart Values** (7 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **Helm Unittest Deployment Suite** (6 connections) — `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- **Demo Proxy Service (HTTP, container proxy)** (6 connections) — `docker-compose.demo.yml`
- **Production Values Profile** (5 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **PodDisruptionBudget Template** (4 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **Development Values Profile** (4 connections) — `deploy/helm/s3-encryption-proxy/values-development.yaml`
- **cert-manager Certificate Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/certificate.yaml`
- **License JWT Volume Mount** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **Ingress Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`
- **S3 API Service Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- **Prometheus ServiceMonitor Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **No Default AES Key Rule** (3 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **Monitoring Values Profile** (3 connections) — `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`
- **Hardened Pod and Container Security Context** (3 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **MinIO Demo Backend Service** (3 connections) — `docker-compose.demo.yml`
- **Demo Proxy Service (TLS, container proxy-tls)** (3 connections) — `docker-compose.demo.yml`
- **Helm Chart Configuration Reference** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **Chart Secrets Management Policy** (2 connections) — `deploy/helm/s3-encryption-proxy/README.md`
- **HorizontalPodAutoscaler Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- **NetworkPolicy Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/networkpolicy.yaml`
- **PDB Render-Time Fail Guard** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **Dedicated Monitoring Service Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- **Namespace/Release Job Label Relabeling** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- *... and 21 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `deploy/helm/s3-encryption-proxy/Chart.yaml`
- `deploy/helm/s3-encryption-proxy/README.md`
- `deploy/helm/s3-encryption-proxy/templates/certificate.yaml`
- `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `deploy/helm/s3-encryption-proxy/templates/grafana-dashboard.yaml`
- `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`
- `deploy/helm/s3-encryption-proxy/templates/networkpolicy.yaml`
- `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- `deploy/helm/s3-encryption-proxy/values-development.yaml`
- `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`
- `deploy/helm/s3-encryption-proxy/values-production.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`
- `docker-compose.demo.yml`
- `docker-scout.yml`

## Audit Trail

- EXTRACTED: 46 (75%)
- INFERRED: 12 (20%)
- AMBIGUOUS: 3 (5%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*