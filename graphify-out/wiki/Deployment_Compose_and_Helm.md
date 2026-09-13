# Deployment Compose and Helm

> 33 nodes · cohesion 0.08

## Key Concepts

- **Proxy Deployment Template** (11 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **Proxy ConfigMap Template** (6 connections) — `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- **Helm Unittest Deployment Suite** (6 connections) — `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- **Demo Proxy Service (HTTP, container proxy)** (6 connections) — `docker-compose.demo.yml`
- **License JWT Volume Mount** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **PodDisruptionBudget Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **S3 API Service Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- **Prometheus ServiceMonitor Template** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **Default Chart Values** (3 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **Development Values Profile** (3 connections) — `deploy/helm/s3-encryption-proxy/values-development.yaml`
- **Monitoring Values Profile** (3 connections) — `deploy/helm/s3-encryption-proxy/values-monitoring.yaml`
- **MinIO Demo Backend Service** (3 connections) — `docker-compose.demo.yml`
- **Demo Proxy Service (TLS, container proxy-tls)** (3 connections) — `docker-compose.demo.yml`
- **Dedicated Monitoring Service Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- **Namespace/Release Job Label Relabeling** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **Default Proxy config.yaml Payload** (2 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **Hardened Pod and Container Security Context** (2 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **GOCOVER Instrumented Build and Shutdown Grace** (2 connections) — `docker-compose.demo.yml`
- **Health Check Sidecar** (2 connections) — `docker-compose.demo.yml`
- **s3-encryption-proxy Helm Chart** (1 connections) — `deploy/helm/s3-encryption-proxy/Chart.yaml`
- **cert-manager Certificate Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/certificate.yaml`
- **Grafana Dashboard ConfigMap Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/grafana-dashboard.yaml`
- **HorizontalPodAutoscaler Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- **Ingress Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`
- **NetworkPolicy Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/networkpolicy.yaml`
- *... and 8 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `deploy/helm/s3-encryption-proxy/Chart.yaml`
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
- `deploy/helm/s3-encryption-proxy/values.yaml`
- `docker-compose.demo.yml`

## Audit Trail

- EXTRACTED: 30 (73%)
- INFERRED: 8 (20%)
- AMBIGUOUS: 3 (7%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*