# Helm ConfigMap and Deployment

> 26 nodes · cohesion 0.09

## Key Concepts

- **deployment.yaml** (9 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **configmap.yaml (renders config.yaml)** (5 connections) — `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- **s3-encryption-proxy.probe helper** (4 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **helm-unittest suite: deployment, service and configmap** (4 connections) — `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- **s3-encryption-proxy.validateReplicas** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **servicetls-certificate.yaml (cert-manager Certificate for the Service)** (3 connections) — `deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml`
- **serviceTLS (TLS at the proxy's own Service)** (3 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **s3-encryption-proxy.validatePreStop** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **s3-encryption-proxy.validateTLS** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **PodDisruptionBudget Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **Dedicated Monitoring Service Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- **service.yaml** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- **Prometheus ServiceMonitor Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **s3-encryption-proxy.serviceDNSNames (four computed Service names)** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml`
- **preStopSleepSeconds (EndpointSlice withdrawal budget)** (2 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **Injected blocks are added, never merged into .Values.config** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- **checksum/config hashes the RENDERED ConfigMap** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **HorizontalPodAutoscaler Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- **Ingress Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`
- **PDB Render-Time Fail Guard** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **Namespace/Release Job Label Relabeling** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **livenessProbe on /livez** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **probes.scheme derived from tls.enabled in the rendered config** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **One instance only: a multipart upload lives in the process that created it** (1 connections) — `deploy/helm/s3-encryption-proxy/values-production.yaml`
- **readinessProbe on /readyz (the lifecycle signal)** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- *... and 1 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `deploy/helm/s3-encryption-proxy/templates/configmap.yaml`
- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- `deploy/helm/s3-encryption-proxy/templates/ingress.yaml`
- `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- `deploy/helm/s3-encryption-proxy/templates/service.yaml`
- `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- `deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml`
- `deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`
- `deploy/helm/s3-encryption-proxy/values-production.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 26 (90%)
- INFERRED: 3 (10%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*