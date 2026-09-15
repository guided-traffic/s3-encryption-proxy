# Deployment

> 10 nodes · cohesion 0.20

## Key Concepts

- **deployment.yaml** (9 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **s3-encryption-proxy.validatePreStop** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- **PodDisruptionBudget Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **Dedicated Monitoring Service Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- **Prometheus ServiceMonitor Template** (2 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **preStopSleepSeconds (EndpointSlice withdrawal budget)** (2 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`
- **HorizontalPodAutoscaler Template** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- **PDB Render-Time Fail Guard** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- **Namespace/Release Job Label Relabeling** (1 connections) — `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- **terminationGracePeriodSeconds derived from preStop + shutdown_timeout + 5** (1 connections) — `deploy/helm/s3-encryption-proxy/values.yaml`

## Relationships

- [Configmap](Configmap.md) (3 shared connections)
- [Values](Values.md) (1 shared connections)
- [AES Example](AES_Example.md) (1 shared connections)

## Source Files

- `deploy/helm/s3-encryption-proxy/templates/deployment.yaml`
- `deploy/helm/s3-encryption-proxy/templates/hpa.yaml`
- `deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml`
- `deploy/helm/s3-encryption-proxy/templates/service-monitoring.yaml`
- `deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml`
- `deploy/helm/s3-encryption-proxy/values.yaml`

## Audit Trail

- EXTRACTED: 12 (86%)
- INFERRED: 2 (14%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*