# Grafana Multi-Tenant Dashboard Configuration

## Übersicht

Das S3 Encryption Proxy Grafana Dashboard unterstützt Multi-Tenant-Filtering nach:
- **Namespace**: Kubernetes Namespace, in dem die Instanz läuft
- **Instanz**: Der Name des Helm-Releases (z.B. `my-s3-proxy`)

## Dashboard Template Variables

Das Dashboard verwendet zwei Prometheus Template Variables:

### 1. Job Variable
- **Name**: `job`
- **Label**: "Job (Namespace/Service)"
- **Type**: Query
- **Query**: `label_values(s3ep_requests_total, job)`
- **Format**: `namespace/release-name`

### 2. Instance Variable
- **Name**: `instance`
- **Label**: "Instance (Pod)"
- **Type**: Query
- **Query**: `label_values(s3ep_requests_total{job=~"$job"}, instance)`
- **Format**: Standard Kubernetes Pod-Namen

## ServiceMonitor Konfiguration

Der ServiceMonitor wird automatisch mit den korrekten Labels konfiguriert:

```yaml
metricRelabelings:
  - targetLabel: job
    replacement: "{{ .Release.Namespace }}/{{ .Release.Name }}"
  - targetLabel: helm_release
    replacement: "{{ .Release.Name }}"
```

## Deployment mit Multi-Tenant Support

### 1. Helm Chart Installation

```bash
# Installation mit spezifischem Release-Namen
helm install my-s3-proxy ./deploy/helm/s3-encryption-proxy \
  --namespace s3-proxy-prod \
  --create-namespace \
  -f deploy/helm/s3-encryption-proxy/values-monitoring.yaml
```

### 2. ServiceMonitor Labels

Der ServiceMonitor erstellt automatisch folgende Labels:
- `job`: `s3-proxy-prod/my-s3-proxy`
- `helm_release`: `my-s3-proxy`
- `instance`: Kubernetes Pod IP (Standard Prometheus)

### 3. Grafana Dashboard Import

Das Dashboard wird automatisch über ConfigMap importiert und steht sofort zur Verfügung.

## Verwendung des Dashboards

### Filtering nach Namespace/Release

1. **Job Dropdown**: Wählen Sie den gewünschten Job im Format `namespace/release-name`
   - Beispiel: `s3-proxy-prod/my-s3-proxy`
   - Beispiel: `s3-proxy-dev/dev-proxy`

2. **Instance Dropdown**: Wählen Sie spezifische Pod-Instanzen
   - Zeigt alle Pods des gewählten Jobs
   - Nützlich für Multi-Pod-Deployments

### Multi-Namespace Beispiele

```bash
# Produktions-Environment
helm install prod-s3-proxy ./deploy/helm/s3-encryption-proxy \
  --namespace production \
  --create-namespace

# Development-Environment  
helm install dev-s3-proxy ./deploy/helm/s3-encryption-proxy \
  --namespace development \
  --create-namespace

# Staging-Environment
helm install staging-s3-proxy ./deploy/helm/s3-encryption-proxy \
  --namespace staging \
  --create-namespace
```

Resultierende Jobs in Grafana:
- `production/prod-s3-proxy`
- `development/dev-s3-proxy`
- `staging/staging-s3-proxy`

## Metrics Queries mit Filtering

Alle Dashboard-Queries verwenden die Template Variables:

```promql
# Request Rate mit Filtering
rate(s3ep_requests_total{job=~"$job",instance=~"$instance"}[5m])

# Performance Metrics mit Filtering
histogram_quantile(0.95, rate(s3ep_proxy_performance_seconds_bucket{
  phase="total",
  job=~"$job",
  instance=~"$instance"
}[5m]))

# License Days Remaining mit Filtering
s3ep_license_days_remaining{job=~"$job",instance=~"$instance"}
```

## Troubleshooting

### 1. Job Labels erscheinen nicht

Überprüfen Sie, ob der ServiceMonitor korrekt deployed ist:

```bash
kubectl get servicemonitor -n <namespace>
kubectl describe servicemonitor <release-name> -n <namespace>
```

### 2. Keine Metriken im Dashboard

Überprüfen Sie die Prometheus Targets:

```bash
# Zugriff auf Prometheus UI
kubectl port-forward svc/prometheus-server 9090:80 -n monitoring

# Überprüfen Sie Status -> Targets
# Suchen Sie nach Ihrem s3-encryption-proxy Service
```

### 3. Template Variables laden nicht

Überprüfen Sie die Prometheus Data Source Konfiguration in Grafana:
- Data Source muss korrekt konfiguriert sein
- Prometheus muss die s3ep_* Metriken sammeln

## Anpassungen

### Custom Job Names

Falls Sie custom Job Names benötigen, können Sie den ServiceMonitor anpassen:

```yaml
# In values.yaml
monitoring:
  serviceMonitor:
    enabled: true
    # Custom metricRelabelings können hier hinzugefügt werden
```

### Additional Labels

Sie können zusätzliche Labels für granularere Filterung hinzufügen:

```yaml
metricRelabelings:
  - targetLabel: job
    replacement: "{{ .Release.Namespace }}/{{ .Release.Name }}"
  - targetLabel: helm_release
    replacement: "{{ .Release.Name }}"
  - targetLabel: environment
    replacement: "{{ .Values.environment | default "unknown" }}"
```

## Best Practices

1. **Konsistente Naming**: Verwenden Sie konsistente Release-Namen pro Environment
2. **Namespace Isolation**: Ein Namespace pro Environment/Team
3. **Resource Labels**: Nutzen Sie Kubernetes Labels für zusätzliche Gruppierung
4. **Monitoring Namespace**: Separater Namespace für Monitoring-Komponenten

## Siehe auch

- [Grafana Custom Annotations](GRAFANA_CUSTOM_ANNOTATIONS.md)
- [Prometheus Monitoring Setup](../README.md#monitoring)
- [Helm Chart Values](../deploy/helm/s3-encryption-proxy/values-monitoring.yaml)
