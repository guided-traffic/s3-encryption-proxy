# Grafana Dashboard Custom Annotations

## Übersicht

Die Grafana Dashboard ConfigMap unterstützt vollständig konfigurierbare **Custom Annotations** für erweiterte Dashboard-Verwaltung und Integration.

## ⚙️ Konfiguration

### values.yaml
```yaml
monitoring:
  grafana:
    dashboard:
      enabled: true
      namespace: monitoring
      labels:
        grafana_dashboard: "1"
        # Custom Labels
      annotations:
        # Custom Annotations hier definieren
```

### values-monitoring.yaml (Produktions-Beispiel)
```yaml
monitoring:
  grafana:
    dashboard:
      enabled: true
      namespace: monitoring
      labels:
        grafana_dashboard: "1"
        app.kubernetes.io/component: dashboard
        dashboard-category: monitoring
        team: platform-engineering
        environment: production
      annotations:
        grafana-folder: "S3 Encryption Proxy"
        grafana.com/dashboard-uid: s3ep-performance
        grafana.com/auto-import: "true"
        description: "Performance monitoring dashboard for S3 Encryption Proxy"
        kubernetes.io/managed-by: Helm
        config.kubernetes.io/local-config: "true"
        meta.helm.sh/release-name: "s3-encryption-proxy"
        contact: "platform-team@company.com"
        documentation: "https://docs.company.com/s3ep-monitoring"
```

## 📋 Unterstützte Custom Annotations

### Grafana-spezifische Annotations
| Annotation | Beschreibung | Beispiel |
|------------|-------------|----------|
| `grafana-folder` | Grafana Folder für Dashboard-Organisation | `"S3 Encryption Proxy"` |
| `grafana.com/dashboard-uid` | Eindeutige Dashboard ID | `"s3ep-performance"` |
| `grafana.com/auto-import` | Automatischer Import durch Grafana | `"true"` |
| `grafana.com/refresh-interval` | Standard Refresh-Intervall | `"30s"` |
| `grafana.com/time-range` | Standard Zeitbereich | `"1h"` |

### Kubernetes-Management Annotations
| Annotation | Beschreibung | Beispiel |
|------------|-------------|----------|
| `kubernetes.io/managed-by` | Management-Tool | `"Helm"` |
| `config.kubernetes.io/local-config` | Lokale Konfiguration | `"true"` |
| `meta.helm.sh/release-name` | Helm Release Name | `"s3-encryption-proxy"` |
| `app.kubernetes.io/managed-by` | Application Management | `"Helm"` |

### Organisations-Annotations
| Annotation | Beschreibung | Beispiel |
|------------|-------------|----------|
| `description` | Dashboard-Beschreibung | `"Performance monitoring dashboard"` |
| `contact` | Kontakt-Information | `"platform-team@company.com"` |
| `documentation` | Link zur Dokumentation | `"https://docs.company.com/monitoring"` |
| `owner` | Dashboard-Besitzer | `"platform-engineering"` |
| `version` | Dashboard-Version | `"v1.2.3"` |
| `environment` | Umgebung | `"production"`, `"staging"`, `"development"` |

## 🎯 Use Cases

### 1. **Multi-Tenant Grafana Setup**
```yaml
annotations:
  grafana-instance: "production"
  tenant: "platform-team"
  environment: "prod"
```

### 2. **Automatisierte Dashboard-Verwaltung**
```yaml
annotations:
  grafana.com/auto-import: "true"
  grafana.com/dashboard-uid: "s3ep-perf-prod"
  config.kubernetes.io/managed-by: "ArgoCD"
```

### 3. **Compliance & Auditing**
```yaml
annotations:
  compliance.company.com/reviewed: "2025-09-12"
  security.company.com/approved: "true"
  audit.company.com/last-update: "2025-09-12T10:30:00Z"
```

### 4. **Integration mit anderen Tools**
```yaml
annotations:
  pagerduty.com/service-key: "PXXXXXX"
  slack.com/channel: "#platform-alerts"
  jira.com/project: "PLATFORM"
```

## 🔧 Template-Verarbeitung

Das Helm Template verarbeitet Annotations wie folgt:

```yaml
{{- if .Values.monitoring.grafana.dashboard.enabled }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "s3-encryption-proxy.fullname" . }}-grafana-dashboard
  namespace: {{ .Values.monitoring.grafana.dashboard.namespace | default .Release.Namespace }}
  labels:
    {{- include "s3-encryption-proxy.labels" . | nindent 4 }}
    {{- with .Values.monitoring.grafana.dashboard.labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- with .Values.monitoring.grafana.dashboard.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
data:
  s3ep-performance-dashboard.json: |
{{ .Files.Get "dashboards/s3ep-performance-dashboard.json" | indent 4 }}
{{- end }}
```

## ✅ Validierung

Test das Helm Template:
```bash
# Template-Validierung
helm template test-release deploy/helm/s3-encryption-proxy \
  --values deploy/helm/s3-encryption-proxy/values-monitoring.yaml

# Lint-Check
helm lint deploy/helm/s3-encryption-proxy \
  --values deploy/helm/s3-encryption-proxy/values-monitoring.yaml
```

## 🚀 Deployment

```bash
# Mit custom Annotations deployen
helm upgrade --install s3-encryption-proxy deploy/helm/s3-encryption-proxy \
  --values deploy/helm/s3-encryption-proxy/values-monitoring.yaml \
  --namespace monitoring \
  --create-namespace
```

Die ConfigMap wird dann mit allen konfigurierten custom Annotations erstellt und kann von Grafana und anderen Tools automatisch erkannt und verarbeitet werden.
