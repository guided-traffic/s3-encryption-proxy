# S3 Encryption Proxy - Monitoring & Performance Dashboard

## Übersicht

Das S3 Encryption Proxy System verfügt über ein umfassendes Prometheus-basiertes Monitoring-System mit Grafana Dashboard zur Performance-Analyse.

## Features

### 📊 Prometheus Metriken

#### License Monitoring
- `s3ep_license_info` - License-Status mit Details (Lizenzinhaber, Firma, Ablaufdatum)
- `s3ep_license_days_remaining` - **Verbleibende Tage bis License-Ablauf**
- `s3ep_license_expiry_timestamp` - License-Ablauf als Unix Timestamp

#### Performance Monitoring
- `s3ep_proxy_performance_seconds` - **Zeit für verschiedene Request-Phasen**:
  - `total` - Gesamte Request-Zeit (Client → Proxy → S3 → Client)
  - `s3_backend` - Zeit für S3-Backend Operationen
  - `encryption` - Zeit für Verschlüsselung/Entschlüsselung
  - `client_transfer` - Zeit für Client-Datenübertragung

- `s3ep_download_throughput_mbps` - **Download-Durchsatz in MB/s** nach Objektgröße

#### Request Monitoring
- `s3ep_requests_total` - HTTP Requests nach Method, Endpoint, Status Code
- `s3ep_request_duration_seconds` - Request-Laufzeit
- `s3ep_s3_operations_total` - S3 Operationen
- `s3ep_encryption_operations_total` - Verschlüsselungsoperationen

#### System Monitoring
- `s3ep_server_info` - Server Build-Informationen
- `s3ep_encryption_providers_info` - Verschlüsselungs-Provider Status
- `s3ep_active_connections` - Aktive Verbindungen
- `s3ep_bytes_transferred_total` - Übertragene Bytes

### 🚀 Monitoring Endpoints

| Endpoint | Beschreibung |
|----------|-------------|
| `http://localhost:9090/metrics` | Prometheus Metriken |
| `http://localhost:9090/health` | Health Check |
| `http://localhost:9090/info` | Server Informationen |

### Grafana Dashboard ConfigMap

Das Dashboard wird als Kubernetes ConfigMap deployed mit konfigurierbaren Labels und Annotations:

```yaml
monitoring:
  grafana:
    dashboard:
      enabled: true
      namespace: monitoring
      # Custom Labels für Dashboard Discovery
      labels:
        grafana_dashboard: "1"              # Standard Grafana Discovery Label
        app.kubernetes.io/component: dashboard
        dashboard-category: monitoring      # Kategorisierung
        team: platform-engineering          # Team-Zuordnung
        environment: production             # Environment-spezifisch
      # Custom Annotations für Dashboard-Konfiguration
      annotations:
        grafana-folder: "S3 Encryption Proxy"           # Grafana Folder
        grafana.com/dashboard-uid: s3ep-performance      # Dashboard UID
        grafana.com/auto-import: "true"                  # Auto-Import aktivieren
        description: "Performance monitoring dashboard"  # Beschreibung
        kubernetes.io/managed-by: Helm                   # Management Info
        config.kubernetes.io/local-config: "true"       # Config-Management
```

**Unterstützte Custom Annotations:**
- `grafana-folder` - Grafana Folder für Dashboard-Organisation
- `grafana.com/dashboard-uid` - Eindeutige Dashboard ID
- `grafana.com/auto-import` - Automatischer Import durch Grafana
- `description` - Dashboard-Beschreibung
- `kubernetes.io/managed-by` - Management-Tool Info
- `config.kubernetes.io/local-config` - Lokale Konfiguration
- `meta.helm.sh/release-name` - Helm Release Info

### 📈 Grafana Dashboard Features

Das Dashboard zeigt:

1. **Request Rate** - HTTP Requests pro Sekunde
2. **License Days Remaining** - Verbleibende Lizenz-Tage (mit Warnschwellen)
3. **Proxy Performance** - Gesamte Request-Zeit (50th & 95th Perzentil)
4. **Download Throughput** - Durchsatz nach Objektgröße
5. **Performance Breakdown** - Aufschlüsselung nach Phasen:
   - S3 Backend Zeit
   - Verschlüsselungszeit
   - Client Transfer Zeit
6. **Encryption Operations** - Verschlüsselungsoperationen pro Sekunde
7. **License Status** - Aktueller License-Status

## 🐳 Docker Compose Setup

```yaml
services:
  s3-encryption-proxy:
    ports:
      - "8080:8080"     # S3 API
      - "9090:9090"     # Monitoring/Prometheus
```

## ⚙️ Konfiguration

### Command Line
```bash
./s3-encryption-proxy --monitoring --monitoring-port 9090
```

### YAML Config
```yaml
monitoring:
  enabled: true
  bind_address: ":9090"
  metrics_path: "/metrics"
```

## ☸️ Kubernetes/Helm Deployment

### values-monitoring.yaml
```yaml
monitoring:
  enabled: true
  port: 9090

  serviceMonitor:
    enabled: true
    namespace: monitoring

  grafana:
    dashboard:
      enabled: true
      labels:
        grafana_dashboard: "1"
```

### ServiceMonitor für Prometheus Operator
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: s3-encryption-proxy-monitoring
spec:
  selector:
    matchLabels:
      app.kubernetes.io/component: monitoring
  endpoints:
  - port: monitoring
    interval: 30s
```

## 📊 Performance Analyse

### Metriken verstehen

**Proxy Performance Phasen**:
- `total`: Gesamtzeit für Request (wichtigste Metrik für Client-Sicht)
- `s3_backend`: Zeit für S3-Backend (zeigt Storage-Performance)
- `client_transfer`: Zeit für Client-Übertragung (zeigt Netzwerk-Performance)
- `encryption`: Zeit für Ver-/Entschlüsselung (zeigt Encryption-Overhead)

**Objektgrößen-Kategorien**:
- `tiny`: < 1KB
- `small`: < 1MB
- `medium`: < 10MB
- `large`: < 100MB
- `huge`: ≥ 100MB

### Beispiel-Queries

```promql
# Durchschnittliche Download-Zeit nach Objektgröße
rate(s3ep_proxy_performance_seconds_sum{phase="total",operation="get"}[5m]) / rate(s3ep_proxy_performance_seconds_count{phase="total",operation="get"}[5m])

# Verschlüsselungs-Overhead
s3ep_proxy_performance_seconds{phase="encryption"} / s3ep_proxy_performance_seconds{phase="total"}

# Warnung bei < 7 Tagen License-Restlaufzeit
s3ep_license_days_remaining < 7
```

## 🔧 Makefile Targets

```bash
# Monitoring lokal testen
make run-monitoring

# Monitoring endpoints automatisch testen
make test-monitoring

# Helm mit Monitoring deployen
make helm-monitoring
```

## 🎯 Use Cases

### 1. Performance-Optimierung
- Vergleiche `s3_backend` vs `client_transfer` Zeit
- Identifiziere Bottlenecks bei verschiedenen Objektgrößen
- Monitore Verschlüsselungs-Overhead

### 2. License Management
- Überwache `s3ep_license_days_remaining`
- Setze Alerts bei < 30 Tagen
- Tracke License-Nutzung über Zeit

### 3. System Health
- Monitore Request-Erfolgsraten
- Verfolge aktive Provider-Status
- Überwache System-Ressourcen

## 🚨 Alerting Beispiele

```yaml
# Prometheus Alert Rules
groups:
- name: s3ep-alerts
  rules:
  - alert: S3EPLicenseExpiring
    expr: s3ep_license_days_remaining < 7
    labels:
      severity: warning
    annotations:
      summary: "S3EP License expires soon"

  - alert: S3EPHighLatency
    expr: histogram_quantile(0.95, rate(s3ep_proxy_performance_seconds_bucket{phase="total"}[5m])) > 5
    labels:
      severity: warning
    annotations:
      summary: "S3EP high request latency"
```

## 🔗 URLs (Demo Environment)

- **S3 API**: http://localhost:8080
- **Monitoring**: http://localhost:9090/metrics
- **Health Check**: http://localhost:9090/health
- **S3 Explorer (verschlüsselt)**: http://localhost:8081
- **S3 Explorer (direkt)**: http://localhost:8082
- **MinIO Console**: https://localhost:9001
