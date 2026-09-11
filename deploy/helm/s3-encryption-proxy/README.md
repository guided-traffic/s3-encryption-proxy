# S3 Encryption Proxy Helm Chart

This Helm chart deploys the S3 Encryption Proxy to a Kubernetes cluster.

The chart renders one Deployment, one Service and one ConfigMap, plus optional
Ingress, cert-manager Certificate, HPA, PodDisruptionBudget, NetworkPolicy,
Secret, monitoring Service, ServiceMonitor and Grafana dashboard ConfigMap.

## Prerequisites

- Kubernetes 1.23+ (the chart renders `autoscaling/v2` and `policy/v1`)
- Helm 3.2.0+
- cert-manager, only if `certificate.enabled` is set
- Prometheus Operator, only if `monitoring.serviceMonitor.enabled` is set
- **A license token.** Without one the proxy refuses to start with any provider
  type other than `exit` — see [The proxy needs three things](#the-proxy-needs-three-things-to-start).
- **A 256-bit AES key** for the `aes` provider, held in a Secret you manage
  yourself. The chart has no value for it on purpose.

## Installing the Chart

The release workflow packages the chart and publishes it to GitHub Pages:

```bash
helm repo add s3-encryption-proxy https://guided-traffic.github.io/s3-encryption-proxy/
helm install my-s3-proxy s3-encryption-proxy/s3-encryption-proxy
```

Or from a source checkout:

```bash
cd deploy/helm/s3-encryption-proxy
helm install my-s3-proxy .
```

> Installing from a checkout resolves the image tag from `Chart.yaml`
> `appVersion`, which is the placeholder `1.0.0` that the release workflow
> rewrites at package time. Pin `image.tag` when you install from source.

`deploy/helm/install.sh` wraps the same `helm install` into the namespace
`s3-encryption-proxy` and picks up `config/license.jwt` if it exists. It accepts
only `--dry-run`, `--upgrade` and `--help`; any positional argument is refused.

## Uninstalling the Chart

```bash
helm delete my-s3-proxy
```

## The proxy needs three things to start

A `helm install` with nothing but the chart defaults produces a pod that never
becomes ready. The defaults are a template, not a working deployment.

**1. A proxy configuration.** `config` is a **single string**, passed verbatim
into the ConfigMap as `config.yaml` — not a map of Helm values. There is no
`config.logLevel`, no `config.targetEndpoint`. Replace the whole block, or point
Helm at a file:

```bash
helm install my-s3-proxy . --set-file config=./my-config.yaml
```

The proxy refuses to start without `s3_backend.target_endpoint` and without at
least one entry under `s3_clients`. The full configuration reference is in the
[project README](../../../README.md#configuration).

**2. A license.** The startup gate ([ADR 0016](../../../docs/adr/0016-the-license-is-a-startup-gate.md))
admits provider type `exit` unlicensed; every other type, `aes` included, fails
startup without a valid token. The gate looks only at the provider named by
`encryption_method_alias`, which is what makes the exit provider a way out
without a license: it stores what the client sends and still decrypts objects
this proxy encrypted earlier, as long as the `aes` provider that holds their key
stays listed alongside it. `config/exit-example.yaml` in the source tree is that
configuration. Two routes for the licensed case, both supported:

| Route | How |
|---|---|
| Chart-managed | `license.jwt` (token inline) or `license.existingSecret` + `license.existingSecretKey`. The chart mounts it at `/app/license/license.jwt` and prepends `license_file:` to the rendered config |
| Environment | an `env` entry named `S3EP_LICENSE_TOKEN` with a `secretKeyRef`. The proxy also reads `S3EP_LICENSE` and `S3_ENCRYPTION_PROXY_LICENSE` |

**3. The credentials the config references.** The shipped `config` refers to
`${S3_ACCESS_KEY_ID}`, `${S3_SECRET_KEY}` and `${S3EP_AES_KEY}`. A `${VAR}`
reference whose variable is unset or empty is a **startup failure**, not an
empty string. The first two come from `secrets.s3.*`; the third you inject
yourself through `env`:

```yaml
env:
  - name: S3EP_AES_KEY
    valueFrom:
      secretKeyRef:
        name: s3-encryption-proxy-keys   # example
        key: aes-key                     # example
```

`${VAR}` expansion is not general: it is applied to `s3_backend.access_key_id`,
`s3_backend.secret_key`, `s3_clients[].access_key_id`, `s3_clients[].secret_key`
and the values under `encryption.providers[].config`. Anywhere else — a target
endpoint, a TLS path — the reference stays a literal.

## Configuration

> **Defaults are tuned for trying the proxy out**, not for production: a single
> replica, no PodDisruptionBudget, no NetworkPolicy, no autoscaling and no TLS.
> For production deployments start from `values-production.yaml`, which runs
> multiple replicas behind a PodDisruptionBudget and enables autoscaling,
> network policies, monitoring and cert-manager TLS. See
> [Production Installation with cert-manager](#production-installation-with-cert-manager).

Defaults below are the values in `values.yaml`.

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas; ignored when `autoscaling.enabled` | `1` |
| `nameOverride` | Overrides the chart name in the resource names and labels | `""` |
| `fullnameOverride` | Replaces the generated release-plus-chart resource name | `""` |
| `image.registry` | Container image registry | `docker.io` |
| `image.repository` | Container image repository | `guidedtraffic/s3-encryption-proxy` |
| `image.tag` | Image tag | `""` (falls back to chart `appVersion`) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Pull secrets for a private registry | `[]` |
| `serviceAccount.create` | Create a ServiceAccount | `true` |
| `serviceAccount.name` | ServiceAccount name; generated when empty | `""` |
| `serviceAccount.annotations` | ServiceAccount annotations | `{}` |
| `podAnnotations` | Pod annotations | `{}` |
| `podLabels` | Additional pod labels | `{}` |

The generated ServiceAccount sets `automountServiceAccountToken: false`. The
proxy never talks to the Kubernetes API.

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port; also the port the Ingress backend targets | `8080` |
| `service.targetPort` | Container port, named `http` | `8080` |
| `service.nodePort` | Fixed node port. Honoured only with `service.type: NodePort`; empty lets Kubernetes allocate one | `""` |
| `service.annotations` | Service annotations | `{}` |

`service.targetPort` must match the port `bind_address` listens on inside
`config`.

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsNonRoot` | Run as non-root user | `true` |
| `podSecurityContext.runAsUser` | User ID | `1001` |
| `podSecurityContext.runAsGroup` | Group ID | `1001` |
| `podSecurityContext.fsGroup` | Filesystem group | `1001` |
| `podSecurityContext.seccompProfile.type` | Seccomp profile | `RuntimeDefault` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.capabilities.drop` | Dropped capabilities | `[ALL]` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| `securityContext.runAsNonRoot` | Run as non-root user | `true` |
| `securityContext.runAsUser` | User ID | `1001` |

The container image is distroless and runs as UID 65532 by default; these values
override that with 1001. `readOnlyRootFilesystem` is satisfied by the `tmp`
emptyDir the chart always mounts at `/tmp`.

### Resource and Probe Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `250m` |
| `resources.requests.memory` | Memory request | `256Mi` |
| `livenessProbe` | Whole probe object, replaced as one | `GET /health` on port `http`, `initialDelaySeconds: 30`, `periodSeconds: 10`, `timeoutSeconds: 5`, `failureThreshold: 3` |
| `readinessProbe` | Whole probe object, replaced as one | `GET /health` on port `http`, `initialDelaySeconds: 5`, `periodSeconds: 5`, `timeoutSeconds: 3`, `failureThreshold: 3` |
| `probes.scheme` | Override the probe scheme. Empty derives it from `tls.enabled` in `config` | `""` |

`/health` is served by the same listener as the S3 API, so it speaks TLS as soon
as `config` sets `tls.enabled` — and a plaintext probe against a TLS listener
gets a 400, so the pod never becomes Ready and says nothing about why. The chart
derives the scheme from the config the pod will actually receive rather than from
a second value that can drift out of sync with it. Set `probes.scheme` only under
`configMap.useExistingConfigMap: true`, where the chart cannot see the config.

Memory is the limit to watch: a client-driven multipart upload holds a part that
does not cover whole segments until Complete, bounded per session by
`optimizations.multipart_short_part_buffer_size` (default 64 MB,
[ADR 0011](../../../docs/adr/0011-the-proxy-owns-the-part-layout.md)).

### Scheduling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | soft `podAntiAffinity` across `kubernetes.io/hostname` |

To remove the default anti-affinity, set `affinity: null`. Helm coalesces maps,
so `affinity: {}` leaves the chart default in place.

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable horizontal pod autoscaler | `false` |
| `autoscaling.minReplicas` | Minimum number of replicas | `2` |
| `autoscaling.maxReplicas` | Maximum number of replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target memory utilization; the metric is omitted when unset | unset |

### Availability Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PodDisruptionBudget | `false` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods during voluntary disruptions | `1` |
| `podDisruptionBudget.minAvailable` | Minimum available pods (alternative to `maxUnavailable`) | unset |

Set either `minAvailable` or `maxUnavailable`, never both - the chart fails the
render if both or neither are set. `maxUnavailable` is the default because it
stays drainable at any replica count, while `minAvailable` equal to the replica
count blocks node drains indefinitely.

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Hosts and paths | one host `s3-proxy.local`, path `/`, `pathType: Prefix` |
| `ingress.tls` | Ingress TLS configuration | `[]` |

An S3 object is arbitrarily large and streams through the proxy. Ingress
controllers that buffer a request body by default have to be told not to;
`values-production.yaml` carries the two nginx annotations that do it.

### Network Policy Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Render a NetworkPolicy | `false` |
| `networkPolicy.policyTypes` | Policy types | `[Ingress, Egress]` |
| `networkPolicy.ingress` | Ingress rules | allow TCP 8080 from anywhere |
| `networkPolicy.egress` | Egress rules | allow TCP 443, TCP/UDP 53 to anywhere |

The default egress rules assume the S3 backend is reachable on 443. A backend on
another port (MinIO on 9000, for example) is blocked until you add it. The
default ingress rules do not open the monitoring port; `values-production.yaml`
adds 9090.

### Certificate Configuration (cert-manager)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `certificate.enabled` | Render a cert-manager Certificate | `false` |
| `certificate.issuer.kind` | Certificate issuer kind | `ClusterIssuer` |
| `certificate.issuer.name` | Certificate issuer name | `letsencrypt-prod` |
| `certificate.dnsNames` | Certificate DNS names | `["s3-proxy.local"]` |
| `certificate.secretName` | Certificate secret name | `s3-proxy-tls` |
| `certificate.annotations` | Certificate annotations | `{}` |

This certificate is for TLS terminated at the Ingress. It is not wired into the
proxy's own listener — see [Pod TLS](#pod-tls-is-not-a-chart-feature).

### ConfigMap and Extra Mounts

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config` | The whole proxy `config.yaml`, as one string | see `values.yaml` |
| `configMap.useExistingConfigMap` | Do not render a ConfigMap | `false` |
| `configMap.existingConfigMapName` | Name of the ConfigMap to mount | `""` |
| `env` | Additional container environment variables, verbatim | `[]` |
| `volumes` | Additional pod volumes | `[]` |
| `volumeMounts` | Additional container volume mounts | `[]` |

The chart always creates a `config` volume from the ConfigMap at `/app/config`
and a `tmp` emptyDir at `/tmp`; `volumes` and `volumeMounts` are appended to
those. Set `existingConfigMapName` only together with
`useExistingConfigMap: true` — the name is used for the mount either way, so
setting it alone makes the chart render a ConfigMap over the name you meant to
reuse.

### Secrets Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.s3.accessKeyId` | Becomes the env var `S3_ACCESS_KEY_ID` | `""` |
| `secrets.s3.secretKey` | Becomes the env var `S3_SECRET_KEY` | `""` |
| `license.jwt` | License token, stored in the chart's Secret | `""` |
| `license.existingSecret` | Secret holding the license; takes precedence over `license.jwt` | `""` |
| `license.existingSecretKey` | Key inside `license.existingSecret` | `license.jwt` |

Both S3 environment variables are injected as soon as **either** `secrets.s3`
value is set, and both read from the chart's Secret. Set both or neither;
setting one leaves the other's `secretKeyRef` pointing at a key that does not
exist and the pod stays in `CreateContainerConfigError`.

### Monitoring Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.enabled` | Add `--monitoring` and the monitoring container port | `false` |
| `monitoring.port` | Monitoring port | `9090` |
| `monitoring.metricsPath` | Metrics path used by the ServiceMonitor | `/metrics` |
| `monitoring.service.enabled` | Render the separate monitoring Service | `false` |
| `monitoring.service.type` | Monitoring service type | `ClusterIP` |
| `monitoring.service.port` | Monitoring service port | `9090` |
| `monitoring.service.targetPort` | Monitoring target port | `9090` |
| `monitoring.service.annotations` | Monitoring service annotations | `{}` |
| `monitoring.serviceMonitor.enabled` | Render a Prometheus ServiceMonitor | `false` |
| `monitoring.serviceMonitor.namespace` | ServiceMonitor namespace | `monitoring` |
| `monitoring.serviceMonitor.interval` | Scrape interval | `30s` |
| `monitoring.serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `monitoring.serviceMonitor.labels` | Extra ServiceMonitor labels | `{}` |
| `monitoring.serviceMonitor.annotations` | ServiceMonitor annotations | `{}` |
| `monitoring.serviceMonitor.path` | Metrics path override | `""` (falls back to `monitoring.metricsPath`) |
| `monitoring.grafana.dashboard.enabled` | Render the dashboard ConfigMap | `false` |
| `monitoring.grafana.dashboard.namespace` | Dashboard namespace | `""` (release namespace) |
| `monitoring.grafana.dashboard.labels` | Dashboard discovery labels | `{grafana_dashboard: "1"}` |
| `monitoring.grafana.dashboard.annotations` | Dashboard annotations | `{}` |

The ServiceMonitor selects the monitoring Service by its
`app.kubernetes.io/component: monitoring` label, so `monitoring.service.enabled`
must be set as well or it matches nothing.

The proxy exports seven of its own metrics: `s3ep_requests_total`,
`s3ep_request_duration_seconds`, `s3ep_active_connections`, `s3ep_server_info`,
`s3ep_license_info`, `s3ep_license_expiry_timestamp` and
`s3ep_license_days_remaining`, plus the Go runtime and process collectors
(`go_*`, `process_*`).

**The bundled Grafana dashboard predates that list.** Four of its seven panels —
*Proxy Performance*, *Download Throughput*, *Performance Breakdown by Phase* and
*Encryption Operations Rate* — query `s3ep_proxy_performance_seconds`,
`s3ep_download_throughput_mbps` and `s3ep_encryption_operations_total`, which
were registered and never observed and are gone. Those panels have no series to
draw and stay empty. Rebuilding the dashboard against the metrics above is
outstanding work; `monitoring.grafana.dashboard.enabled` is `false` by default,
so nothing ships it unless it is asked for.

### Values nothing reads

These keys exist in `values.yaml` and change no rendered manifest. They are
listed so nobody spends an afternoon on them; removing them is outstanding work
([ADR 0013](../../../docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)).

| Parameter | Why it is inert |
|-----------|-----------------|
| `logging.enabled`, `logging.format`, `logging.level` | No template refers to them. Logging is configured by `log_level` and `log_format` inside `config` |
| `monitoring.serviceMonitor.port` | The ServiceMonitor endpoint is pinned to the named port `monitoring` |
| `secrets.gcp.serviceAccountKey` | Mounted at `/app/secrets`, but no provider reads it. The KMS provider it was meant for does not exist ([ADR 0005](../../../docs/adr/0005-a-kms-key-is-a-provider.md)) |
| `secrets.aws.accessKeyId`, `secrets.aws.secretAccessKey` | Written into the chart's Secret and referenced by nothing |

`metadata_key_prefix` sits under `encryption:` in the shipped `values.yaml`, at
the proxy's own default `s3ep-`. It used to sit inside the provider `config:`
block, where only `aes_key` is read and the rest is swallowed, so the file
claimed a prefix no deployment ever used. The prefix is the proxy's exclusive
metadata namespace ([ADR 0009](../../../docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md)),
validated at startup against `^[a-z0-9][a-z0-9-]{2,}-$`. **Changing it makes
every object written under the old one unreadable**: the read path accepts
prefixed metadata only, so those objects answer `403 InvalidObjectState`.

## Pod TLS is not a chart feature

The chart has no `tls.*` values. `values-production.yaml` terminates TLS at the
Ingress and the pod serves plain HTTP inside the cluster.

To make the proxy itself serve TLS, mount the certificate through the generic
`volumes`/`volumeMounts` and enable it in `config`:

```yaml
volumes:
  - name: tls
    secret:
      secretName: my-proxy-tls   # example
volumeMounts:
  - name: tls
    mountPath: /app/tls
    readOnly: true

config: |
  tls:
    enabled: true
    cert_file: "/app/tls/tls.crt"   # example
    key_file: "/app/tls/tls.key"    # example
  ...
```

`/health` is served by the same listener as the S3 API, so it speaks TLS too.
Both probes then need `scheme: HTTPS`, or the pod never becomes ready:

```yaml
readinessProbe:
  httpGet:
    path: /health
    port: http
    scheme: HTTPS
```

A worked example of this shape is the Velero e2e suite's values file,
[test/e2e/velero/values-proxy.yaml](../../../test/e2e/velero/values-proxy.yaml).

## Examples

### Basic Installation

```bash
helm install my-s3-proxy . \
  --set secrets.s3.accessKeyId="your-access-key" \
  --set secrets.s3.secretKey="your-secret-key" \
  --set license.existingSecret="s3-proxy-license" \
  --set-file config=./my-config.yaml
```

### Production Installation with cert-manager

```bash
helm install my-s3-proxy . \
  --values values-production.yaml \
  --set secrets.s3.accessKeyId="your-access-key" \
  --set secrets.s3.secretKey="your-secret-key" \
  --set license.existingSecret="s3-proxy-license" \
  --set 'certificate.dnsNames[0]=s3-proxy.yourdomain.com' \
  --set 'ingress.hosts[0].host=s3-proxy.yourdomain.com' \
  --set 'ingress.tls[0].hosts[0]=s3-proxy.yourdomain.com'
```

`values-production.yaml` expects `S3EP_AES_KEY` to come from a Secret named
`s3-encryption-proxy-keys` with the key `aes-key`. Every line in that file
marked `CHANGE ME` is a placeholder.

### Other values files

`values-development.yaml` points at an in-cluster MinIO with `log_level: debug`
and ships local-cluster credentials; `values-monitoring.yaml` turns on the
`monitoring` block, the ServiceMonitor and the Grafana dashboard and expects
`secrets.s3.*` and a KEK at install time. Both render, and `make helm-test`
renders all four override files plus the Velero e2e values on every run.

## Security Considerations

1. **The configuration is a ConfigMap.** `config` is rendered verbatim into a
   ConfigMap, which is not a secret store. A key written there is readable by
   anyone with `get configmaps` in the namespace. Keep the master key in a
   Secret you manage and reference it as `${S3EP_AES_KEY}` — this is why the
   chart ships no value for it
   ([ADR 0021](../../../docs/adr/0021-key-material-is-generated-never-committed.md)).

2. **Secrets in values files are not secrets.** `secrets.s3.*` and
   `license.jwt` are base64-encoded into a chart-managed Secret; base64 is
   encoding, not encryption, and the value ends up in Helm's release history.
   Prefer `--set` at install time, `license.existingSecret`, or an external
   secret manager.

3. **The default `config` reuses one key pair for two roles.** It hands the same
   `${S3_ACCESS_KEY_ID}` / `${S3_SECRET_KEY}` to `s3_backend` (the proxy's
   credentials against the backend) and to `s3_clients` (what clients present to
   the proxy). Give them separate credentials: a client holding the backend key
   reaches the bucket directly, where it can write unencrypted objects and
   delete stored ones without the proxy ever seeing the request. A client secret
   must be at least 16 characters, an access key at least 8.

4. **Backend TLS follows the endpoint scheme.** There is no toggle: an
   `s3_backend.target_endpoint` beginning `http://` sends backend traffic in
   clear. `s3_backend.insecure_skip_verify` disables certificate verification
   and belongs in test clusters only.

5. **Profiling has no chart surface, and should keep none.** A heap profile of
   this process contains data keys and plaintext. If you enable
   `monitoring.pprof_enabled` inside `config`, its listener must bind a loopback
   address — the proxy refuses to start otherwise — and it is reached with
   `kubectl port-forward`, never through a Service.

6. **Network Policies**: enable `networkPolicy` in production and replace the
   empty `from: []` selectors with your ingress controller and Prometheus
   namespaces. As shipped they allow the ports from anywhere.

7. **Pod Security**: the chart runs non-root with a read-only root filesystem,
   all capabilities dropped, `RuntimeDefault` seccomp and no mounted service
   account token.

8. **Availability**: the defaults run a single replica without a
   PodDisruptionBudget so that node drains never block. In production run at
   least 2 replicas and enable `podDisruptionBudget` so voluntary disruptions
   never take down more than one pod at a time.

The threat model behind these points is in
[SECURITY_ARCHITECTURE.md](../../../SECURITY_ARCHITECTURE.md).

## Known limitations

- **An externally managed ConfigMap or Secret does not restart pods.** The pod
  template hashes what the chart renders, so `helm upgrade` with a changed
  `config`, a rotated credential or a renewed license rolls the pods. With
  `configMap.useExistingConfigMap: true`, or with a Secret you manage yourself,
  the chart cannot see the content and nothing rolls; restart them yourself:
  `kubectl rollout restart deployment/<release>-s3-encryption-proxy` (the
  generated name is `<release>-<chart>` unless `fullnameOverride` is set).
- **The probe scheme cannot be derived from an external ConfigMap either.** With
  `configMap.useExistingConfigMap: true` the chart does not see `tls.enabled`,
  so set `probes.scheme` explicitly or a TLS pod never becomes Ready.

## Troubleshooting

### Common Issues

1. **Pod not starting, `license required for encryption provider type 'aes'`**:
   no license reached the container. Check `license.existingSecret`,
   `license.jwt` or the `S3EP_LICENSE_TOKEN` env var.
2. **Pod not starting, `environment variable ${...} is not set or empty`**: the
   config references a variable that no `env` entry or `secrets.s3` value
   provides.
3. **Pod not starting, `s3_backend.target_endpoint is required`**: the mounted
   config did not parse as expected, or the key is missing. The legacy top-level
   backend block is gone; the endpoint has to sit under `s3_backend`.
4. **Never becomes ready, probes fail**: the chart derives the probe scheme from
   `tls.enabled` in `config`. It cannot do that under
   `configMap.useExistingConfigMap: true` — set `probes.scheme: HTTPS` there.
5. **`helm template` fails with `values.config is not parseable YAML`**: `config`
   is one literal string (`config: |`), not a map, and it has to parse.
6. **Certificate issues**: ensure cert-manager is installed and the issuer is
   configured correctly.

### Debugging Commands

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=s3-encryption-proxy

# View logs
kubectl logs -l app.kubernetes.io/name=s3-encryption-proxy

# Check the rendered configuration (resource names are <release>-<chart>-...)
kubectl get configmap my-s3-proxy-s3-encryption-proxy-config -o jsonpath='{.data.config\.yaml}'

# Render locally without installing
helm template my-s3-proxy . --values values-production.yaml

# Check certificate status (if enabled)
kubectl describe certificate my-s3-proxy-s3-encryption-proxy-tls
```

## Contributing

Please refer to the main project repository for contribution guidelines.
