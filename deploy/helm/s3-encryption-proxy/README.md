# S3 Encryption Proxy Helm Chart

This Helm chart deploys the S3 Encryption Proxy to a Kubernetes cluster.

The chart renders one Deployment, one Service, one ConfigMap, one Secret and one
ServiceAccount, plus optional Ingress, cert-manager Certificates (one for the
Ingress, one for the proxy's own Service), PodDisruptionBudget, monitoring
Service, ServiceMonitor, PrometheusRule and Grafana dashboard ConfigMap. It renders no
NetworkPolicy: the network boundary belongs to the administrator (ADR 0030),
and no HorizontalPodAutoscaler: **this chart installs one instance and refuses
to render a second** (ADR 0033) — see
[One instance, and the chart refuses a second](#one-instance-and-the-chart-refuses-a-second).

## Prerequisites

- Kubernetes 1.34+, declared as `kubeVersion: ">=1.34.0-0"` in `Chart.yaml`.
  The pod's `preStop` hook uses the native `sleep` action, which is stable from
  1.34; an older cluster fails the install rather than running without the hook.
  The `-0` suffix is what lets a distribution version such as `1.34.4-gke.1`
  satisfy the requirement instead of being read as a prerelease.
- Helm 3.2.0+. `helm install` and `helm upgrade` read the real cluster version,
  so the `kubeVersion` floor above is checked against your cluster. A client-only
  `helm template` has no cluster to ask and falls back to the version its own
  binary was built against, which on an older Helm is below 1.34 and is refused —
  pass `--kube-version 1.34.0` to render offline on any client.
- cert-manager, only if `certificate.enabled` is set, or `serviceTLS.enabled`
  without `serviceTLS.existingSecret`
- Prometheus Operator, only if `monitoring.serviceMonitor.enabled` or
  `monitoring.prometheusRule.enabled` is set
- **A license token.** Without one the proxy refuses to start with any provider
  type other than `exit` — see [The proxy needs three things](#the-proxy-needs-three-things-to-start).
- **A 256-bit AES key** for the `aes` provider. The chart ships no key and no
  default; supply one through `secrets.encryption.*`.

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
> `appVersion`, which names the release this branch is heading for; the release
> workflow rewrites it to the tag at package time. Between releases that tag may
> not be published yet, so pin `image.tag` when you install from source.

`deploy/helm/install.sh`, run from the repository root, installs the chart as
release `s3-proxy` into the namespace `s3-encryption-proxy` with `values.yaml`,
and picks up `config/license.jwt` if it exists. It pins `image.tag` itself — the
most recent tag reachable from HEAD with the `v` stripped, else `Chart.yaml`
`appVersion`, else the short commit — so it installs the last released image
rather than the `appVersion` the note above is about. It accepts only
`--dry-run`, `--upgrade` and `--help` (`-h`); any positional argument is refused.

## Uninstalling the Chart

```bash
helm delete my-s3-proxy
```

## Upgrading to 5.0.0

Four things changed shape. Two of them refuse — the render fails, or the pod
does — and two are value keys the chart no longer declares, which Helm carries
into an upgrade with no error and no warning. Check your values file for all
four before you upgrade.

- **The backend block inside `config` is now the list `s3_backends`.** The
  entry's fields are unchanged: move the block under a single `- ` entry. A
  configuration still carrying the singular `s3_backend` refuses the start with
  a message saying so
  ([ADR 0013](../../../docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11),
  so this one is caught by the pod rather than by Helm. The release reads
  exactly one entry and refuses a second: the list is the shape, not yet the
  feature.
- **`replicaCount` above 1 and `autoscaling.enabled: true` now fail the
  render.** The shipped production profile asked for three replicas and
  autoscaling to twenty until this release, so a values file carrying either
  stops at `helm upgrade` with a message naming the value. A deployment that
  followed that profile goes from three pods to one — a capacity change to plan
  for, and one that was never serving client-driven multipart uploads correctly:
  see [One instance, and the chart refuses a second](#one-instance-and-the-chart-refuses-a-second).
- **`networkPolicy.*`**. The chart renders no NetworkPolicy any more (ADR 0030).
  If you set `networkPolicy.enabled: true`, **the upgrade removes the policy your
  release owns** and the pod is left with whatever the cluster's other policies
  say. Take the rules out of your values file into a NetworkPolicy of your own
  before upgrading; the policy is yours to maintain from here.
- **`monitoring.metricsPath` now reaches the proxy.** The chart renders a
  `monitoring:` block into its ConfigMap instead of passing `--monitoring` and
  `--monitoring-port` on the command line, which those flags could not carry. A
  path other than `/metrics` used to reach the ServiceMonitor alone, so every
  scrape was a 404; it is now what the proxy serves. If your values carry a
  `monitoring:` block inside `config` as a workaround, remove it — the chart
  refuses to render with both.

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

The proxy refuses to start without an `s3_backends` entry carrying a
`target_endpoint`, and without at least one entry under `s3_clients`. The
backend block is a list this release reads exactly one entry from; a second
entry refuses the start. The full configuration reference is in the
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
| Environment | an `env` entry named `S3EP_LICENSE_TOKEN` with a `secretKeyRef`. It is the one variable the proxy reads |

A written `license_file` is binding ([ADR 0013](../../../docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D13),
so on the chart-managed route a Secret that is missing or carries the wrong key
makes the pod fail to start with an error naming the file, instead of running on
a token from somewhere else. The environment route is read first and leaves the
key unwritten, so the pod starts on the variable alone.

**3. The credentials the config references.** The shipped `config` refers to
`${S3_ACCESS_KEY_ID}`, `${S3_SECRET_KEY}` and `${S3EP_AES_KEY}`. A `${VAR}`
reference whose variable is unset or empty is a **startup failure**, not an
empty string. The first two come from `secrets.s3.*`, the third from
`secrets.encryption.*`. An `env` entry does it too, and is what
`values-production.yaml` uses:

```yaml
env:
  - name: S3EP_AES_KEY
    valueFrom:
      secretKeyRef:
        name: s3-encryption-proxy-keys   # example
        key: aes-key                     # example
```

`${VAR}` expansion is not general: it is applied to
`s3_backends[].target_endpoint`, `s3_backends[].region`,
`s3_backends[].access_key_id`, `s3_backends[].secret_key`,
`s3_clients[].access_key_id`, `s3_clients[].secret_key` and the values under
`encryption.providers[].config`. Anywhere else — a bind address, a TLS path —
the reference stays a literal.

## Configuration

> **Defaults are tuned for trying the proxy out**, not for production: modest
> resource limits, no monitoring and no TLS.
> For production deployments start from `values-production.yaml`, which raises
> the limits and enables monitoring and cert-manager TLS at an Ingress. See
> [Production Installation with cert-manager](#production-installation-with-cert-manager).
> The replica count is not one of the differences: **this chart installs one
> instance** and every profile it ships runs one — see
> [One instance, and the chart refuses a second](#one-instance-and-the-chart-refuses-a-second).

Defaults below are the values in `values.yaml`.

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas. May only be 1; a higher value fails the render | `1` |
| `nameOverride` | Overrides the chart name in the resource names and labels | `""` |
| `fullnameOverride` | Replaces the generated resource name | `""` |
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
| `livenessProbe` | Whole probe object, replaced as one | `GET /livez` on port `http`, `initialDelaySeconds: 2`, `periodSeconds: 5`, `timeoutSeconds: 5`, `failureThreshold: 3` |
| `readinessProbe` | Whole probe object, replaced as one | `GET /readyz` on port `http`, `initialDelaySeconds: 5`, `periodSeconds: 5`, `timeoutSeconds: 3`, `failureThreshold: 3` |
| `probes.scheme` | Override the probe scheme. Empty derives it from `tls.enabled` in `config` | `""` |

The two probes answer two different questions
([ADR 0034](../../../docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md)).
`/livez` is a constant 200 and never reports the drain: the only reaction to a failing liveness
probe is a restart, and a restart during a shutdown would skip the multipart
sweep the process is in the middle of. `/readyz` answers 503 from the moment the
drain starts, which takes the pod out of the Service while the listener stays up.
Pointing both at one endpoint, which is what this chart did before the probes
were split, kills a draining pod by design.

There is no startup probe and `initialDelaySeconds` is 2 rather than 30: a
constant-200 handler needs no warm-up, and the proxy's whole startup path is
local, so there is no half-started window to cover. The effect is that a wedged
process is noticed after about 17 s instead of 60 s.

Both paths are served by the same listener as the S3 API, so they speak TLS as
soon as `config` sets `tls.enabled` — and a plaintext probe against a TLS
listener gets a 400, so the pod never becomes Ready and says nothing about why.
The chart derives the scheme from the config the pod will actually receive rather
than from a second value that can drift out of sync with it. Set `probes.scheme` only under
`configMap.useExistingConfigMap: true`, where the chart cannot see the config.

Memory is the limit to watch: a client-driven multipart upload holds a part that
does not cover whole segments until Complete, and
`optimizations.multipart_short_part_buffer_size` (default 64 MB,
[ADR 0011](../../../docs/adr/0011-the-proxy-owns-the-part-layout.md)) bounds what
every open upload holds there together.

### Scheduling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | soft `podAntiAffinity` across `kubernetes.io/hostname` |

To remove the default anti-affinity, set `affinity: null`. Helm coalesces maps,
so `affinity: {}` leaves the chart default in place.

### One instance, and the chart refuses a second

**This chart installs one proxy instance.** `replicaCount` above 1 and
`autoscaling.enabled: true` each fail the render with a message naming the value
and the reason
([ADR 0033](../../../docs/adr/0033-a-proxy-instance-holds-its-uploads.md)).

The reason is a property of the product, not a preference of the chart. A
client-driven multipart upload is not stateless: its part table and the object's
data key live in the process that answered `CreateMultipartUpload` and nowhere
else, so an `UploadPart` that lands on another pod names an upload that pod has
never heard of and is answered `404 NoSuchUpload` — `CompleteMultipartUpload`
and `ListParts` answer the same way. Nothing here makes a client reach the same
pod twice: the Service sets no `sessionAffinity` and the default Ingress
annotations carry none. A second replica therefore does not take a share of the
work, it takes requests belonging to an upload the first pod is holding.

**Several cooperating proxies are a change to the proxy, not to this chart.**
They need a session table the instances share, an owner for the sweeper and a
short-part bound that means something across processes — none of which is a
values key, because the state lives in the process. Until the proxy can hand an
upload to another instance, a replica count above one has nothing to configure.

One instance is a single point of failure, and a rollout is a gap rather than a
handover. While the pod drains, a new request is answered
`503 ServiceUnavailable` with `Retry-After` instead of a refused connection and
the transfers already running are finished inside `shutdown_timeout`
([ADR 0029](../../../docs/adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)) —
but with one pod there is no second one for an SDK to retry against, so the
client waits out the restart.

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Refused: `true` fails the render, see above | `false` |
| `autoscaling.minReplicas` | Minimum number of replicas; inert | `2` |
| `autoscaling.maxReplicas` | Maximum number of replicas; inert | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization; inert | `80` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target memory utilization; inert, and the metric is omitted when unset | unset |

The four keys under `enabled` are kept for the release that can use them. No
HorizontalPodAutoscaler renders today: `autoscaling.enabled: true` fails the
render before it, and `false` renders nothing.

### Availability Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable PodDisruptionBudget. Over a single pod it cannot protect the service | `false` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods during voluntary disruptions | `1` |
| `podDisruptionBudget.minAvailable` | Minimum available pods (alternative to `maxUnavailable`) | unset |
| `preStopSleepSeconds` | Seconds the pod holds still before the proxy is sent SIGTERM, as a `lifecycle.preStop.sleep` hook | `5` |
| `terminationGracePeriodSeconds` | Pod termination grace period | `""`, derived |

Set either `minAvailable` or `maxUnavailable`, never both - the chart fails the
render if both or neither are set. `maxUnavailable` is the default because it
stays drainable at any replica count, while `minAvailable` equal to the replica
count blocks node drains indefinitely.

At one replica there is nothing in between: `maxUnavailable: 1` lets a drain
take the only pod, and `minAvailable: 1` blocks every drain for as long as the
release exists. A single instance cannot be drained without downtime, which is
why `values-production.yaml` ships `podDisruptionBudget.enabled: false` — an
honest gap rather than a drain that never finishes.

`preStopSleepSeconds` buys the pod's EndpointSlice withdrawal time to reach
kube-proxy on every node. Without it the listener stops accepting in the same
moment that propagation begins, and for its duration the pod refuses connections
the cluster is still sending it. The hook has no opt-out — an opt-out is the
broken drain running silently — but its duration is a values key, because the
propagation time is a property of the cluster and not of the proxy. Five seconds
is well over what a small cluster needs, and every second is paid per pod on
every rollout. **A value below 1 fails the render**: a zero hold is the opt-out
this chart does not have, wearing a values key — it installs everywhere and
leaves the drain racing the withdrawal exactly as before the hook existed.

Left empty, `terminationGracePeriodSeconds` is
`preStopSleepSeconds` + `shutdown_timeout` from `config` + five seconds
([ADR 0015](../../../docs/adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)):
the hook, the proxy's own transfer budget, and the listener close with the
process exit. An absent or zero `shutdown_timeout` means the proxy's 30-second
fallback, so the derived value at the defaults is 40.

**An explicit `terminationGracePeriodSeconds` below that sum fails the render**,
naming all three numbers and the sum. It used to win outright, which left the
multipart sweep
([ADR 0028](../../../docs/adr/0028-an-abandoned-upload-is-ended-not-forgotten.md))
without a budget and said nothing: the pod was SIGKILLed mid-drain and every open
upload stayed at the backend. A shorter shutdown is had by lowering one of the two
numbers that mean something; the sum is only their consequence. A value at or
above the sum is honoured as before.

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

### Network Policy

The chart renders none, and has no `networkPolicy` values (ADR 0030). Which
namespaces may reach the proxy, and which port and address the S3 backend
listens on, are properties of the cluster the chart cannot know — so the rules
it used to ship were `from: []` and `to: []`, which in Kubernetes means "from
anywhere" and "to anywhere": a blanket grant under the name of a security
control. Write the policy for your own topology, or run without one knowingly.

The pod is an ordinary `NetworkPolicy` target: it carries the chart's standard
selector labels, serves the S3 API on `service.targetPort` and, with
`monitoring.enabled`, metrics on `monitoring.port`. Its egress goes to the
backend named by `s3_backends[0].target_endpoint` and to DNS.

### Certificate Configuration (cert-manager)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `certificate.enabled` | Render a cert-manager Certificate | `false` |
| `certificate.issuer.kind` | Certificate issuer kind | `ClusterIssuer` |
| `certificate.issuer.name` | Certificate issuer name | `letsencrypt-prod` |
| `certificate.dnsNames` | Certificate DNS names | `["s3-proxy.local"]` |
| `certificate.secretName` | Certificate secret name | `s3-proxy-tls` |
| `certificate.annotations` | Certificate annotations | `{}` |

This certificate is for TLS terminated at the Ingress; the chart does not wire it
into the proxy's own listener by itself. To serve it there too, set
`serviceTLS.enabled: true`, point `serviceTLS.existingSecret` at its secret and
give `certificate.dnsNames` the Service names — see [TLS at the Service](#tls-at-the-service).

**The chart refuses two TLS configurations that look like TLS and are not:**

- `ingress.enabled: true` with an empty `ingress.tls`, or an `ingress.hosts` entry
  that no `ingress.tls` entry covers. That host would be answered in plaintext,
  putting the client's S3 credentials and object keys on the wire in front of a
  proxy whose job is to keep the data confidential.
- `certificate.enabled: true` when nothing consumes `certificate.secretName`. A
  consumer is an `ingress.tls` entry naming that secret (with `ingress.enabled`),
  or `serviceTLS.enabled` with `serviceTLS.existingSecret` pointing at it — a pod
  that mounts the certificate consumes it just as an Ingress does
  ([ADR 0026](../../../docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md)).
  Issuing one nothing uses reads as "TLS is configured" and is not.

Both are render-time failures naming the values involved.

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
| `secrets.encryption.aesKey` | The key encryption key, base64 of 32 bytes, stored in the chart's Secret | `""` |
| `secrets.encryption.existingSecret` | A Secret holding the key; takes precedence over `aesKey` | `""` |
| `secrets.encryption.existingSecretKey` | Key inside `secrets.encryption.existingSecret` | `aes-key` |
| `license.jwt` | License token, stored in the chart's Secret | `""` |
| `license.existingSecret` | Secret holding the license; takes precedence over `license.jwt` | `""` |
| `license.existingSecretKey` | Key inside `license.existingSecret` | `license.jwt` |

Both S3 environment variables are injected as soon as **either** `secrets.s3`
value is set, and both read from the chart's Secret. Set both or neither;
setting one leaves the other's `secretKeyRef` pointing at a key that does not
exist and the pod stays in `CreateContainerConfigError`. `S3EP_AES_KEY` is
injected as soon as `secrets.encryption.aesKey` or `.existingSecret` is set;
with neither set and no `env` entry, `${S3EP_AES_KEY}` in `config` has
nothing to resolve to and the proxy refuses to start.

### Monitoring Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.enabled` | Render the `monitoring:` block into the ConfigMap and open the monitoring container port | `false` |
| `monitoring.port` | Monitoring port; becomes `monitoring.bind_address` | `9090` |
| `monitoring.metricsPath` | Metrics path; becomes `monitoring.metrics_path` and is what the ServiceMonitor scrapes | `/metrics` |
| `monitoring.service.enabled` | Render the separate monitoring Service (with `monitoring.enabled`) | `false` |
| `monitoring.service.type` | Monitoring service type | `ClusterIP` |
| `monitoring.service.port` | Monitoring service port | `9090` |
| `monitoring.service.annotations` | Monitoring service annotations | `{}` |
| `monitoring.serviceMonitor.enabled` | Render a Prometheus ServiceMonitor (with `monitoring.enabled`) | `false` |
| `monitoring.serviceMonitor.namespace` | ServiceMonitor namespace | `monitoring` |
| `monitoring.serviceMonitor.interval` | Scrape interval | `30s` |
| `monitoring.serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `monitoring.serviceMonitor.labels` | Extra ServiceMonitor labels | `{}` |
| `monitoring.serviceMonitor.annotations` | ServiceMonitor annotations | `{}` |
| `monitoring.serviceMonitor.path` | Metrics path override | `""` (falls back to `monitoring.metricsPath`) |
| `monitoring.prometheusRule.enabled` | Render the alerting rules (with `monitoring.enabled`) | `false` |
| `monitoring.prometheusRule.namespace` | PrometheusRule namespace | `""` (the release namespace) |
| `monitoring.prometheusRule.labels` | Extra PrometheusRule labels, for your Prometheus' rule selector | `{}` |
| `monitoring.prometheusRule.annotations` | PrometheusRule annotations | `{}` |
| `monitoring.prometheusRule.integrity.window` | Window for the integrity-failure alert | `5m` |
| `monitoring.prometheusRule.backend.window` | Rate window for the backend failure share | `5m` |
| `monitoring.prometheusRule.backend.failureRatio` | Share of backend round trips with no HTTP response that fires the alert | `0.1` |
| `monitoring.prometheusRule.backend.for` | How long that share must hold | `5m` |
| `monitoring.prometheusRule.license.warnDays` | Days before expiry that the licence alert fires | `30` |
| `monitoring.grafana.dashboard.enabled` | Render the dashboard ConfigMap | `false` |
| `monitoring.grafana.dashboard.namespace` | Dashboard namespace | `""` (release namespace) |
| `monitoring.grafana.dashboard.labels` | Dashboard discovery labels | `{grafana_dashboard: "1"}` |
| `monitoring.grafana.dashboard.annotations` | Dashboard annotations | `{}` |

The monitoring Service and the ServiceMonitor are gated on `monitoring.enabled`
too — with it `false` neither renders. The Grafana dashboard ConfigMap is not; it
renders on its own flag. The ServiceMonitor selects the monitoring Service by its
`app.kubernetes.io/component: monitoring` label, so `monitoring.service.enabled`
must be set as well or it matches nothing.

The proxy exports thirteen of its own metrics — request rate and latency, active
connections, build information, licence validity and expiry, object integrity
failures, the backend observation (last response, last failure by class, whether
anything was observed, and the two counters an alert reads) and the active
encryption provider — plus the Go runtime and process collectors (`go_*`,
`process_*`). The full table with labels is in the
[docs/operations/monitoring.md](../../../docs/operations/monitoring.md#metrics).

**The bundled dashboard draws all five of its panels** — request rate, request
latency, active connections, licence status and days to expiry — and a unit test
holds it to that: it fails if a panel names a series no scrape exports, and if
the `$job` or `$instance` variable resolves off a counter, which has no children
until the pod has served its first request and would leave a fresh pod looking
broken. Days to expiry is computed in the query,
`(s3ep_license_expiry_timestamp - time()) / 86400`, because a gauge for it would
be written once at startup and could never fall.
`monitoring.grafana.dashboard.enabled` is `false` by default.

### Alerting rules

`monitoring.prometheusRule.enabled` renders a `PrometheusRule` with four alerts.
**Every one of them tells a human, and nothing in the platform acts on any of
them** — that boundary is the decision
([ADR 0034](../../../docs/adr/0034-a-probe-reports-the-process-never-its-dependencies.md)
D5, D6): a probe that read a dependency would take every instance out of rotation
at the same moment that dependency failed.

| Alert | Fires when | Severity |
|---|---|---|
| `S3EPObjectIntegrityFailure` | `s3ep_object_integrity_failures_total` moves at all. It is supposed to stay at zero: a read was refused or cut because the stored object did not authenticate | critical |
| `S3EPBackendTransportFailing` | More than `backend.failureRatio` of backend round trips get no HTTP response for `backend.for` | warning |
| `S3EPLicenseExpiringSoon` | Less than `license.warnDays` left on the token | warning |
| `S3EPLicenseExpired` | `s3ep_license_info` is 0 | critical |

**The backend alert reads a share, never a count.** The AWS SDK retries, so an
ordinary network produces some transport failures and a bare counter cannot be
read; `s3ep_backend_responses_total` is the denominator that makes a threshold
mean something. Any HTTP answer counts as a response, a `403` included — the
question is whether the backend answered, not whether it agreed — so this alert
is about the network or the backend being gone, never about permissions.

A unit test holds the rules to the same contract as the dashboard: it fails if an
alert names a series no scrape exports, because an alert that cannot fire looks
exactly like an alert with nothing to report, and unlike an empty dashboard panel
nobody ever opens it.

The rules are off by default: thresholds nobody tuned page somebody at three in
the morning. Set your Prometheus' rule selector labels through
`monitoring.prometheusRule.labels`.

**The metrics listener has no authentication** — that is what makes an ordinary
Prometheus scrape work — and it names no licensee. What it exposes is request
rate and latency by route template, build version and commit, active connections,
the licence validity and expiry, the backend observation, **and the active
encryption provider**: `s3ep_encryption_provider_info` carries its alias, type and
key fingerprint, and `/status` on the same port repeats them. The `type` is the
field that matters — `exit` means this proxy is not encrypting and the backend
holds plaintext — so an unauthenticated reader of this port learns whether the
data behind the proxy is encrypted at rest. That is deliberate (ADR 0034 D8): an
operator has to be able to see it, and the alternative was putting it on the S3
listener where every client reaches it without a signature. Who may reach the
port is the operator's to decide; the chart ships no NetworkPolicy for it.

### Values nothing reads

These keys exist in `values.yaml` and change no rendered manifest. They are
listed so nobody spends an afternoon on them; removing them is outstanding work
([ADR 0013](../../../docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)).

| Parameter | Why it is inert |
|-----------|-----------------|
| `logging.enabled`, `logging.format`, `logging.level` | No template refers to them. Logging is configured by `log_level` and `log_format` inside `config` |
| `monitoring.serviceMonitor.port`, `monitoring.service.targetPort` | Both ends are pinned to the named port `monitoring` |

`metadata_key_prefix` sits under `encryption:` in the shipped `values.yaml`, at
the proxy's own default `s3ep-`. It used to sit inside the provider `config:`
block, where only `aes_key` is read and the rest is swallowed, so the file
claimed a prefix no deployment ever used. The prefix is the proxy's exclusive
metadata namespace ([ADR 0009](../../../docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md)),
validated at startup against `^[a-z0-9][a-z0-9-]{2,}-$`. **Changing it makes
every object written under the old one unreadable**: the read path accepts
prefixed metadata only, so those objects answer `403 InvalidObjectState`.

## TLS at the Service

This is the deployment the proxy is normally used in: one proxy beside each S3
client, reached in-cluster at `<fullname>.<namespace>.svc.<clusterDomain>` — for
a release `my-s3-proxy` on a default cluster,
`my-s3-proxy-s3-encryption-proxy.<namespace>.svc.cluster.local`.
That leg carries the client's Signature V4 credentials, every object key and the
plaintext of every object, so it is worth terminating TLS on
([ADR 0026](../../../docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md)).

With cert-manager:

```yaml
serviceTLS:
  enabled: true
  issuer:
    kind: ClusterIssuer
    name: my-internal-ca   # example
```

Or bring your own certificate — cert-manager is then not needed at all:

```yaml
serviceTLS:
  enabled: true
  existingSecret: my-proxy-tls   # holds tls.crt and tls.key
```

Either way the chart mounts the certificate, adds the `tls:` block to the
rendered configuration, and derives `scheme: HTTPS` for both probes. **Do not
write a `tls:` block into `config` as well**: the render fails rather than let two
sources for one setting drift apart.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceTLS.enabled` | Serve TLS on the proxy's own listener | `false` |
| `serviceTLS.existingSecret` | A Secret holding `tls.crt` and `tls.key`. Set it and no Certificate is issued | `""` |
| `serviceTLS.issuer.kind` | `ClusterIssuer` or `Issuer` | `ClusterIssuer` |
| `serviceTLS.issuer.name` | cert-manager issuer. Required unless `existingSecret` is set | `""` |
| `serviceTLS.extraDNSNames` | Added to the four computed Service names, never instead of them | `[]` |
| `serviceTLS.annotations` | Annotations on the Certificate | `{}` |
| `serviceTLS.mountPath` | Where the certificate is mounted, and what the injected `tls:` block points at | `/app/tls` |
| `clusterDomain` | The cluster's DNS domain, used for the fourth Service name | `cluster.local` |

The issued certificate covers the four names the Service answers to, computed
from the release rather than configured: `<name>`, `<name>.<ns>`,
`<name>.<ns>.svc` and `<name>.<ns>.svc.<clusterDomain>`. A name the Service has
and the certificate does not is a failure the operator only sees when a client
refuses the connection, which is why these are not a values list.

**`service.targetPort` and `bind_address` still have to agree.** The chart turns
the listener on; which port it listens on is `bind_address` inside `config`, and
the Service has to target it.

A worked example is the Velero e2e suite's values file,
[test/e2e/velero/values-proxy.yaml](../../../test/e2e/velero/values-proxy.yaml),
which uses the bring-your-own arm against the repository's test PKI.

**What is not covered by a test run:** the cert-manager arm. The e2e cluster has
no cert-manager, so that arm is exercised by rendering only.

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
renders all three override files plus the Velero e2e values on every run.

## Security Considerations

1. **The configuration is a ConfigMap.** `config` is rendered verbatim into a
   ConfigMap, which is not a secret store. A key written there is readable by
   anyone with `get configmaps` in the namespace. Keep the master key in a
   Secret and reference it as `${S3EP_AES_KEY}`: `secrets.encryption.existingSecret`
   for one you manage, `secrets.encryption.aesKey` for the chart's own Secret.
   The chart ships no key either way
   ([ADR 0021](../../../docs/adr/0021-key-material-is-generated-never-committed.md)).

2. **Secrets in values files are not secrets.** `secrets.s3.*`,
   `secrets.encryption.aesKey` and `license.jwt` are base64-encoded into a
   chart-managed Secret; base64 is encoding, not encryption, and the value ends
   up in Helm's release history. Prefer `--set` at install time,
   `secrets.encryption.existingSecret`, `license.existingSecret`, or an external
   secret manager.

3. **The default `config` reuses one key pair for two roles.** It hands the same
   `${S3_ACCESS_KEY_ID}` / `${S3_SECRET_KEY}` to the `s3_backends` entry (the
   proxy's credentials against the backend) and to `s3_clients` (what clients
   present to the proxy). Give them separate credentials: a client holding the
   backend key reaches the bucket directly, where it can write unencrypted
   objects and delete stored ones without the proxy ever seeing the request. A
   client secret must be at least 16 characters, an access key at least 8.

4. **Backend TLS follows the endpoint scheme.** There is no toggle. An
   `s3_backends[0].target_endpoint` beginning `http://` refuses the start under
   every provider, `exit` included: the backend credential would travel in a
   SigV4 header over plaintext, a listener on that leg would learn every bucket
   name, object key and object size, and under `exit` the object bytes would
   cross it in the clear as well. `s3_backends[0].insecure_skip_verify` disables
   certificate verification and belongs in test clusters only.

5. **Profiling has no chart surface, and should keep none.** A heap profile of
   this process contains data keys and plaintext. If you enable
   `monitoring.pprof_enabled` inside `config`, its listener must bind a loopback
   address — the proxy refuses to start otherwise — and it is reached with
   `kubectl port-forward`, never through a Service.

6. **Network Policies**: the chart renders none (ADR 0030). Write one for the
   proxy pod naming your ingress controller and Prometheus namespaces on the
   ingress side and the S3 backend and DNS on the egress side.

7. **Pod Security**: the chart runs non-root with a read-only root filesystem,
   all capabilities dropped, `RuntimeDefault` seccomp and no mounted service
   account token.

8. **Availability**: every shipped profile runs a single replica without a
   PodDisruptionBudget, and the chart refuses a second (ADR 0033): a
   client-driven multipart upload is held by the process that created it. A node
   drain and a rollout are each an outage for the length of a restart. What would
   answer that is a proxy able to hand an upload to another instance; no
   deployment layer can.

The threat model behind these points is in
[docs/security/threat-model.md](../../../docs/security/threat-model.md), and the
deployment side of it is
[docs/security/operational-security.md](../../../docs/security/operational-security.md).

## Known limitations

- **An externally managed ConfigMap or Secret does not restart pods.** The pod
  template hashes what the chart renders, so `helm upgrade` with a changed
  `config`, a rotated credential or a renewed license rolls the pods. With
  `configMap.useExistingConfigMap: true`, or with a Secret you manage yourself,
  the chart cannot see the content and nothing rolls; restart them yourself:
  `kubectl rollout restart deployment/<release>-s3-encryption-proxy` (the
  generated name is `<release>-<chart>`, or the release name alone when it
  already contains the chart name, and `fullnameOverride` when that is set).
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
3. **Pod not starting, `s3_backends[0].target_endpoint is required`** or
   **`s3_backends is required: name exactly one backend`**: the mounted config
   did not parse as expected, or the backend block is missing. A config still
   carrying the singular `s3_backend` is refused by a message of its own that
   says to move the block under a single `- ` entry; the legacy top-level
   backend keys are gone as well.
4. **Never becomes ready, probes fail**: the chart derives the probe scheme from
   `tls.enabled` in `config`. It cannot do that under
   `configMap.useExistingConfigMap: true` — set `probes.scheme: HTTPS` there.
5. **`helm template` fails with `values.config is not parseable YAML`**: `config`
   is one literal string (`config: |`), not a map, and it has to parse.
6. **`helm upgrade` fails with `replicaCount is 2 and this chart installs one
   instance`**, or with the same message for `autoscaling.enabled`: a values
   file from before this release. Set `replicaCount: 1` and
   `autoscaling.enabled: false` — see
   [One instance, and the chart refuses a second](#one-instance-and-the-chart-refuses-a-second).
7. **Certificate issues**: ensure cert-manager is installed and the issuer is
   configured correctly.

### Debugging Commands

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=s3-encryption-proxy

# View logs
kubectl logs -l app.kubernetes.io/name=s3-encryption-proxy

# Check the rendered configuration (names below assume release my-s3-proxy;
# the generated name is the one described under Known limitations)
kubectl get configmap my-s3-proxy-s3-encryption-proxy-config -o jsonpath='{.data.config\.yaml}'

# Render locally without installing. --kube-version is not decoration: a
# client-only render falls back to the version the Helm binary was built
# against, and on an older client that is below the chart's 1.34 floor -- the
# call is then refused by the version check rather than by anything in values.
helm template my-s3-proxy . --values values-production.yaml --kube-version 1.34.0

# Check certificate status (if enabled)
kubectl describe certificate my-s3-proxy-s3-encryption-proxy-tls
```

## Contributing

Please refer to the main project repository for contribution guidelines.
