# Ticket 016: Helm chart: config rollout, TLS probes and the stale values files

## Status (2026-09-06)

**Open.** Carries [P-10](README.md#parked-items-p-1-to-p-13) from the Velero
path findings, all six items, plus the CI wiring that would have caught two of
them, plus the four Velero e2e version pins
that turn out to sit outside Renovate's view (item 7b), plus the two gaps in
the e2e health check itself (items 8 and 9) — this is the only ticket that edits
`test/e2e/velero`, so they have nowhere better to live.
Everything here is chart, values, CI and e2e harness — no proxy code, no stored
object format, no config schema change. It therefore depends on nothing and
blocks nothing: it can land before or after storage format v2 (item 2 of the
order of work), and the configuration-hygiene ticket (D-6, D-7, N-5) will change
the *content* of the values files this ticket makes templatable, not their shape.
The one coupling to watch is item 1's e2e cleanup: the V9 rotation scenario
patches the ConfigMap out of band with `kubectl`, so a `checksum/config`
annotation alone does not retire its workaround — see the design note under
item 1 and the first open question.

---

## Context

The chart under [deploy/helm/s3-encryption-proxy/](../../deploy/helm/s3-encryption-proxy/)
is the supported way to run the proxy in Kubernetes. The Velero e2e suite was the
first consumer of it that was not a demo, and bringing it up surfaced six
defects. Five are traps every operator has to rediscover; one is worse than a
trap.

That one is item 1. Everything that decides how the proxy encrypts lives in the
`config` string: the active provider alias, the provider key material, the
integrity mode. `helm upgrade` with a changed `config` updates the ConfigMap,
reports success, and leaves the old pods running the old configuration. Under
the threat model this proxy exists for — the S3 endpoint is hostile, and the
proxy is the only thing standing between the backup data and it — an operator
who rotates a KEK and is told the rotation succeeded, while the old key is still
encrypting every new object, has been given a false statement about the security
of their data by the deployment tooling. Rule 2 of the threat model applies
directly: a control that exists only in configuration is worse than no control,
because it gets relied upon.

Item 3 has the same shape one step down. Turning on pod-level TLS
(`tls.enabled` in the proxy config, [config.go:29-34](../../internal/config/config.go#L29))
without also rewriting both probe blocks produces a pod that never becomes
Ready, with no hint as to why — a plaintext `httpGet` against a TLS listener
gets a 400 from Go's HTTP server. The failure mode pushes operators towards
running the proxy in plaintext, which is the wrong direction.

The remaining four are cost, not security: two values files that cannot be
rendered at all, a cert-manager `Certificate` with no stated consumer, a Service
that cannot pin a NodePort, and a helm-unittest suite that asserts things the
chart stopped rendering and that nothing runs.

**The CI gap is the reason items 2 and 6 survived.** `make helm-test`
([Makefile:236-239](../../Makefile#L236)) runs `helm lint` and exactly one
`helm template` with the default values, and — verified by grep over
`.github/workflows/` — **no workflow invokes it at all**. The only helm in CI is
the chart-packaging job `release-helm-gh`
([push.yml:121-206](../../.github/workflows/push.yml#L121)), which installs helm,
rewrites the versions and runs `helm package` and `helm repo index` without ever
rendering the chart, and the `azure/setup-helm` install inside the e2e job
([release.yml:494-497](../../.github/workflows/release.yml#L494)). So the chart is
released without ever being rendered against the values files that ship with it.

---

## Scope

**In**

- All six P-10 items, as detailed below.
- Two defects in the *default* values file found while verifying item 2 (a
  publicly known AES-256 KEK as the shipped default, and a `metadata_key_prefix`
  in a place the Go config ignores). They are in the same file family, they are
  one line each, and one of them is security-relevant.
- Wiring `helm lint` + `helm template` over **every** values file plus
  `helm unittest` into `make helm-test`, and running that from a new CI job that
  gates `semantic-release`.
- The Renovate custom managers for the pins this ticket touches: the
  helm-unittest plugin version the new job installs, and the four Velero e2e CSI
  sidecar pins that turn out to have no manager at all (item 7b).
- Two patterns the e2e health check was specified to catch and does not
  (item 8). Not chart work either, but the gate every success criterion below
  leans on, in a file this ticket already edits.
- The whole health check the same specification made mandatory and nobody built:
  scanning `velero backup logs` and `velero restore logs` for error-level lines
  (item 9). Same file, same gate, larger hole.
- The unbuilt half of the N-4 decision: the e2e runs kopia with the published
  default repository password, so the configuration the README tells operators
  to use is the one nothing exercises (item 10). Same script, same bring-up.
- The chart README parameter tables for the values this ticket adds or changes,
  and the e2e comments that describe the workarounds being removed.

**Out**

- Proxy code, the proxy config schema and its validation. `s3_security` knob
  deletion (N-5), `use_tls` startup refusal (D-6) and
  `max_presign_expiry_seconds` (D-7) belong to the configuration-hygiene ticket.
  This ticket does not edit config *semantics*, only files that carry config.
- Storage format v2 and anything downstream of it.
- Giving the chart a first-class pod-TLS story (mount a secret, inject
  `tls.cert_file`/`tls.key_file` into the rendered config). The e2e does this by
  hand with generic `volumes`/`volumeMounts`
  ([values-proxy.yaml:63-75](../../test/e2e/velero/values-proxy.yaml#L63)); making
  it a chart feature is a new feature, not a P-10 defect. Named as an open
  question.
- `templates/secret.yaml` not triggering a rollout either. Same defect family as
  item 1, not in P-10, and it needs a decision about the license secret — see
  the open questions.

**Closes:** P-10 (all six sub-items), the two unbuilt parts of the e2e health
check (items 8 and 9), and the e2e half of N-4 (item 10) — its operator half is
already closed in the README and in `SECURITY_ARCHITECTURE.md` H-4. No D-, N- or other P- item is closed here: D-12 covers the
same health check but was itself decided and closed on 2026-09-06, and appears
under item 9 as the rationale for the half that is deliberately not changing.
D-3 (gitignore the test keys) and D-18 (license reissue + CI expiry check) touch
neighbouring files but are separate work.

---

## Item 1 — no `checksum/config` annotation, so a config change does not roll the pods

**Verified.** [templates/configmap.yaml:9-13](../../deploy/helm/s3-encryption-proxy/templates/configmap.yaml#L9)
renders `config.yaml` from `.Values.config`. The Deployment's pod template
carries only `.Values.podAnnotations`
([deployment.yaml:16-19](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L16)),
so nothing in the pod spec changes when the ConfigMap content changes, and Helm
has no reason to create a new ReplicaSet. The config is mounted as a volume
([deployment.yaml:92-95](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L92),
[deployment.yaml:111-114](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L111)),
and the proxy reads it once at startup, so the kubelet's eventual ConfigMap
refresh does not help either.

**Fix.** Add to the pod template metadata, alongside `podAnnotations`:

```yaml
      annotations:
        {{- if not .Values.configMap.useExistingConfigMap }}
        checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
        {{- end }}
        {{- with .Values.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
```

Note the restructure: `annotations:` today is emitted only inside
`{{- with .Values.podAnnotations }}`, so the key has to move out of the `with`
block or the checksum disappears whenever `podAnnotations` is empty — which is
the default ([values.yaml:29](../../deploy/helm/s3-encryption-proxy/values.yaml#L29)).

Hashing the *rendered ConfigMap* rather than `.Values.config` is deliberate: the
template also injects `license_file` when a license is configured
([configmap.yaml:10-12](../../deploy/helm/s3-encryption-proxy/templates/configmap.yaml#L10)),
so hashing the raw value would miss a license being switched on or off. The
`useExistingConfigMap` guard is required because the template renders nothing in
that mode ([configmap.yaml:1](../../deploy/helm/s3-encryption-proxy/templates/configmap.yaml#L1)),
and hashing an empty render would produce a constant that silently never changes.

**Workarounds this retires.**

- [test/e2e/velero/e2e-up.sh:165-167](../../test/e2e/velero/e2e-up.sh#L165) — the
  two comment lines and the `k -n "$PROXY_NAMESPACE" rollout restart deploy/s3ep-proxy`
  call. Line 168 (`rollout status`) stays: `helm upgrade --wait` at line 164
  already waits, but the status call is the thing that fails loudly when a
  rejected config crashloops the pod, and it costs nothing.
- [scenarios_lifecycle_test.go:338-340](../../test/e2e/velero/scenarios_lifecycle_test.go#L338) —
  the comment and the `rollout restart` inside `patchProxyConfig`, **but only if
  the scenario stops patching the ConfigMap out of band.** As written,
  `patchProxyConfig` builds a ConfigMap with `kubectl create configmap
  --dry-run=client` and applies it
  ([scenarios_lifecycle_test.go:331-336](../../test/e2e/velero/scenarios_lifecycle_test.go#L331)).
  Helm is never involved, so the annotation — which is computed at render time —
  does not move, and the restart is still required. The honest fix is to make V9
  rotate the way an operator would: write the rotated config to a temp file and
  run `helm upgrade --reuse-values --set-file config=<file>` against the release,
  then `rollout status`. That turns the scenario into a live test of the
  annotation instead of a workaround for its absence. Cost: the Go suite gains a
  `helm` dependency (the harness has `kubectl` and `velero` helpers in
  [exec.go:89-90](../../test/e2e/velero/exec.go#L89); `helm` is already a hard
  requirement of `e2e-up.sh`, [e2e-up.sh:19](../../test/e2e/velero/e2e-up.sh#L19)).
  Also update the stale reasoning at
  [scenarios_lifecycle_test.go:183-186](../../test/e2e/velero/scenarios_lifecycle_test.go#L183).

Do not delete the restart at line 340 while leaving the `kubectl`-patch in place:
that would make V9 test a rollout that never happens.

---

## Item 2 — `values-development.yaml` and `values-monitoring.yaml` cannot be rendered

**Verified by running it** (helm v3.21.3, this tree):

```
$ helm template t deploy/helm/s3-encryption-proxy -f deploy/helm/s3-encryption-proxy/values-development.yaml
coalesce.go:237: warning: skipped value for s3-encryption-proxy.config: Not a table.
Error: template: s3-encryption-proxy/templates/configmap.yaml:13:33: executing
"s3-encryption-proxy/templates/configmap.yaml" at <4>: wrong type for value;
expected string; got map[string]interface {}
```

Identical failure for `values-monitoring.yaml`. `values.yaml` and
`values-production.yaml` render fine.

The template needs `config` to be a raw string that goes into the ConfigMap 1:1
([configmap.yaml:13](../../deploy/helm/s3-encryption-proxy/templates/configmap.yaml#L13),
`{{- .Values.config | nindent 4 }}`). Both files define it as a map:
[values-development.yaml:51-69](../../deploy/helm/s3-encryption-proxy/values-development.yaml#L51)
and [values-monitoring.yaml:81-106](../../deploy/helm/s3-encryption-proxy/values-monitoring.yaml#L81).

`values-development.yaml` is wrong independently of the type: it uses a schema
the Go config does not have — camelCase keys (`logLevel`,
`encryptionMethodAlias`, `aesKey`), a top-level `targetEndpoint` where the
struct wants `s3_backend.target_endpoint`
([config.go:38](../../internal/config/config.go#L38) on the `S3Backend` field,
[config.go:159](../../internal/config/config.go#L159)), and
`type: "aes-gcm"`, which
[`validateProvider`](../../internal/config/config.go#L606) rejects with
`unsupported encryption type: aes-gcm (supported: aes, rsa, none)`
([config.go:624](../../internal/config/config.go#L624)).

`values-monitoring.yaml` is wrong only in the type. Its `target_endpoint`,
`region`, `access_key_id` and `secret_key` sit at the top level, but that is the
*legacy* form the Go config still accepts: `Config` declares all four
([config.go:160-163](../../internal/config/config.go#L160)) and
`migrateLegacyConfig` copies them into `s3_backend`
([config.go:266-288](../../internal/config/config.go#L266)). So it needs the string
conversion; moving the keys under `s3_backend` is modernisation, not a fix.

**Fix.** Rewrite both `config:` blocks as literal strings (`config: |`) in the
real schema, modelled on
[values-production.yaml:137-179](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L137),
which is the one override file that is correct today. Keep each file's actual
purpose: development points at an in-cluster MinIO with `log_level: debug`,
monitoring enables the `monitoring` block. Then render both under CI (item 7).

One constraint borrowed from a decision this ticket does not implement: D-6
makes the proxy refuse to start on `s3_backend.use_tls: false` under an
encrypting provider, and `values-development.yaml` points at a plain-HTTP MinIO
today ([values-development.yaml:53](../../deploy/helm/s3-encryption-proxy/values-development.yaml#L53)).
Give the rewritten file an HTTPS backend, so it does not become unstartable the
day the configuration-hygiene ticket lands.

Also fix the chart README, which tells the reader to install with a file that
cannot render
([README.md:183](../../deploy/helm/s3-encryption-proxy/README.md#L183)).

### 2b — two defects in the default values, found while verifying this item

Not part of P-10. Both are one line, both are in the file CI does render, and
one is security-relevant, so they are fixed here rather than filed.

- **The chart ships a publicly known AES-256 KEK as its default.**
  [values.yaml:209](../../deploy/helm/s3-encryption-proxy/values.yaml#L209) sets
  `aes_key: "0123456789abcdef0123456789abcdef"`. That string is not valid
  base64 for 32 bytes, so the provider takes the raw-bytes fallback
  ([aes.go:61-70](../../pkg/encryption/keyencryption/aes.go#L61)) and it *is* a
  working 32-byte AES-256 key. Anyone who installs the chart without overriding
  `config` encrypts every object under a key printed in this repository, and the
  install succeeds, so nothing tells them. Fix: remove the literal and reference
  an environment variable the operator must supply, exactly as production does
  (`aes_key: "${S3EP_AES_KEY}"`,
  [values-production.yaml:179](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L179),
  fed from a secret at
  [values-production.yaml:129-134](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L129)).
  Unset, the proxy then refuses to start with a key error, which is the correct
  outcome for "you did not configure encryption".
- **`metadata_key_prefix` is in a place the config ignores.**
  [values.yaml:210](../../deploy/helm/s3-encryption-proxy/values.yaml#L210) puts it
  inside the provider's `config:` map. The field lives on `EncryptionConfig`
  ([config.go:63](../../internal/config/config.go#L63)), one level up; a provider's
  `config` is a free-form `map[string]interface{}`, so the misplaced key is
  accepted and dropped. The rendered deployment uses the default `s3ep-` prefix
  ([config.go:354](../../internal/config/config.go#L354)) while the values file
  claims `x-s3ep-`. Fix: move it under `encryption:` or drop it — dropping it is
  better, since the default is what CLAUDE.md documents.

---

## Item 3 — probes have no scheme, so pod TLS means the pod never goes Ready

**Verified.** [values.yaml:92-108](../../deploy/helm/s3-encryption-proxy/values.yaml#L92)
defines both probes as bare `httpGet` with `path` and `port` only, and
[deployment.yaml:54-57](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L54)
emits them with `toYaml` unchanged. Kubernetes defaults `scheme` to `HTTP`.
`/health` is served by the same listener as the S3 API, so it speaks TLS as soon
as the proxy config sets `tls.enabled: true`
([config.go:29-34](../../internal/config/config.go#L29),
[config.go:153](../../internal/config/config.go#L153)) — the e2e values file
carries the discovery as a comment
([values-proxy.yaml:4-6](../../test/e2e/velero/values-proxy.yaml#L4)) and works
around it by restating both probes with `scheme: HTTPS`
([values-proxy.yaml:41-59](../../test/e2e/velero/values-proxy.yaml#L41)).

There is **no chart-level `tls` value today** — verified by grep over the chart:
the only `tls` keys are `ingress.tls`, `certificate.*` and the proxy config's own
`tls:` block inside the `config` string. So "derive the scheme from the tls
value" means deriving it from the config the pod will actually receive, not from
a second knob that can drift out of sync with it (threat-model rule 2 again: two
sources of truth for "is this listener TLS" is how the trap gets rebuilt).

**Fix.** A helper that parses `.Values.config` and sets `httpGet.scheme` when the
probe does not already specify one:

```gotemplate
{{- define "s3-encryption-proxy.probeScheme" -}}
{{- if .Values.probes.scheme -}}
{{- .Values.probes.scheme -}}
{{- else -}}
{{- $cfg := .Values.config | fromYaml -}}
{{- if $cfg.Error -}}{{- fail (printf "values.config is not valid YAML: %s" $cfg.Error) -}}{{- end -}}
{{- if and $cfg.tls $cfg.tls.enabled -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}
{{- end }}
```

and, in the Deployment, `deepCopy` each probe, `set` the scheme under `httpGet`
when absent, then `toYaml`. Add one new value, `probes.scheme: ""` (empty =
derive), for the `configMap.useExistingConfigMap: true` case where the chart
cannot see the config at all — an explicit override, not a parallel truth.

`fail` on unparseable config is a bonus: today a malformed `config` string
renders happily and crashloops the pod at runtime.

**Workaround this retires.** The `scheme: HTTPS` lines and the first bullet of
the comment in [values-proxy.yaml:4-6 and 41-59](../../test/e2e/velero/values-proxy.yaml#L41).
Removing them is the verification: the e2e runs with `tls.enabled: true`
([values-proxy.yaml:105-108](../../test/e2e/velero/values-proxy.yaml#L105)), so if
the derivation is wrong the pod never goes Ready and `e2e-up.sh` fails at
[line 168](../../test/e2e/velero/e2e-up.sh#L168).

---

## Item 4 — the cert-manager `Certificate` has no consumer inside the chart

**Verified, with a correction to the finding.**
[templates/certificate.yaml](../../deploy/helm/s3-encryption-proxy/templates/certificate.yaml)
issues into `.Values.certificate.secretName`
([certificate.yaml:13](../../deploy/helm/s3-encryption-proxy/templates/certificate.yaml#L13),
default `s3-proxy-tls`,
[values.yaml:81](../../deploy/helm/s3-encryption-proxy/values.yaml#L81)). No pod
mounts it — the Deployment's volumes are `config`, `tmp`, optional
`gcp-credentials` and optional `license`
([deployment.yaml:111-139](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L111)).
But it is not unconditionally orphaned: in `values-production.yaml` the same
secret name is what `ingress.tls` references
([values-production.yaml:110-111](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L110)
vs [values-production.yaml:125](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L125)),
and the comment above it says so
([values-production.yaml:115-117](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L115)).
So the resource has a real purpose — TLS terminated at the ingress — that
nothing in the chart enforces or documents outside one values file.

**Fix.** Keep the template, make the relation explicit and unfakeable:

- Fail the render when `certificate.enabled: true` and no `ingress.tls` entry
  names `certificate.secretName` — the only configuration in which the chart
  creates a Certificate nothing consumes. Message names both values.
- State in the chart README (`certificate.*` table,
  [README.md:117-121](../../deploy/helm/s3-encryption-proxy/README.md#L117)) that
  this certificate terminates TLS **at the ingress**, that the pod does not
  mount it, and that pod-level TLS is configured through the proxy's own `tls:`
  config block plus a mounted secret.

Deleting the template instead is the wrong call: `values-production.yaml`
depends on it and cert-manager ingress-shim (the alternative) is explicitly
warned against in the same comment.

---

## Item 5 — the Service cannot pin a NodePort

**Verified.** [templates/service.yaml:11-17](../../deploy/helm/s3-encryption-proxy/templates/service.yaml#L11)
emits `type`, one port, `targetPort: http`, `protocol` and `name`, with no
`nodePort` field. With `service.type: NodePort` Kubernetes allocates a random
port from the node range. The e2e needs a fixed one, because Velero's
`BackupStorageLocation.publicUrl` is `https://127.0.0.1:30443`
([values-velero.yaml:49](../../test/e2e/velero/values-velero.yaml#L49)) and
`kind-config.yaml` maps exactly that port
([kind-config.yaml:12-13](../../test/e2e/velero/kind-config.yaml#L12)), so it ships
its own Service:
[test/e2e/velero/manifests/proxy-nodeport.yaml](../../test/e2e/velero/manifests/proxy-nodeport.yaml),
applied at [e2e-up.sh:169](../../test/e2e/velero/e2e-up.sh#L169), with the reason
written at the top of the manifest.

**Fix.** In the Service template:

```yaml
    - port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
      name: http
      {{- if and .Values.service.nodePort (eq .Values.service.type "NodePort") }}
      nodePort: {{ .Values.service.nodePort }}
      {{- end }}
```

with `service.nodePort: ""` added to `values.yaml` next to
[service.type](../../deploy/helm/s3-encryption-proxy/values.yaml#L51) and to the
README service table.

**Can the e2e manifest then be deleted? Yes.** A `NodePort` Service also gets a
ClusterIP, so the in-cluster URL Velero uses for the S3 API
(`https://s3ep-proxy.s3ep.svc.cluster.local:8443`,
[values-velero.yaml:46](../../test/e2e/velero/values-velero.yaml#L46)) keeps
working through the same Service, and the host-side pre-signed-URL path keeps
its fixed 30443. The e2e manifest's selector
([proxy-nodeport.yaml:12-14](../../test/e2e/velero/manifests/proxy-nodeport.yaml#L12))
is byte-identical to what `s3-encryption-proxy.selectorLabels` renders
([_helpers.tpl:48-51](../../deploy/helm/s3-encryption-proxy/templates/_helpers.tpl#L48)),
and `port: 8443` / `targetPort: http` match
[values-proxy.yaml:20-23](../../test/e2e/velero/values-proxy.yaml#L20). The only
difference is the port *name* (`https` vs `http`); nothing reads it — the Go
suite reaches the proxy by `PROXY_NODEPORT` alone
([backend.go:52](../../test/e2e/velero/backend.go#L52)). So: set
`service.type: NodePort` and `service.nodePort: 30443` in
`values-proxy.yaml`, delete the manifest and delete
[e2e-up.sh:169](../../test/e2e/velero/e2e-up.sh#L169).

---

## Item 6 — the helm-unittest suite is stale and nothing runs it

**Verified.** [tests/deployment_test.yaml](../../deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml)
is helm-unittest format. `helm plugin list` on this machine shows only `diff`, so
the plugin is not even installed, and no Makefile target or workflow invokes
`helm unittest` (grep over `Makefile` and `.github/`). Three concrete rots:

- [tests/deployment_test.yaml:15-17](../../deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml#L15)
  asserts `spec.replicas: 2`; the chart default is
  `replicaCount: 1` ([values.yaml:7](../../deploy/helm/s3-encryption-proxy/values.yaml#L7)),
  changed when the defaults were retuned for evaluation
  ([values.yaml:5-6](../../deploy/helm/s3-encryption-proxy/values.yaml#L5)).
- [tests/deployment_test.yaml:49-56](../../deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml#L49)
  asserts the pod label `app.kubernetes.io/component: proxy`. Rendering the
  chart with defaults produces exactly two pod labels,
  `app.kubernetes.io/name` and `app.kubernetes.io/instance`
  ([deployment.yaml:20-22](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L20),
  [_helpers.tpl:48-51](../../deploy/helm/s3-encryption-proxy/templates/_helpers.tpl#L48)) —
  `component` is rendered nowhere in the chart.
- The suite declares four templates
  ([tests/deployment_test.yaml:2-6](../../deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml#L2))
  and the first test omits `template:`
  ([tests/deployment_test.yaml:8-17](../../deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml#L8)),
  so `isKind: Deployment` is asserted against the Service, ConfigMap and
  ServiceAccount as well.

**Fix.** Rewrite the suite against the chart as it stands and extend it to cover
the five fixes above, so a regression fails in seconds instead of in the 45-minute
e2e job:

| Test | Asserts |
|---|---|
| deployment renders | `spec.replicas` equals the default `replicaCount`, per-template scoping restored |
| pod labels | the labels the chart actually renders, nothing else |
| config checksum | `checksum/config` annotation exists; a different `config` value produces a different value; absent with `configMap.useExistingConfigMap: true` |
| probe scheme | `HTTP` with a plaintext config; `HTTPS` with `tls: {enabled: true}` in `config`; `probes.scheme` override wins |
| service nodePort | rendered with `type: NodePort` + `nodePort`, absent with `ClusterIP` |
| certificate guard | render fails with `certificate.enabled: true` and no matching `ingress.tls` entry; succeeds with one |

While in the file: `podLabels` renders an empty line into the pod template when
unset ([deployment.yaml:22](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L22)
with the empty helper at
[_helpers.tpl:92-96](../../deploy/helm/s3-encryption-proxy/templates/_helpers.tpl#L92)).
Cosmetic, one `with` guard, fix it while the tests are being written.

---

## Item 7 — wire the chart into CI (this is what would have caught items 2 and 6)

**`make helm-test` today** ([Makefile:236-239](../../Makefile#L236)) is
`helm lint` on the chart plus one `helm template` with default values, and it is
called by `helm-install`, `helm-dev`, `helm-prod` and `helm-monitoring`
([Makefile:241-251](../../Makefile#L241),
[Makefile:278](../../Makefile#L278)) — all of which are developer convenience
targets, none of which run in CI.

**Fix, two parts.**

1. `helm-test` renders **every** values file, not just the default:
   `deploy/helm/s3-encryption-proxy/values.yaml` (implicit),
   `values-development.yaml`, `values-monitoring.yaml`, `values-production.yaml`,
   and `test/e2e/velero/values-proxy.yaml` — the last one because it is a real
   consumer of the chart and a chart/values drift there costs a 45-minute e2e
   run to discover. Then `helm unittest $(HELM_CHART_DIR)`. Glob the
   `values-*.yaml` files rather than listing them, so a new one is covered on
   the day it is added.
2. A new job in [.github/workflows/release.yml](../../.github/workflows/release.yml),
   named `helm-chart` ("Helm Chart"), `runs-on: self-hosted` like every other
   job, with four steps: `actions/checkout@v7`, `azure/setup-helm@v5` with
   `version: v4.2.4` (the version the e2e job already pins,
   [release.yml:494-497](../../.github/workflows/release.yml#L494)), a
   `helm plugin install https://github.com/helm-unittest/helm-unittest --version <pinned>`
   step, and `run: make helm-test`. Add `helm-chart` to the `needs:` list of
   `semantic-release`
   ([release.yml:549](../../.github/workflows/release.yml#L549)), which currently
   reads `[malware-scan, gosec, govulncheck, linter, unit-tests, integration-tests, e2e-velero]`.
   The job needs no Go, no Docker and no license, so it is seconds, not minutes.
   That matters because the integration job in the same workflow already pays
   for two transports — `make test-integration` and then `make test-integration-tls`
   over the same package list
   ([release.yml:269-283](../../.github/workflows/release.yml#L269)) — which
   runs the suite twice and, by the estimate recorded when the second endpoint
   landed and not re-measured since, roughly doubles that job's wall-clock.
   D-15 kept it that way on purpose
   ([label index](README.md#label-index)): aws-sdk-go-v2 emits
   `STREAMING-UNSIGNED-PAYLOAD-TRAILER` framing only over TLS
   ([Makefile:94-97](../../Makefile#L94)), so the HTTP run and the HTTPS run
   cover different upload framing. The standing instruction for anyone who later
   finds this pipeline too slow: split the two transports into parallel jobs.
   Dropping one drops a framing path, and a chart job measured in seconds is not
   a reason to reopen that trade.

Pin the plugin version and add it to the Renovate config next to the other pins
if Renovate can manage it; an unpinned `plugin install` puts an unversioned
network dependency in front of every release (D-2 keeps the release gated on
these jobs). Concretely, a tenth custom manager over
[.github/workflows/release.yml](../../.github/workflows/release.yml) matching the
`--version` on the plugin-install line, `depNameTemplate:
helm-unittest/helm-unittest`, `datasourceTemplate: github-releases`.

### 7b — four Velero e2e version pins are outside Renovate's view

Not part of P-10, and not chart work at all — but it is the same defect as the
unpinned plugin one paragraph up, it lives in the two file families this ticket
already edits (`renovate.json` and `test/e2e/velero/`), and it is cheap enough
that splitting it into its own ticket costs more than doing it.

**Verified.** [versions.env](../../test/e2e/velero/versions.env) exists so that
"Renovate has one place to update" — its own header says so
([versions.env:1-2](../../test/e2e/velero/versions.env#L1)) — and it carries
eleven upstream pins. `renovate.json` ships **nine** Velero e2e custom managers
([renovate.json:38-145](../../renovate.json#L38)): velero,
velero-plugin-for-aws, the Velero chart, kind, kubectl, csi-driver-host-path,
external-snapshotter, the MinIO image and the kind node image. Four pins have no
manager and no `matchStrings` anywhere in the file mentions them:

| Pin | Declared | Consumed |
|---|---|---|
| `CSI_ATTACHER_VERSION` | [versions.env:20](../../test/e2e/velero/versions.env#L20) | [e2e-up.sh:133](../../test/e2e/velero/e2e-up.sh#L133) |
| `CSI_PROVISIONER_VERSION` | [versions.env:21](../../test/e2e/velero/versions.env#L21) | [e2e-up.sh:134](../../test/e2e/velero/e2e-up.sh#L134) |
| `CSI_RESIZER_VERSION` | [versions.env:22](../../test/e2e/velero/versions.env#L22) | [e2e-up.sh:135](../../test/e2e/velero/e2e-up.sh#L135) |
| `CSI_HEALTH_MONITOR_VERSION` | [versions.env:23](../../test/e2e/velero/versions.env#L23) | [e2e-up.sh:136](../../test/e2e/velero/e2e-up.sh#L136) |

All four interpolate into a `raw.githubusercontent.com` URL that `kubectl apply`
fetches at bring-up time, so each one is an unmanaged network dependency of
every e2e run, and of the `e2e-velero` job that gates `semantic-release`. They
rot silently: nothing fails until an upstream tag is deleted or the sidecar RBAC
drifts away from the Kubernetes version `KIND_NODE_IMAGE` pins.

**Fix.** Four more custom managers of the same shape as the existing ones, e.g.

```json
{
  "description": "Velero e2e: external-attacher",
  "customType": "regex",
  "managerFilePatterns": ["/^test/e2e/velero/versions\\.env$/"],
  "matchStrings": ["CSI_ATTACHER_VERSION=(?<currentValue>v\\d+\\.\\d+\\.\\d+)\\s"],
  "depNameTemplate": "kubernetes-csi/external-attacher",
  "datasourceTemplate": "github-releases"
}
```

and the same against `kubernetes-csi/external-provisioner`,
`kubernetes-csi/external-resizer` and `kubernetes-csi/external-health-monitor`.
No `packageRules` change is needed: the "Velero e2e" rule matches by file name
([renovate.json:147-159](../../renovate.json#L147)), so the new pins join the
existing group, inherit `automerge: false` and land as one PR that the e2e job
has to pass — which is the whole point of grouping them.

**D-4 belongs beside that inheritance: the group stays manual on purpose.**
`automerge: false` on this rule ([renovate.json:155](../../renovate.json#L155))
is the one exception to the repository default `automerge: true`
([renovate.json:17](../../renovate.json#L17)); the reason — the Velero chart lags
the Velero release, so a chart bump and an image bump must never land separately
— is in the [label index](README.md#label-index). What the register does not
carry is the condition for reversing it: turn automerge on only after the
`e2e-velero` job has been green across several Renovate cycles. D-2 settled the
other half by keeping that job blocking `semantic-release`, so an automerged pin
bump would clear the gate and reach a release with nobody having read it — that
is what a track record has to buy first. Adding the four managers above is not
the moment to flip it: their first PR is exactly the one a human should read.

---

## Item 8 — the e2e health check misses two patterns its own specification names

Third one of the same kind as 2b and 7b: not P-10, two lines of Go, and in a
file this ticket already opens.

**Verified.** Every scenario ends in `guard.assertHealthy` — twelve call sites
across `scenarios_atrest_test.go`, `scenarios_metadata_test.go`,
`scenarios_lifecycle_test.go` and `scenarios_volumes_test.go` — which reads the
logs of `deploy/velero`, `daemonset/node-agent` and `deploy/s3ep-proxy` since
the scenario started and fails on any string in `forbiddenLogPatterns`
([healthcheck.go:65-84](../../test/e2e/velero/healthcheck.go#L65)). That slice
holds seven entries
([healthcheck.go:37-45](../../test/e2e/velero/healthcheck.go#L37)):
`"level":"error"`, `"level":"fatal"`, `level=error`, `level=fatal`, `panic:`,
`runtime error` and `HMAC verification failed`. The health-check specification
the suite was built from also requires `goroutine ` and `stack trace` to fail a
scenario, and neither made it into the code. So a panic that is recovered and
logged as a goroutine dump, without the literal `panic:` prefix inside the
scanned window, passes every scenario today.

**Fix.** Two entries in the slice:

```go
	"goroutine ",
	"stack trace",
```

The trailing space in `"goroutine "` is load-bearing: it matches the dump header
`goroutine 1 [running]:` and leaves the plural in ordinary prose
("waiting for goroutines to finish") alone.

**Not verified:** whether a clean 13/13 run is free of both strings. Velero and
kopia are chatty, and a debug line carrying a goroutine id would turn this into
a flaky gate that someone later deletes rather than debugs. Decide it from the
logs of a green run, not by reasoning — and if either string does appear in a
healthy run, narrow the pattern (`goroutine 1 [running]:`) instead of dropping
it.

---

## Item 9 — the mandatory Velero-side log scan was specified but never built

Same specification as item 8, same file, much larger hole: two of the five
mandatory post-scenario checks read Velero's own backup and restore logs, and
neither exists.

**Verified absent.** The specification made five things fail a scenario: a phase
other than `Completed` or a non-zero error count; `level=error` in
`velero backup logs <name>` or `velero restore logs <name>`; error, panic or
stack-trace output in the **pod** logs of Velero, node-agent and the proxy; a
changed container restart count; an HMAC failure in the proxy log. The pod-log
scan, the restart counts and the HMAC pattern are in
[`assertHealthy`](../../test/e2e/velero/healthcheck.go#L67); the phase and error
count are in [`waitBackupCompleted`](../../test/e2e/velero/healthcheck.go#L179)
and [`waitRestoreCompleted`](../../test/e2e/velero/healthcheck.go#L210). Nothing
anywhere fetches the log object Velero writes for a backup or a restore.
`healthTargets` is three pod selectors and nothing else
([healthcheck.go:22-29](../../test/e2e/velero/healthcheck.go#L22)).

Those artefacts are read in exactly one place, scenario V10
([backup_logs, scenarios_lifecycle_test.go:74-78](../../test/e2e/velero/scenarios_lifecycle_test.go#L74),
[restore_logs, :97-101](../../test/e2e/velero/scenarios_lifecycle_test.go#L97)),
which asserts they come back non-empty and look like Velero output — that they
were fetchable through a pre-signed URL, which is what V10 exists for. Their
content is never inspected.

**What that costs today.** A backup that reaches `Completed` with
`status.errors == 0` while its own log records error-level lines passes the whole
suite. Velero writes things there that never reach the server pod log — per-item
plugin failures, uploader errors on individual files — and the proxy is on the
path of every one of those items. This is the check that catches a partial
data-path failure Velero itself tolerated.

**The closed decision that belongs beside it.** D-12 asked whether the phase
assertion should read the Backup CR or run `velero backup describe --details` as
the specification said. Decided and **closed** 2026-09-06: keep the CR read,
because `describe` fetches results through a pre-signed URL and would drag the
download path into every assertion, and keep V10 as the explicit coverage of that
path. The reasoning already sits where it applies
([healthcheck.go:151-155](../../test/e2e/velero/healthcheck.go#L151)), so the
phase assertions are not open work — but item 9 partly re-opens the tradeoff D-12
settled, which is why the two are written down together. See the cost note below.

**Fix.** Scan inside the two waiters, not in `assertHealthy`. They already know
the object name, have just established a terminal `Completed` phase, and sit on
the path of every scenario, so nothing has to opt in. After the existing phase
assertions, fetch the log and run the same `forbiddenLogPatterns` scan with the
same [`excerpt`](../../test/e2e/velero/healthcheck.go#L102) reporting
`assertHealthy` uses — including whatever item 8 adds to that slice.

Three constraints, all verified in the harness:

- Fetch with [`tryVelero`](../../test/e2e/velero/exec.go#L129), not `velero`, and
  give a fetch failure its own message. An unfetchable pre-signed URL is a defect
  too, but it is not "the backup logged an error", and the failure output must
  not conflate them.
- `run` returns `CombinedOutput`
  ([exec.go:95-108](../../test/e2e/velero/exec.go#L95)), so the CLI's own stderr
  lands in the very string a naive scan would search. Keep the fetch and the scan
  separate so nothing the CLI prints can trip the pattern list.
- `forbiddenLogPatterns` carries both `"level":"error"` and `level=error`
  ([healthcheck.go:37-45](../../test/e2e/velero/healthcheck.go#L37)). The Velero
  server runs with `logFormat: json`
  ([values-velero.yaml:27](../../test/e2e/velero/values-velero.yaml#L27)); whether
  the per-backup log object uses that formatter or logrus text is **not
  verified**. Covering both is exactly why the slice has both entries, so reuse
  the slice rather than picking a format.

**Cost, stated plainly.** This puts a pre-signed-URL fetch on the mandatory path
of every scenario — the coupling D-12 kept out. Accepted here for log *content*,
because an unscanned log is the gap, but it means a regression in the pre-signed
path fails all 13 scenarios instead of only V10. Keep the phase assertions
reading the CR, so they can still fail on their own and point at Velero rather
than at the download path.

**Unknown until it runs.** Whether the 13 currently green scenarios stay green
under this check has never been measured — Velero logs errors for conditions it
recovers from, and nothing has ever looked. Same discipline as item 8: implement
the scan, run the full suite, take the result as the result. Either it is clean,
or every hit is triaged and each one is fixed or allowlisted with a comment
naming why it is benign. Do not weaken the pattern list to make the first run
pass.

---

## Item 10 — the e2e suite runs kopia with the published default repository password

The N-4 decision of 2026-09-06 had two halves. The operator half landed: the
README carries the warning and the command
([README.md:718-745](../../README.md#L718)), and
[SECURITY_ARCHITECTURE.md H-4](../../SECURITY_ARCHITECTURE.md#h-4-velero-kopia-repositories-default-to-a-published-password)
states why a strong repository password is what makes kopia a second layer
rather than a decoration. The suite half — *set one in the e2e, so the suite
runs the configuration the README tells operators to run* — was never built.
`grep -rn 'velero-repo-credentials\|repository-password' test/e2e/` matches
nothing, and `README.md:744` says so out loud: "The e2e suite in this repository
does not set it and runs with the upstream default."

**What it costs, stated narrowly.** Not exposure: the e2e bucket is a throwaway
MinIO inside a kind cluster that is deleted with `make e2e-down`. It is
fidelity. The documented path is the one nothing exercises, so a change that
broke it — Velero renaming the secret or the key, or the proxy interfering with
a repository created under a non-default password — would pass all 13 scenarios
untouched.

**Where it goes.** `e2e-up.sh` already creates the Velero namespace
([:181](../../test/e2e/velero/e2e-up.sh#L181)) and a secret next to it
([:189](../../test/e2e/velero/e2e-up.sh#L189)), before the Velero install at
[:212](../../test/e2e/velero/e2e-up.sh#L212), and `openssl` is already a
required tool ([:19](../../test/e2e/velero/e2e-up.sh#L19)). Then one subtest in
`TestPreflight` ([e2e_test.go:88](../../test/e2e/velero/e2e_test.go#L88)),
shaped like `proxy_is_serving_https`: assert the secret exists and its
`repository-password` is not `static-passw0rd`. Fail, never skip — the package
doc forbids skipping.

**One trap in the obvious implementation.** The neighbouring secret uses
`kubectl create ... --dry-run=client -o yaml | kubectl apply -f -`, which
rewrites the value on every run. A kopia repository keeps the password it was
created with, so copying that idiom would break every repository the previous
run created against a warm cluster. Create the secret only when it is absent,
and let `e2e-down.sh` remove it with the cluster.

**Acceptance.** `TestV2_CSISnapshotDataMover` and `TestV3_FileSystemBackup`
([scenarios_volumes_test.go](../../test/e2e/velero/scenarios_volumes_test.go))
are the scenarios that actually build a kopia repository; both must stay green
against a cluster brought up from scratch, and `README.md:744` loses its last
sentence in the same change.

---

## Work breakdown

- [ ] 1. Add `checksum/config` to the Deployment pod template, guarded on
      `configMap.useExistingConfigMap`, with `podAnnotations` merged alongside it
      rather than owning the `annotations:` key.
- [ ] 2. Remove the rollout workaround from
      [e2e-up.sh:165-167](../../test/e2e/velero/e2e-up.sh#L165), keep the
      `rollout status` at line 168.
- [ ] 3. Move V9's `patchProxyConfig` from a `kubectl`-applied ConfigMap to
      `helm upgrade --reuse-values --set-file config=...`, drop the
      `rollout restart` at
      [scenarios_lifecycle_test.go:338-340](../../test/e2e/velero/scenarios_lifecycle_test.go#L338)
      and correct the comment at
      [lines 183-186](../../test/e2e/velero/scenarios_lifecycle_test.go#L183).
- [ ] 4. Rewrite `values-development.yaml`'s `config:` as a literal string in the
      real schema; verify with `helm template` and by starting the proxy against
      the rendered ConfigMap.
- [ ] 5. Same for `values-monitoring.yaml`.
- [ ] 6. Default values hygiene: remove the hardcoded `aes_key` from
      [values.yaml:209](../../deploy/helm/s3-encryption-proxy/values.yaml#L209) in
      favour of `${S3EP_AES_KEY}`, and drop the misplaced
      `metadata_key_prefix` at
      [values.yaml:210](../../deploy/helm/s3-encryption-proxy/values.yaml#L210).
- [ ] 7. Add the `probeScheme` helper + `probes.scheme` value, apply it to both
      probes in the Deployment, `fail` on unparseable `config`.
- [ ] 8. Delete the `scheme: HTTPS` overrides and the stale comment bullet from
      [values-proxy.yaml](../../test/e2e/velero/values-proxy.yaml#L4).
- [ ] 9. Add the `certificate.enabled` / `ingress.tls` consistency guard and the
      README statement that the certificate serves the ingress, not the pod.
- [ ] 10. Add `service.nodePort` to the Service template and to `values.yaml`.
- [ ] 11. Switch the e2e to the chart Service (`service.type: NodePort`,
      `service.nodePort: 30443` in `values-proxy.yaml`), delete
      `manifests/proxy-nodeport.yaml` and
      [e2e-up.sh:169](../../test/e2e/velero/e2e-up.sh#L169).
- [ ] 12. Rewrite `tests/deployment_test.yaml` against the current chart and add
      the six test groups from the item 6 table; fix the empty-`podLabels` blank
      line.
- [ ] 13. Extend `make helm-test` to lint and template every values file
      (including `test/e2e/velero/values-proxy.yaml`) and to run
      `helm unittest`.
- [ ] 14. Add the `helm-chart` job to `release.yml` and to `semantic-release`'s
      `needs:`.
- [ ] 15. Update the chart README: the new `service.nodePort` and
      `probes.scheme` parameters, the certificate note, the corrected
      `values-development.yaml` install example
      ([README.md:183](../../deploy/helm/s3-encryption-proxy/README.md#L183)), and
      a line saying a config change now rolls the pods.
- [ ] 16. Add five Renovate custom managers to
      [renovate.json](../../renovate.json): the helm-unittest plugin version
      pinned by the new job, and `CSI_ATTACHER_VERSION`,
      `CSI_PROVISIONER_VERSION`, `CSI_RESIZER_VERSION`,
      `CSI_HEALTH_MONITOR_VERSION` from
      [versions.env:20-23](../../test/e2e/velero/versions.env#L20). No
      `packageRules` change.
- [ ] 17. Add `"goroutine "` and `"stack trace"` to `forbiddenLogPatterns`
      ([healthcheck.go:37-45](../../test/e2e/velero/healthcheck.go#L37)), then
      read the logs of the green run below to confirm neither fires on healthy
      output.
- [ ] 18. Scan the Velero-side logs in
      [waitBackupCompleted](../../test/e2e/velero/healthcheck.go#L179) and
      [waitRestoreCompleted](../../test/e2e/velero/healthcheck.go#L210): fetch
      with `tryVelero`, report a fetch failure separately from a pattern hit,
      reuse `forbiddenLogPatterns` and `excerpt`.
- [ ] 19. Run all 13 scenarios with items 17 and 18 in place, triage every hit,
      and either fix it or allowlist it with a comment naming the condition it
      excuses.
- [ ] 20. Create `velero-repo-credentials` with
      `--from-literal=repository-password="$(openssl rand -base64 32)"` in
      [e2e-up.sh](../../test/e2e/velero/e2e-up.sh#L189), **only when the secret
      is absent**, before the Velero install at
      [:212](../../test/e2e/velero/e2e-up.sh#L212).
- [ ] 21. Add a `kopia_repository_password_is_not_the_default` subtest to
      [TestPreflight](../../test/e2e/velero/e2e_test.go#L88), and delete the
      last sentence of the README warning box
      ([README.md:744](../../README.md#L744)) in the same change.

---

## Success criteria

Chart-only work, so the gate is "every values file renders, every fix has a test
that fails without it, and the e2e still passes with the workarounds gone".

- [ ] `make helm-test` is green and covers five values files plus
      `helm unittest`. Confirm the coverage rather than assuming it:
      ```bash
      make helm-test 2>&1 | tee /tmp/helm-test.log
      grep -c 'values-' /tmp/helm-test.log   # every override file was rendered
      ```
- [ ] Each of the five chart fixes fails `make helm-test` when reverted in
      isolation. Do this per fix, not once at the end — an assertion that passes
      against both the fixed and the broken chart is not a test.
- [ ] Item 1 verified live against a real `helm upgrade`, not only by unit test:
      ```bash
      ./test/e2e/velero/e2e-up.sh
      kubectl -n s3ep get deploy s3ep-proxy \
        -o jsonpath='{.spec.template.metadata.annotations.checksum/config}'
      # change log_level in test/e2e/velero/values-proxy.yaml, then
      helm -n s3ep upgrade s3ep deploy/helm/s3-encryption-proxy \
        -f test/e2e/velero/values-proxy.yaml --wait
      kubectl -n s3ep get deploy s3ep-proxy \
        -o jsonpath='{.spec.template.metadata.annotations.checksum/config}'   # differs
      kubectl -n s3ep logs deploy/s3ep-proxy --tail=5   # shows the new level
      ```
- [ ] Item 3 verified by the e2e coming up with **no** `scheme:` anywhere in
      `values-proxy.yaml`: `./test/e2e/velero/e2e-up.sh` reaches
      `environment ready`, which requires the readiness probe to pass against a
      TLS listener.
- [ ] Item 5 verified with the e2e manifest deleted:
      `kubectl -n s3ep get svc s3ep-proxy -o jsonpath='{.spec.ports[0].nodePort}'`
      returns `30443`, and `curl -k https://127.0.0.1:30443/health` answers from
      the host.
- [ ] Full Velero e2e green, all 13 scenarios, including V9 rotating through
      `helm upgrade`: `make e2e-up && make test-e2e-velero`.
- [ ] The Velero-side log scan (item 9) is proven to read something. An empty or
      never-fetched log passes a pattern scan in silence, so assert the opposite
      once: temporarily add `level=info` (and `"level":"info"`) to the pattern
      list, run one scenario, confirm it fails on a line that came from the
      *backup log* rather than from a pod log, then remove it.
- [ ] The two new health-check patterns are proven harmless on that green run,
      not assumed: after it, grep the same window the check reads.
      ```bash
      for t in "velero deploy/velero" "velero daemonset/node-agent" "s3ep deploy/s3ep-proxy"; do
        set -- $t; kubectl -n "$1" logs "$2" --all-containers --tail=-1 \
          | grep -nE 'goroutine |stack trace' && echo "FIRES in $2"
      done
      ```
      Any hit on a healthy run means the pattern needs narrowing, not removing.
- [ ] Unchanged suites still green — no Go outside `test/e2e/velero` is touched,
      so this is a regression check, not a coverage claim:
      `make test-unit`, `./start-demo.sh && make test-integration`,
      `make test-integration-tls`.
- [ ] `make test-integration-performance` is **not** required as a gate: no
      request path, no crypto path and no proxy binary changes here. Run it only
      if the default `resources` block in the chart is touched, which this ticket
      does not do.
- [ ] The `helm-chart` job appears in the workflow and in `semantic-release`'s
      `needs:`, and a deliberately broken values file fails the job on a branch
      before this is merged.
- [ ] Every pin in `test/e2e/velero/versions.env` that names an upstream release
      is matched by a custom manager, and the config still parses:
      ```bash
      npx --yes --package renovate renovate-config-validator renovate.json
      ```
      Renovate runs on a schedule and after pushes to `main`
      ([renovate.yml:2-11](../../.github/workflows/renovate.yml#L2)), so that the
      managers actually produce PRs is **not** verifiable on the branch — check
      the dependency dashboard after the merge and record it as an open loop
      rather than claiming it green.

---

## Risks and open questions

1. **V9 through Helm is the load-bearing change, and it is the one with the most
   ways to go wrong.** `helm upgrade --reuse-values` interacts badly with values
   supplied by `-f` at install time; the e2e installs with
   `-f values-proxy.yaml --set-string image.tag=...`
   ([e2e-up.sh:161-164](../../test/e2e/velero/e2e-up.sh#L161)), so a `--reuse-values`
   upgrade must not drop the image tag override. Verify by asserting the pod
   image after the rotation, not only that the pod restarted. If this proves
   fragile, the acceptable fallback is to keep the `rollout restart` in
   `patchProxyConfig` with a comment saying it exists because the *test* patches
   out of band — not because the chart is missing an annotation. Do not leave the
   old comment in place either way.
2. **`fromYaml` cannot see an existing ConfigMap.** With
   `configMap.useExistingConfigMap: true` the probe scheme falls back to
   `probes.scheme`, and if the operator forgets it, they are back in the
   original trap. Unverified whether anyone uses that mode; the guard is one
   value and a README line, not a solution.
3. **Secret changes still do not roll the pods.** The license is mounted from a
   Secret ([deployment.yaml:128-139](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L128))
   and the S3 credentials are read from one
   ([deployment.yaml:77-88](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L77)),
   so the D-18 license reissue will update the Secret and change nothing running.
   Same defect family as item 1, not in P-10. Open question: add
   `checksum/secret` in this ticket, or leave it to the D-18 work? Adding it
   means every credential rotation restarts the pods, which is correct but is a
   behaviour change worth stating in the README.
4. **helm-unittest is a plugin, installed over the network on a self-hosted
   runner, in front of a job that gates releases.** A GitHub outage or an
   upstream tag move then blocks `semantic-release` (D-2 keeps that coupling
   deliberate). Pin the version; consider a pre-installed plugin directory on the
   runner if it flakes. Not yet measured.
5. **Rewriting the two values files may surface further failures once they render
   at all.** `helm lint` and `helm template` prove the chart produces manifests;
   they prove nothing about the proxy accepting the config. The only real check
   is starting the proxy against the rendered ConfigMap — item 4 and 5 of the
   work breakdown say to do that, and it is the step most likely to be skipped.
6. **The default `aes_key` removal is a breaking change for anyone who installed
   the chart with defaults** — their objects were encrypted under the published
   key and the upgrade will refuse to start without `S3EP_AES_KEY`. That is the
   correct outcome (the alternative is continuing to encrypt under a public key),
   and CLAUDE.md wants no backward compatibility, but it belongs in the release
   notes, not only in the values file diff.
7. **Not verified:** whether the chart renders correctly under Helm versions
   older than the v3.21 used here, or under the v4.2.4 that CI pins. `deepCopy`,
   `fromYaml` and `fail` are all long-standing sprig/Helm builtins, but the new
   job is the first thing that will actually exercise the chart under the CI
   Helm version.
8. **The allowlist items 17 to 19 may need is a decision, not a detail.** If the
   first green run comes back with error-level lines Velero recovers from, the
   choice of what to excuse defines what the health check is worth for the rest
   of its life. Bring the list back for sign-off instead of committing it
   silently, and prefer fixing a hit over excusing it — S-1 and N-9, both closed
   on 2026-09-06, were failures the suite ran past because nothing was reading
   for them.
