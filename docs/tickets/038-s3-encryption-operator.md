# 038 — s3-encryption-operator: proxy instances provisioned by Custom Resources

## Decided 2026-09-14, before any of this is built

**The operator is a separate program**, with an entry point of its own rather
than a mode of the proxy binary, and it ships its own Helm chart. That chart
installs the operator; the operator then provisions proxy instances through its
Custom Resources. `s3-encryption-proxy` stays the single-instance chart and now
refuses `replicaCount` above 1 and autoscaling (ADR 0033). So the question this
ticket opened — whether operator and chart coexist or one replaces the other — is
answered: they coexist and do different jobs.

**It does not depend on [036](036-high-availability.md), and this was got wrong
once.** An operator that provisions single instances is a complete product: one
custom resource, one Deployment of the single-instance chart, as many of those as
the cluster needs. Nothing here waits on proxies that share an upload between
them. Whether the operator lives in this repository or its own is open; what is
decided is that it is not this binary.

**Configuration is read at start and only at start.** There is no `SIGHUP`, no
configuration watch, and the only signals handled are `SIGINT` and `SIGTERM`. An
operator that changes a backend therefore rolls the pod, which is what the
existing chart already does by hashing the rendered ConfigMap into the pod
template. That is a design input for the CR, not a defect.

**`/version` now answers the real build** — version, commit and build time —
rather than a hard-coded `dev`, so a CR status has something honest to report
without the operator having to read a metric.


Raised 2026-09-14 by the owner, **announced only**. **Not scheduled, no work
started, nothing designed.** It is written down today because 5.0.0 is being cut
today: a configuration key the proxy does not define refuses the start
([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11),
so changing the *shape* of a key is a breaking change, and a breaking change
ships in a major ([ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md)
D5). Whatever this feature would need the configuration to look like is free
today and costs a 6.0.0 later.

This ticket carries no decisions. Everything that needs one is under
*Open questions* and is **undecided**.

## What it is

A Kubernetes-native operator that manages several s3-encryption-proxy instances
in one cluster and provisions them from Custom Resources: it configures the
backends, distributes the licence, creates the Secrets holding the credentials
the proxy references, and reconciles the instances as the resources change.

The proxy itself is not the subject. The subject is everything around it that is
a Helm chart today, plus the parts a chart structurally cannot do — watching a
Secret, rolling a Deployment when something it does not render changes, and
reporting per-instance status back into a resource. Two neighbouring announcements
own questions this one only touches: [036](036-high-availability.md) for what
several replicas of one instance mean, and [037](037-multiple-backends.md) for
several backends behind one proxy.

## What the tree looks like today

Verified in this repo on 2026-09-14.

- **The chart already does most of this job.** `deploy/helm/s3-encryption-proxy/`
  renders a Deployment, Service, ConfigMap, Secret and ServiceAccount, plus
  optional Ingress, two cert-manager Certificates, HPA, PodDisruptionBudget,
  monitoring Service, ServiceMonitor and a Grafana dashboard ConfigMap. Into the
  ConfigMap it injects `license_file`, `tls:` and `monitoring:` and passes the
  rest of `.Values.config` through verbatim (`templates/configmap.yaml:9-36`).
- **The configuration is read once, at process start.** `config.LoadAndStartLicense()`
  at `cmd/s3-encryption-proxy/main.go:75`; the only signals handled are SIGINT
  and SIGTERM (`main.go:211`). There is no SIGHUP handler, no file watcher and no
  viper `WatchConfig` anywhere in the tree. **An operator cannot change a
  backend, a credential or a provider without restarting the pod.** Every
  reconcile that touches configuration is a rollout.
- **`${VAR}` expansion happens at that same load**, over exactly seven places:
  the four `s3_backend` fields, `s3_clients[].access_key_id` / `secret_key`, and
  every string under `encryption.providers[].config`
  (`internal/config/envexpand.go:51-103`). So a rotated Secret reaches a running
  proxy through nothing at all.
- **A client-driven multipart session is process-local.** It is filed in an
  in-memory map on the manager (`internal/orchestration/segmented_session.go:181-189`)
  and no other replica can adopt it
  ([docs/developer/multipart.md](../developer/multipart.md), "Shutdown ends what it
  is still holding"); a part arriving at another pod is answered `404 NoSuchUpload`
  (`internal/proxy/handlers/multipart/upload.go:162`). No `sessionAffinity` is set
  anywhere under `deploy/`, and `values-production.yaml:27-32` enables autoscaling
  from 3 to 20 replicas. *Scaling instances is not the same thing as scaling
  replicas*, and the operator has to know which one a CR means.
- **The proxy has no API-server footprint.** The chart's ServiceAccount sets
  `automountServiceAccountToken: false` (`templates/serviceaccount.yaml:12`) and
  no Role or ClusterRole exists under `deploy/`. An operator introduces the first
  Kubernetes privilege this product has ever held.
- **The listener certificate is loaded once.** `ServeTLS(listener, cert, key)` at
  `internal/proxy/server.go:263`, and no `tls.Config` with a `GetCertificate`
  callback exists on the serving path (the only one in the tree is the backend
  transport's, `server.go:211`). *Not verified by experiment here*, but it follows
  that a cert-manager renewal is not served until the pod restarts — and the pod
  template hashes only what the chart itself renders
  (`templates/deployment.yaml:22-28`), which a cert-manager Secret is not. This is
  an argument **for** an operator, not against it.
- **Nothing reports what a proxy loaded.** `/health` answers `{"status":"healthy"}`
  as soon as the listener is up and `503` only during shutdown
  (`internal/proxy/handlers/health/handler.go:60-87`); `/version` answers a
  hard-coded `"dev"` (`handler.go:114`); the monitoring listener's `/info` is a
  fixed string (`internal/monitoring/server.go:47-53`). No metric names a provider
  alias, a KEK fingerprint or the backend's reachability, and `monitoring.enabled`
  defaults to `false` (`internal/config/config.go:395`).
- **Nothing counts instances.** The licence carries a `k8s_cluster_id` claim
  (`internal/license/types.go:19`) that is only logged (`internal/license/logger.go:41-42`)
  and never validated. One token across many pods is unnoticed by the product today.

## What it would need from the configuration

Per item: the key as it is today, the shape the feature would need, whether
changing it later breaks a running deployment.

**1. `s3_backend:` — one endpoint per process.** A single struct,
`internal/config/config.go:29-35`. "Configures the backends" is either one CR per
backend (no change) or several backends per process, which makes `s3_backend` a
list or a map — **breaking later**, because every deployment writes this key. The
shape itself belongs to [037](037-multiple-backends.md); what this ticket adds is
that an operator is the party that would make several backends worth having.
*5.0.0 could do*: nothing on this ticket's account.

**2. There is no file form for a secret value.** `license_file`
(`config.go:169`) is the only key that names a file; `s3_backend.secret_key`,
`s3_clients[].secret_key` and a provider's `aes_key` arrive only as `${VAR}`.
A `*_file` sibling is **additive, not breaking** — an old configuration keeps
working on a new binary. *5.0.0 could do*: nothing. The later cost is one
decision (precedence when both are written), not a shape change.

**3. `s3_clients[]` and `encryption.providers[]` are already lists with a
`type` discriminator** (`config.go:38-46`, `config.go:64-69`). New client types
and new provider types are additive, and a provider's `config` is a `,remain`
map. *5.0.0 could do*: nothing — the shape an operator would want is already
there.

**4. `tls:` is one struct and the process opens one listener**
(`config.go:22-26`, `server.go:247-270`): TLS or plaintext, never both, so an
operator asked for both Services runs two Deployments, as the demo stack does. A
future `listeners: [...]` shape is **breaking later** and would rewrite the
chart's TLS injection (ADR 0026 D3) and every example configuration.
*5.0.0 could do*: adopt it — not cheap, only cheaper than a 6.0.0, and nothing
has decided the product wants two listeners. Listed to be decided, not proposed.

**5. An instance has no identity in its configuration.** The only thing naming a
deployment is four environment variables read by the metrics package —
`KUBERNETES_NAMESPACE`, `KUBERNETES_POD_NAME`, `HELM_RELEASE_NAME`,
`HELM_CHART_VERSION` (`internal/monitoring/metrics.go:13-16`) — turned into
metric labels, each omitted when empty (`metrics.go:19-36`), and set by the chart
(`templates/deployment.yaml:70-85`). Two are named after Helm. An operator either
writes a CR name into `HELM_RELEASE_NAME`, where the label lies, or leaves it
empty and the series changes shape. Renaming them is **breaking for anyone's
dashboards**; verified that the dashboard this repository ships uses none of the
four. *5.0.0 could do*: rename or drop the Helm-named pair. Cheap, and only free
in a major.

**6. `encryption.metadata_key_prefix` and a provider's key are not
per-environment values.** The prefix is the proxy's namespace
([ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md)) and
changing it orphans every object; a KEK's fingerprint is what a stored object
names. A CR that templates either per tenant destroys data on the next reconcile.
No configuration change is needed — the constraint lands in the CRD as
immutability, wherever this is taken up.

## What 5.0.0 could do now, and what it costs

- **Serve the real build information from `/version`** instead of the literal
  `"dev"` (`handler.go:114`). The process already holds version, commit and build
  time and hands them to the metrics package. It is a client-visible answer, so it
  carries a breaking marker (ADR 0018 D5) — which is exactly why the major is the
  cheap place for it. Small, and it gives an operator one thing to read that does
  not require the monitoring listener.
- **Settle the four Helm-named environment variables** (finding 5): rename, drop
  or keep deliberately. Free today, breaking after.
- **Everything else: nothing worth doing.** The two shapes a future operator might
  want — `s3_backend` as a list, `tls:` as a list of listeners — are changes to keys
  every deployment writes, for a feature with no design and no schedule. A shape
  adopted "just in case" is usually the wrong shape.

## Open questions — all undecided

1. **Chart and operator: coexist, or one replaces the other?** Coexist means two
   supported deployment paths and two places every new key has to land. Replace
   means dropping a published chart, which is a breaking change for every current
   installation and needs the upgrade note ADR 0030 D3 demands. A third option is
   an operator that renders the chart — one source of templates, one more
   dependency, and the chart's value keys become the CR's API by accident.
2. **What does the CR carry?** An opaque `config` string, the way the chart does
   (`values.yaml:214` → `configmap.yaml:36`): no duplication, and no validation
   until the pod refuses to start. Or a typed schema: admission-time validation
   and per-field status, at the price of every proxy key becoming CRD API surface
   with its own compatibility rules, duplicating the strict loader. Or a reference
   to an operator-managed ConfigMap, which pushes the question one object along.
3. **Does ADR 0030 D1 bind the operator?** The chart ships no NetworkPolicy
   because the administrator owns the boundary. An operator that reconciles the
   whole deployment is a different actor from a chart, and whether the rule is
   about charts or about this product is not decided here.
4. **How is the licence distributed, and does the product ever notice?** Today
   `S3EP_LICENSE_TOKEN` or `license_file` per pod, and the `k8s_cluster_id` claim
   is carried and ignored. If it is ever validated (ADR 0016 names this as an open
   residual risk), an operator spanning clusters, or one token across many
   namespaces, changes from a copy job to a policy question. *Not verified:*
   whether the commercial licence terms say anything about instance counts —
   that is not in this tree.
5. **Does the operator own rotation?** Watching a Secret or a cert-manager
   Certificate and rolling the Deployment is the gap the chart cannot close
   (`deployment.yaml:22-28`, and the chart README's *Known limitations*). It is
   also the most useful thing an operator could do on day one — and it is a
   privilege escalation of the product's footprint, so it belongs in
   `SECURITY_ARCHITECTURE.md` before it belongs in code.
6. **Where does instance status come from?** Today: nothing but metrics, off by
   default, on an unauthenticated listener whose content is itself a decision
   (ADR 0030 D2/D4). A status endpoint is additive to the configuration, but what
   it may name — a provider alias, a KEK fingerprint, a licensee — is a security
   decision, not an API design one.

## What it must not break

- **The strict loader.** A key the proxy does not define refuses the start, and
  the error names it (ADR 0013 D11). An operator that renders a key the running
  image does not know produces a crash loop, not a warning — version skew between
  operator and proxy image is a first-class failure mode here.
- **No key material outside a Secret.** A CR spec is a cluster-readable object;
  an `aes_key` written into one is key material in etcd outside the Secret API
  ([ADR 0021](../adr/0021-key-material-is-generated-never-committed.md)).
- **The licence gate.** Fatal at startup, no grace period, and `exit` is the one
  provider type admitted without a token
  ([ADR 0016](../adr/0016-the-license-is-a-startup-gate.md),
  [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)).
- **The metadata namespace.** The prefix is the proxy's alone and is not a
  per-tenant value (ADR 0009).
- **The stored format.** No operator action rewrites, migrates or re-encrypts an
  object ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md),
  [ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md)).
- **The scrape names no licensee** (ADR 0030 D4) — including any status the
  operator surfaces from it.

## Done when

- [ ] The chart-versus-operator relationship is decided and recorded in an ADR.
- [ ] The CR's configuration carrier is decided and recorded in an ADR.
- [ ] The backend question (one per instance or several per process) is answered,
      and the configuration consequence is taken in a major or explicitly deferred.
- [ ] The licence distribution model is written down, `k8s_cluster_id` included.
- [ ] The operator's Kubernetes privileges are in `SECURITY_ARCHITECTURE.md` as a
      trust boundary before any code exists.
- [ ] Replica-versus-instance is answered against the process-local multipart session.
- [ ] This ticket is archived, its decisions extracted into ADRs first.
