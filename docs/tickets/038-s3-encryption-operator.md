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

**The tree was gone over a second time the same day**, after ADR 0033 and the
`s3_backends` list had landed. What that found is under *Second pass* and is
lettered A-J; open questions 7-13 come out of it and cite those letters. Two
claims in *What the tree looks like today* were stale by then and have been
corrected in place rather than left standing.


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
- **`${VAR}` expansion happens at that same load**, and nowhere else: the four
  fields of **every** `s3_backends` entry, `s3_clients[].access_key_id` /
  `secret_key` per entry, and every string under `encryption.providers[].config`
  (`internal/config/envexpand.go:45-104`). An unset or empty variable refuses the
  start, naming the field. So a rotated Secret reaches a running proxy through
  nothing at all — the variable is read once, into a value that never changes
  again.
- **A client-driven multipart session is process-local.** It is filed in an
  in-memory map on the manager (`internal/orchestration/segmented_session.go:181-189`)
  and no other replica can adopt it
  ([docs/developer/multipart.md](../developer/multipart.md), "Shutdown ends what it
  is still holding"); a part arriving at another pod is answered `404 NoSuchUpload`
  (`internal/proxy/handlers/multipart/upload.go:162`). No `sessionAffinity` is set
  anywhere under `deploy/`. Since ADR 0033 the chart refuses `replicaCount` above 1
  and refuses autoscaling outright (`templates/_helpers.tpl:204-211`), and the
  production profile installs one instance with no budget
  (`values-production.yaml:15,34-41`) — so *scaling instances is not the same thing
  as scaling replicas* is now enforced rather than assumed, and the operator still
  has to know which one a CR means.
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
  (`internal/proxy/handlers/health/handler.go:49-95`); `/version` answers the real
  version, commit and build time since 2026-09-14 (`handler.go:98-140`), which is
  the one honest thing an operator can read without the monitoring listener; the
  monitoring listener's `/info` is still a fixed string
  (`internal/monitoring/server.go:47-53`). No metric names a provider
  alias, a KEK fingerprint or the backend's reachability, and `monitoring.enabled`
  defaults to `false` (`internal/config/config.go:395`).
- **Nothing counts instances.** The licence carries a `k8s_cluster_id` claim
  (`internal/license/types.go:19`) that is only logged (`internal/license/logger.go:41-42`)
  and never validated. One token across many pods is unnoticed by the product today.

## What it would need from the configuration

Per item: the key as it is today, the shape the feature would need, whether
changing it later breaks a running deployment.

**1. `s3_backends:` is a list already, and this stopped being a cost on
2026-09-14.** `Config.S3Backends []S3BackendConfig` (`internal/config/config.go:167`);
[037](037-multiple-backends.md) took the shape change into 5.0.0 for exactly the
reason this ticket was written, and everything *inside* an entry stays additive
afterwards. So "several backends per process" no longer forces a 6.0.0 and needs
nothing reserved here. What an operator must know instead: **this release reads
one entry and refuses a second by a message of its own**, so a CR naming two
backends does not start. *5.0.0 does*: nothing further on this ticket's account.

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
  `"dev"` — **done 2026-09-14** (`handler.go:98-140`). The process already held
  version, commit and build time; it is a client-visible answer, so it carried a
  breaking marker (ADR 0018 D5), which is why the major was the cheap place for it.
  It gives an operator one thing to read that does not require the monitoring
  listener, and it opens a question that had no subject while the answer was
  `"dev"` — see G and open question 11.
- **Settle the four Helm-named environment variables** (finding 5): rename, drop
  or keep deliberately. Free today, breaking after.
- **Everything else: nothing worth doing.** One of the two shapes a future
  operator might want — `s3_backends` as a list — landed on its own ticket's
  account. The other, `tls:` as a list of listeners, is a change to a key every
  deployment writes, for a feature with no design and no schedule. A shape adopted
  "just in case" is usually the wrong shape.
- **Not a configuration shape, and cheaper than any of them: give the backend
  credential an external-Secret path in the chart** (second pass, A). Additive,
  breaks nothing, and it is the first thing an operator needs that does not exist.

## Second pass, 2026-09-14: what else an operator inherits

Verified against the branch the same day, after ADR 0033 and the `s3_backends`
list had landed. Nothing here is decided either — it is what the next reader needs
in front of them before the first design session.

**A. The backend credential has no external-Secret path, and it is the first
thing an operator needs.** `secrets.encryption.existingSecret` and
`license.existingSecret` both exist; `secrets.s3` has neither
(`values.yaml:266-282`, `templates/secret.yaml:9-14`), so the backend access key
and secret reach the pod only through a Secret the chart renders from a plaintext
values field. A CR may not carry that value
([ADR 0021](../adr/0021-key-material-is-generated-never-committed.md)), so today
an operator would have to create the Secret itself and inject the pair through
`env`, going around `secrets.s3` entirely. Closing it in the chart is additive and
breaks nothing; whether the chart or the operator closes it is open.

**B. Three environment-variable names are an unwritten contract between the chart
and the configuration blob.** The pod is given `S3_ACCESS_KEY_ID`, `S3_SECRET_KEY`
and `S3EP_AES_KEY` (`templates/deployment.yaml:87-110`), and the shipped `config`
references exactly those three by name (`values.yaml:236-260`). Nothing checks the
pairing: a configuration naming a fourth variable renders, installs, and fails at
pod start with `environment variable ${...} is not set or empty`. An operator that
renders the configuration either adopts these three names as part of its own API
or validates the pairing at admission — which is open question 2 arriving through
the back door.

**C. The shipped default gives one key pair two roles, in every profile including
production.** `s3_backends[0]` and `s3_clients[0]` both read `${S3_ACCESS_KEY_ID}`
/ `${S3_SECRET_KEY}` in `values.yaml:236-245`, `values-production.yaml:125-131`,
`values-development.yaml:58-64` and `values-monitoring.yaml:97-103`. The chart
README carries it as known limitation 3 with the right consequence — a client
holding the backend key reaches the bucket directly, where it can write
unencrypted objects and delete stored ones without the proxy ever seeing the
request. A CR that defaults the way the chart defaults inherits exactly that.
Whether the operator *mints* the client credential rather than templating it is
worth deciding early: it is the one credential in this product that has no other
owner.

**D. A licence that lapses while the proxy runs ends the process.** The runtime
monitor calls a shutdown that exits 1 (`internal/license/validator.go:244-259`),
and the startup gate then refuses the restart
([ADR 0016](../adr/0016-the-license-is-a-startup-gate.md)) — so a pod does not
degrade, it crash-loops. With one token across a fleet, every instance does it
inside the same minute. What says why: the pod log, and
`s3ep_license_expiry_timestamp`, which is set once at startup and only when
`monitoring.enabled` is true (`internal/monitoring/metrics.go:164-181`). An
operator turns expiry from a per-pod surprise into a fleet event something could
warn about beforehand — an argument for the status of open question 6, and the
reason the licence question (4) is not only about distribution.

**E. Every reconcile that rolls a pod aborts the uploads that pod is holding.**
`Manager.Shutdown` sweeps the sessions it cannot finish and completes nothing
([docs/developer/multipart.md](../developer/multipart.md), *Shutdown ends what it
is still holding*; ADR 0029, ADR 0011). So the most useful day-one feature —
watch a Secret, roll the Deployment (open question 5) — turns a credential
rotation into a failed upload for every client that was mid-upload, and the client
sees `404 NoSuchUpload` on its next part rather than anything explaining it.
Whether the operator may roll on its own schedule, or may only *mark* an instance
as needing a roll, has to be decided before any watch is built.

**F. Readiness says nothing about whether the instance can do its job.** `/health`
answers 200 as soon as the listener is up, and 503 only during shutdown
(`internal/proxy/handlers/health/handler.go:49-95`): no backend reachability, no
provider, no KEK, no bucket. A CR status mirroring the Deployment's readiness
therefore reports "the listener answered", which is not what anyone reads a status
for. The verdict that would make Ready mean something is
[040](040-managed-buckets.md)'s startup readability check — the two tickets are
independent and meet exactly here.

**G. `/health` and `/version` are unauthenticated on the S3 listener**, matched
ahead of the authentication middleware by a matcher that takes any unsigned
request with no query (`internal/proxy/router.go:65-72`, `:167`). Since 2026-09-14
`/version` answers the real version, commit and build time. That is what makes it
useful to an operator with no monitoring listener, and it is also a precise build
identifier served to anyone who can reach the S3 port. ADR 0030 D4 decided what an
unauthenticated *scrape* may carry; the same question for this endpoint has not
been asked. An operator would be the first consumer to depend on the answer being
"everything".

**H. No configuration scopes an instance to a bucket.** `ListBuckets` is forwarded
as it stands (`internal/proxy/handlers/root/handler.go:66-109`) and no key
restricts what a client may reach. So "a proxy per team" is a credential boundary
onto the whole backend account, not a tenancy boundary: what separates tenants is
the backend's own IAM, and the operator would be provisioning a boundary this
product does not enforce. [040](040-managed-buckets.md) opens the nearest thing to
it.

**I. One instance is one Deployment, one Service, one ConfigMap, one Secret — and
TLS doubles it.** ADR 0033 fixes a chart install at one process, and `tls:` is one
struct with one listener (`internal/config/config.go:140`,
`internal/proxy/server.go:247-270`), so an instance asked to serve both plaintext
and TLS is two of everything, as the demo stack already is. Whatever "instance"
turns out to mean in the CR, the object count behind one is known today.

**J. The listener certificate is loaded once — now read in the code rather than
inferred.** `ServeTLS(listener, certFile, keyFile)` at
`internal/proxy/server.go:263`, and the serving path builds no `tls.Config` with a
`GetCertificate` callback anywhere. A renewed cert-manager Secret is therefore not
served until the pod restarts, and the pod template hashes only what the chart
renders (`templates/deployment.yaml:19-29`), which that Secret is not. Still not
verified *by experiment*; the code leaves no other reading.

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

7. **What does deleting the custom resource delete?** If the operator creates the
   Secret holding the KEK and gives it an `ownerReference` on the CR, removing the
   CR removes the key, and every object that instance wrote stops being readable.
   That is not the compatibility ADR 0017 declines to owe — it is data loss with no
   proxy involved. The safe shapes are a Secret the operator never owns, or a
   finalizer that refuses the delete while objects exist, and the second cannot be
   answered without knowing which buckets belong to the instance
   ([040](040-managed-buckets.md)).
8. **May the operator restart a running proxy on its own?** Everything useful it
   could do to a running instance is a rollout, and a rollout ends the
   client-driven uploads that instance is holding (second pass, E). The candidates
   are a policy field on the CR, a maintenance window, a condition it only reports
   and leaves to a human, or a held-upload count it waits on — and the last needs a
   number no endpoint reports today.
9. **Does the operator mint credentials, or only carry them?** The client
   credential in `s3_clients` has no other owner (C), the KEK must never be in a CR
   (ADR 0021), and the backend credential has no external-Secret path at all (A).
   "Generates a Secret" and "references a Secret" are different products with
   different blast radii, and the answer may differ per credential.
10. **Which image does a CR name, and who guarantees it matches the operator?**
    The strict loader turns a version skew into a crash loop (*What it must not
    break*), and the chart defaults the tag to the chart's `appVersion`. An
    operator that renders configuration for an image it did not choose has to pin
    the pair, refuse the CR, or carry a compatibility range it can state.
11. **What may an unauthenticated endpoint of a provisioned instance carry?**
    ADR 0030 D4 answers it for the scrape only; `/version` now answers a precise
    build and needs no signature (G). Whatever the operator surfaces as status is
    drawn from these, so this answer bounds the CR's status as well.
12. **Is a custom resource a tenant?** Nothing in the proxy scopes an instance to a
    bucket (H). If the pitch is one proxy per team, the isolation that claim rests
    on lives in the backend's IAM — say so, or build the scope.
13. **Where does the operator live, and what does that cost the release?** The
    header leaves the repository open. In this tree it shares the version, the
    pipeline and every release gate of the proxy, and a CRD becomes part of what
    5.x means; in its own it needs a second pipeline, a second licence story and a
    stated compatibility range against proxy images. Neither is free and the
    difference is not cosmetic.

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
- **An upload in flight.** A rollout the operator triggers ends every
  client-driven upload the pod is holding, and nothing is completed at shutdown
  (ADR 0029, ADR 0011). A reconcile is therefore never free, whatever triggered it.
- **Key material outlives the resource that provisioned it.** No deletion path of
  any custom resource may remove a key that stored objects still name (ADR 0021),
  and no reconcile may change a KEK fingerprint or the metadata prefix of a live
  instance (ADR 0009).

## Done when

- [ ] The chart-versus-operator relationship is decided and recorded in an ADR.
- [ ] The CR's configuration carrier is decided and recorded in an ADR.
- [ ] The backend question (one per instance or several per process) is answered,
      and the configuration consequence is taken in a major or explicitly deferred.
- [ ] The licence distribution model is written down, `k8s_cluster_id` included.
- [ ] The operator's Kubernetes privileges are in `SECURITY_ARCHITECTURE.md` as a
      trust boundary before any code exists.
- [ ] Replica-versus-instance is answered against the process-local multipart session.
- [ ] The restart policy is decided: whether the operator may roll a running
      instance on its own, and what is owed to the uploads it ends.
- [ ] What deleting a custom resource does to key material is decided and recorded.
- [ ] The credential model is decided per credential — backend, client, KEK,
      licence — as generated or referenced.
- [ ] What an instance's `Ready` claims is decided against what `/health` actually
      proves.
- [ ] What an unauthenticated endpoint of a provisioned instance may carry is
      decided, `/version` included.
- [ ] This ticket is archived, its decisions extracted into ADRs first.
