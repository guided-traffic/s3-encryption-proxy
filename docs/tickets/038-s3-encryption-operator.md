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

**`/version` answered the real build for one day, and was then deleted.** The
probe round of 2026-09-15 removed `/health`, `/version` and `/info` from both
listeners (ADR 0034). What a CR status can be drawn from instead is `/status` on
the monitoring listener, which is off by default and unauthenticated by design —
see the corrected bullet under *What the tree looks like today* and open
question 29.

**The tree was gone over a second time the same day**, after ADR 0033 and the
`s3_backends` list had landed. What that found is under *Second pass* and is
lettered A-J; open questions 7-13 come out of it and cite those letters. Two
claims in *What the tree looks like today* were stale by then and have been
corrected in place rather than left standing.

## Decided 2026-09-16

**The operator lives in this repository.** That settles the first clause of
open question 13 and turns its second clause from a hypothesis into a list of
obligations, each verified today. One version stream covers both programs:
`release.config.mjs:76` sets `branches: ["main"]` and the file carries no
`tagFormat` key at all. Every existing release gate applies to operator code,
because the one `semantic-release` job
(`.github/workflows/test-pipeline.yml:1034`) is gated *by* every other job
through the `needs:` list at `:1059` — so a new operator end-to-end job joins
that list or it gates nothing. And `go.mod` requires no `k8s.io/*`, no
`sigs.k8s.io/*` and no controller-runtime, so the whole Kubernetes client
module graph arrives inside the module the proxy binary is built from, where
`gosec`, `govulncheck`, the coverage merge and the image build all meet it.
**What remains open inside 13:** whether a change to the Custom Resource
Definition carries the breaking marker under
[ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md) D5 (question
16), and whether the two programs share one Go module (question 36). **It
settles nothing in open question 1** — sharing a repository says nothing about
whether the chart and the operator coexist — and question 1 was in any case
already answered by the 2026-09-14 block above and left standing in the list
by mistake; that is a correction, not a decision.

**Custom Resources are namespaced.** This answers nothing that was asked: the
ticket never asked how the resource is scoped. It is new ground and it is the
decision the other three hang from. It **sharpens open question 12 rather than
answering it**: a namespaced resource reads as a tenancy boundary to every
Kubernetes reader, while nothing in the proxy scopes an instance to a bucket —
`SECURITY_ARCHITECTURE.md:90` states outright that there is no per-client
bucket or prefix scoping, and `HandleListBuckets` forwards the request as it
stands, copying prefix, continuation token, bucket region and maximum through
to the backend and filtering nothing
(`internal/proxy/handlers/root/handler.go:66-101`). The API shape now implies
an isolation the runtime does not enforce, which makes writing the non-claim
down a requirement rather than tidiness. It opens questions 19 and 20, because
a namespace boundary that is not a cryptographic boundary raises the question
of what key material sits on each side of it.

**One cluster-scoped operator Deployment serves the whole cluster.** Also new
ground: nothing in questions 1-13 asked how many operator installs there are.
It opens two that were never asked — what the operator's ServiceAccount may
hold cluster-wide (question 14), and whether there is a second replica and
what a standby holds (question 34) — and it has a cost the ticket can state
from what is verified: because the loader decodes in its exact mode
(`internal/config/config.go:325`, `dc.ErrorUnused = true`;
[ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)
D11), every independent copy of the configuration renderer is an independent
crash-loop risk against whatever proxy image its namespace runs. One
Deployment collapses that skew matrix; it also collapses every namespace's
provisioning into one pod's availability.

**No cross-namespace references inside a Custom Resource.** This is the
containment for the previous decision rather than a convenience: a
cluster-scoped operator must be able to reach Secrets in every namespace to
serve a resource in any namespace, so the schema is the only thing standing
between a namespace's own author and a Secret elsewhere in the cluster. **It
bounds one corner of open question 2** — for reference fields specifically, a
Secret is named by a name plus a key and there is no field in which a foreign
namespace can be written — and it settles nothing else in 2: whether the
resource carries an opaque configuration string, a typed schema or a reference
to an operator-managed ConfigMap is untouched. **It settles nothing at all
about the controller's own reach.** The rule constrains the resource's
*author*; the operator's ClusterRole is a second and wider boundary, and the
two are different entries in a trust-boundary table, not one (question 14).

**The operator reads Secrets holding backend credentials and writes the
proxy's own S3 client credentials back as Secrets.** This half-answers open
question 9: the backend credential is carried, the client credential is
minted. **What remains open inside 9** is the other two rows of the same table
— the KEK (question 19) and the licence (question 15) — and 9 already said the
answer may differ per credential. It also gives open question 7 a concrete
subject it did not have: there is now a Secret the operator creates, so "what
does deleting the resource delete" is no longer hypothetical. Minting the
client credential retires a live defect in the shipped chart rather than
inventing a problem: `deploy/helm/s3-encryption-proxy/values.yaml:255-256` and
`:260-261` resolve `s3_backends[0]` and `s3_clients[0]` from the same two
variables, and
`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:96-107` binds both
to one Secret's `access-key-id` and `secret-key`, so out of the box the
credential a client uses against the proxy *is* the credential the proxy uses
against the bucket. The write side is the largest new privilege in the design
and is question 14.

**cert-manager is adopted into the kind end-to-end setup.** New ground;
questions 1-13 do not mention it. It closes a gap
[ADR 0026](../adr/0026-the-proxy-terminates-tls-at-its-own-service.md) records
in its own status block — the cert-manager arm is exercised by rendering only,
and that is named there rather than left to be discovered
(`docs/adr/0026-the-proxy-terminates-tls-at-its-own-service.md:19-21`,
restated at `:125-127`) — and nothing in this repository installs cert-manager
today. It must not promote cert-manager from the optional arm ADR 0026 D4
grants it to a product requirement: D4 makes bringing your own certificate
first-class precisely so that "cert-manager is then not required at all", and
that is the arm every current user and the Velero suite run on. It opens
questions 30, 31 and 37.

**These decisions owe ADRs, and the number is contested.**
[ADR 0022](../adr/0022-tickets-are-work-lists-that-get-archived.md) D2
requires the ADR to be written in the session the decision is taken, not when
the implementation lands; D3 says a ticket is a work list and nothing else,
not the decision record; D4 says an archived ticket is history and never a
source of a current rule, so a rule found there is the same process defect as
a rule found in a live one. The block above is therefore a second dated
decision record inside a work list, stacked on the 2026-09-14 one, and both
owe extraction. Two subjects follow from what was decided today: the
operator's **scope** — one cluster-scoped controller over namespaced
resources, and what a resource may and may not name across a namespace
boundary — and the **credential model** — which credential is carried, which
is minted, which is written back, and who owns the Secret each lives in.
Folding them into one ADR is defensible and makes the credential rules harder
to cite on their own. **The numbering moved twice on 2026-09-18, which is the hazard
itself:** the high-availability work took 0036
([ADR 0036](../adr/0036-a-response-follows-s3-deviates-for-the-client-and-is-never-a-break.md)),
this ticket then claimed 0037, and the backend-trust work took 0037
([ADR 0037](../adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md))
the same day. **The two ADRs owed here start at 0038.** ADR 0022 carries this
outright as an accepted residual risk — ADR numbers are assigned by hand with no
uniqueness check — and it cost nothing either time only because the bodies of
work landed one after the other instead of side by side. Read the directory
before claiming a number; a claim written down in a ticket is not a reservation. Whether
the two ADRs are written now or at the next refining round is not decided
here.

**The operator's ServiceAccount holds cluster-wide read and write on Secrets,
bounded on the write path by a `ValidatingAdmissionPolicy` that rejects any
Secret write by that ServiceAccount whose object lacks a controller
`ownerReference` to a Custom Resource of this operator's kind.** This closes
open question 14 on the verb list itself: the read half is `get`, `list` and
`watch` on `secrets` in every namespace, and the write half is `create`,
`update` and `patch` — `patch` because a controller-runtime client doing
server-side apply or a merge patch needs it, and a grant without it forbids
the write pattern most operators use while looking complete; the policy side
is unaffected, because a PATCH request reaches admission as `UPDATE`
(Kubernetes semantics, high confidence), so the policy's operations list stays
`CREATE` and `UPDATE`. The three narrower candidates question 14 listed are
rejected, and each costs something different rather than the same thing three
times: **no `secrets` verb at all** costs admission-time validation that the
named Secret exists, costs the rotation watch, and costs the claim that a
provisioned proxy comes with working credentials; **read cluster-wide, write
nowhere** keeps both of those and retires the largest privilege, at the cost
of one more credential per instance for a human to generate and hand over; **a
namespaced Role an administrator binds per namespace** costs self-service
provisioning into a namespace nobody enrolled by hand, and needs a legible
refusal in an unenrolled namespace rather than a 403 loop. **No `delete` and
no `deletecollection` on `secrets` is part of the same closure and is derived
rather than open**: the controller `ownerReference` the policy demands is also
what makes the garbage collector remove the Secret with its resource, so the
verb has no consumer, and acquiring one later is a design change that drags a
`DELETE` entry in the operations list and a third validation keyed on
`oldObject` behind it. What remains open inside 14 is two things and neither
is settled here: whether the operator holds read-only `get`, `list` and
`watch` on `admissionregistration.k8s.io` so it can see its own bound and
refuse to run unbounded; and which Secrets the informer actually decodes,
which is question 21 and which D-A narrows rather than answers. It narrows
three neighbours without closing any: question 17 gains a candidate built from
the same machinery — a policy of this shape over `configmaps` — alongside the
four it already carries, and whether that is better than a per-namespace Role
is still 17's to decide; question 18 gains a sixth candidate beside its five,
one policy over `deployments` asserting the PodSpec carries no `hostPath`,
`hostPID`, `hostNetwork` or privileged container, installed with machinery
already being paid for; and question 21 loses its first candidate outright.
What it costs, in verified terms: nothing in this organisation has ever
written one — a grep of the valkey-operator tree for
`ValidatingAdmissionPolicy` and `admissionregistration` returns zero hits — so
the policy, the binding, their chart templates, their CI bring-up and the
end-to-end cases that prove a denial are all written from nothing. It costs
one new open question, 39, who installs the two objects. And the bound is
narrower than the sentence sounds: **the policy bounds the write path only,
because admission runs on writes and never on reads** (Kubernetes semantics,
high confidence), so cluster-wide `get`, `list` and `watch` over every Secret
in the cluster is untouched by this or any other admission policy and is
recorded under *Accepted residual risks, 2026-09-16*. One correction rides
with the decision and is load-bearing on the version floor: what is GA in
`admissionregistration.k8s.io/v1` from Kubernetes 1.30 is the two resources
`ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`, not the
group version, which has served `ValidatingWebhookConfiguration` since 1.16
(Kubernetes semantics, high confidence) — and the proxy chart's
`kubeVersion: ">=1.34.0-0"` (`deploy/helm/s3-encryption-proxy/Chart.yaml:10`)
is evidence about the *proxy* chart and about nothing else. Its floor is 1.34
because `lifecycle.preStop.sleep` is stable there, and its `-0` suffix exists
because without it Helm reads a distribution version such as 1.34.4-gke.1 as a
prerelease and refuses a cluster that meets the requirement
(`Chart.yaml:7-9`). The operator ships its own chart and needs a floor of its
own, declared deliberately, or it advertises a bound the cluster may not have
— and both question 14 and finding Q currently infer an operator-side
capability from that one proxy-chart line.

**The Custom Resource carries a fully typed schema over the proxy's
configuration keys.** Not an opaque `config` string, not a reference to an
operator-managed ConfigMap, and not a hybrid — so
`x-kubernetes-preserve-unknown-fields` on the per-type provider `config:`
block is out, because that block is exactly where a hybrid would hide. This
closes open question 2 on the carrier and confirms the price the question
already named, measured: `internal/config/config.go` carries 50 `mapstructure`
tags between `:23` and `:180`, of which nine are not leaves — `tls` (`:140`),
`monitoring` (`:159`), `s3_security` (`:171`), `encryption` (`:177`),
`optimizations` (`:180`), `s3_backends` (`:167`), `s3_clients` (`:170`),
`providers` (`:60`) and the `,remain` catch-all at `:45` — leaving 41 declared
leaves, plus `aes_key`, which exists in no struct field and only in
`providerConfigKeys` (`:914-917`), for 42 leaves of API surface. They sit
under nine Go structs, three of which are the list element types
(`S3BackendConfig`, `EncryptionProvider`, `S3ClientCredentials`), each with
compatibility rules of its own, and `validateProviderConfig` (`:952-977`) is
duplicated in the schema as a discriminated union whose `exit` arm is a
presence rule rather than a value rule. One of the 42 is a curiosity worth
naming because a generated schema will expose it:
`EncryptionProvider.Description` (`:41-44`) is declared precisely so that it
is never read — it consumes `description:` here instead of letting it fall
into `Config` through `,remain`, where the provider would refuse it as an
unknown key. What remains open inside 2 is per-leaf rather than structural:
which leaves the operator sets rather than exposes — `license_file`,
`tls.cert_file`, `tls.key_file`, `bind_address` and the two monitoring
addresses are the candidates, and the chart already refuses a `tls:` or a
`monitoring:` block inside `values.config`
(`deploy/helm/s3-encryption-proxy/templates/_helpers.tpl:248`, `:254`) for the
same reason. The genuine advantage, and the reason this is not merely more API
for its own sake, is one refusal that has an admission form under this arm and
under no other: the chart derives the pod's termination grace period from the
configuration it renders — `_helpers.tpl:131` parses the rendered
configuration, `:132` reads `shutdown_timeout` out of it with a fallback of
30, `:133` replaces a value below 1 with 30, `:134` reads
`preStopSleepSeconds`, `:135` sums the three, and `:140-141` fails the render
when a supplied `terminationGracePeriodSeconds` is below that sum — and CEL
expresses that inequality directly, while against an opaque configuration
string it cannot be written at all, because CEL has no YAML parser (Kubernetes
semantics, high confidence; it is why the chart does the parse in a Go
template). So the pod that is killed inside its own drain, which skips the
multipart sweep of ADR 0029 D1 and leaves every held upload open at the
backend where nothing but a lifecycle rule collects it (ADR 0029 D2, D6),
stops being constructible rather than being refused at render time by one
template nobody runs twice. Two smaller gains come free: `log_level` and
`log_format` are validated by no loader rule and fail as a `Fatal` in
`cmd/s3-encryption-proxy/main.go:108-125` after the licence has already been
checked, and both become enums at `kubectl apply`. Two costs are named rather
than discovered — the cross-field rule forces `terminationGracePeriodSeconds`,
`preStopSleepSeconds` and the configuration's `shutdown_timeout` into one CEL
subtree, so the pod shape and the proxy configuration cannot be independent
top-level objects; and the loader's fatal refusal of an unknown key does not
survive the resource boundary, which is recorded under *Accepted residual
risks, 2026-09-16* rather than as a surprise.

**The operator holds one licence token and copies it into each provisioned
namespace as a Secret.** This closes open question 15 on the mechanism and
fills the last carried-versus-minted row but one of open question 9: the
backend credential is carried, the proxy's own client credential is minted,
the licence is carried and copied, and only the KEK row is left open as
question 19. The route is the one the chart already has and the operator
reproduces it exactly: `templates/configmap.yaml:10-11` injects
`license_file: "/app/license/license.jwt"`,
`templates/deployment.yaml:157-168` projects the licence Secret with its key
mapped to path `license.jwt`, and `:137-141` mounts it read-only — a file,
never `S3EP_LICENSE_TOKEN`, because the environment route silently wins over
the file (`internal/license/validator.go:372-389` reads the variable first,
`:332-341` the file) and because the chart deliberately keeps the licence off
the container environment while putting the KEK into it (finding AG). What
bounds the severity of what this hands out is ADR 0016 D12, verbatim: "The
license gate is a commercial control and is never presented as a security one"
(`docs/adr/0016-the-license-is-a-startup-gate.md:138`). A stolen copy grants
no read of any stored object, no key material, no backend credential and no
position on any data path; the loss is revenue. What that D-number does
**not** bound is three things and each is a cost of this decision: it does not
bound the copy count, because N provisioned namespaces means N readable copies
and N places to leak from, where the administrator-supplied alternative has as
many copies as humans chose to make; it does not bound the duration, because
there is no revocation of any kind — `checkClaims` refuses a token with no
`exp` claim (`internal/license/validator.go:123-149`, ADR 0016 D3) and refuses
one whose expiry has passed, which is the running-proxy rule of ADR 0016 D4
(`docs/adr/0016-the-license-is-a-startup-gate.md:101-104`), and nothing else
is checked: `k8s_cluster_id` is parsed (`internal/license/types.go:19`),
logged (`internal/license/logger.go:41-42`) and compared to nothing, and the
trust anchor is a public key compiled into the binary, so withdrawing a copy
needs a new keypair and a rebuild of every image; and it does not bound the
default, because under this decision a namespace holds a copy by virtue of a
resource having been created there rather than because anyone decided that
namespace should hold one, which is precisely the outcome the
no-cross-namespace rule exists to foreclose, accepted here deliberately and
for the licence alone. One precondition outside this tree blocks the licence
ADR rather than this decision, and it is recorded in question 15 with a named
owner.

---

**A policy and a binding are two objects, and one cluster-scoped binding
covers every namespace.** Kubernetes semantics, high confidence, not a fact in
this tree: the `ValidatingAdmissionPolicy` is inert on its own and declares
`matchConstraints`, `matchConditions`, `variables`, `validations` and
`failurePolicy`; the `ValidatingAdmissionPolicyBinding` activates it and
carries `policyName`, an optional `paramRef`, `matchResources` and
`validationActions`. Both are cluster-scoped, and the binding's
`matchResources` can only narrow the policy's `matchConstraints`, never widen
them. A binding whose `matchResources` carries no `namespaceSelector` matches
every namespace, `kube-system` included — so one policy plus one binding
covers a cluster-scoped operator serving arbitrary namespaces and no
per-namespace enrolment object is needed. That is the property D-A depends on:
a per-namespace object would reintroduce exactly the administrator handshake
the cluster-wide grant was chosen to avoid, which is what makes question 14's
namespaced-Role candidate a different product rather than a safer version of
this one.

**The identity match is a `matchCondition` on `request.userInfo.username`, and
the `system:serviceaccount:` form cannot be spoofed by a holder of that
token.** Kubernetes semantics, high confidence: the CEL environment exposes
`request` as the `AdmissionRequest`, and a token-authenticated ServiceAccount
always presents the username `system:serviceaccount:<namespace>:<name>`, a
string the authenticator constructs from the verified token rather than one
the client supplies — so a holder of the operator's token cannot present as
anything else, and no other writer of Secrets in the cluster can present as
the operator. It belongs in `matchConditions` and not in `validations`,
because a false matchCondition means the policy does not apply, which is what
is wanted for cert-manager, for Helm, for a human and for the kubelet, whereas
a false validation denies. The operator's namespace is a chart value, so the
username is templated into the policy or carried in a `paramRef` object.
Matching on `'system:serviceaccounts:<ns>' in request.userInfo.groups` instead
is broader and wrong: it binds every other ServiceAccount in the operator's
namespace.

**The weakness, stated without softening: a policy performs no lookup, and a
compromised operator forges an `ownerReference` that is true in every respect
anything checks.** Kubernetes semantics, high confidence: a policy evaluates
one request against `object`, `oldObject`, `request`, `namespaceObject`,
`authorizer` and a statically selected `params`. It has no client and no
lister. `paramRef` is selected by static name or label selector from the
binding and cannot be derived from a field of the incoming object, so it is
not an existence check, and `authorizer` answers *may this user do X*, never
*does this object exist*. The attacker does not even need a forgery that would
fail a later resolution: a compromised operator holds `get`, `list` and
`watch` on its own Custom Resources by construction, so it reads a real
resource's name and its real `uid` and writes an `ownerReference` the garbage
collector resolves successfully and therefore never acts on. Garbage
collection bounds litter, not capability, and must not be cited as a bound at
all; even in the weaker case where the owner does not exist, GC is an
asynchronous loop and the attacker reads what it wrote in the same second. The
policy asserts the *shape* of the ownership claim completely and its *truth*
not at all, and the residual risk that follows is recorded under *Accepted
residual risks, 2026-09-16*.

**What does bind is a fixed literal in the written Secret's name, and a second
validation on `oldObject`.** The owner's name inside a forged reference is
attacker-chosen, so a rule tying `object.metadata.name` to the owner's name
constrains nothing on its own; what constrains the reachable name space is the
literal in the pattern, which is what puts a namespace's registry pull secret
— `regcred`, `gcr-json-key`, a default-named `builder-dockercfg-xxxxx` — out
of reach, and puts `bootstrap-token-<id>` in `kube-system` out of reach with
it. The second rule removes the overwrite primitive rather than renaming it:
on `UPDATE` the old object must already carry the controller reference,
`request.operation != "UPDATE" || (has(oldObject.metadata.ownerReferences) && oldObject.metadata.ownerReferences.exists(o, o.controller == true && ...))`.
Kubernetes semantics, high confidence: a `create` against an existing name is
`409 AlreadyExists` and is never silently converted to an update, and a
server-side apply generates a `CREATE` request when the object does not exist
and an `UPDATE` when it does — so the overwrite primitive lives entirely on
the update path, and this clause removes it by forbidding the adoption of a
Secret the operator did not create. Without it, the object-side rule alone is
satisfied by an update that merely *adds* the forged reference to a foreign
Secret.

**Two further clauses are required by D-A rather than proposed alongside it,
because they are what make its bound real.** The first is
`object.type == "Opaque"`, and it is load-bearing and live rather than defence
in depth: manually creating a Secret of type
`kubernetes.io/service-account-token` carrying the
`kubernetes.io/service-account.name` annotation is a currently supported way
to mint a long-lived token, and the token controller still populates it — what
Kubernetes 1.24 removed was automatic generation, not manual creation
(Kubernetes semantics, high confidence). Such a Secret may carry any name, so
the name literal does not stop it, and an `ownerReference` does not inhibit
the token controller, so the ownership clause does not stop it either. Without
the type clause, `create secrets` in every namespace is a token for any
ServiceAccount in that namespace, privileged ones included; with it, that path
is closed and the neighbouring `bootstrap.kubernetes.io/token` path is closed
twice over, since a bootstrap token must be named `bootstrap-token-<id>` and
the name literal already forecloses it. The second required clause is the
`oldObject` adoption refusal above: omit it and the policy bounds only the
naming of an overwrite, not the overwrite.

**The name rule is a disjunction over a closed, enumerated set, because D-C
adds a second operator-written Secret shape.** The minted proxy client
credential is one shape; the copied licence Secret of D-C is a second, and the
rule is `object.metadata.name` matching one of an enumerated set of derived
names rather than a single suffix. Since the set is the only thing that
genuinely constrains the reachable name space, widening it is widening the
bound: the set is closed, and adding to it is a deliberate act with its own
line in `SECURITY_ARCHITECTURE.md`, never a consequence of a later feature
needing somewhere to put a value.

**The CEL owner clause is group-pinned and version-agnostic, never pinned to
one `apiVersion`.** An `ownerReference` records the `apiVersion` its writer
used and nothing rewrites it afterwards (Kubernetes semantics, high
confidence), so a clause of the form `o.apiVersion == "<group>/v1"` stops
matching every Secret written under an older served version the moment
question 16 takes its served-version candidate — and the symptom is the
operator silently losing the ability to update its own fleet's credentials, on
exactly the resources that have been in service longest. The correct shape on
both `object` and `oldObject` is
`o.apiVersion.startsWith("<group>/") && o.kind == "<CRKind>" && o.controller == true`,
guarded with `has(...)` for the absent-list case. Matching on `kind` alone is
the opposite error and is equally wrong: `kind` is not unique across API
groups.

**`failurePolicy: Fail` and `validationActions: [Deny]` are the only safe
values, and the case that makes them expensive has to be named rather than
implied.** The two fields take different value sets and must not be conflated:
`failurePolicy` is `Fail` or `Ignore`, and `validationActions` is any of
`Deny`, `Warn`, `Audit`. With `Fail`, any evaluation error, any type-check
failure, or a `paramRef` miss under `parameterNotFoundAction: Deny` denies
every Secret write the operator makes, in every namespace, at once — one
cluster-scoped object is a single point of failure for provisioning the whole
fleet, with no per-namespace blast radius and no degraded mode, and the
symptom is N reconcile loops producing denial-shaped refusals rather than one
visible broken object. That is the correct trade and `Fail` is still right; it
is also the failure the legible-refusal language of question 14 was written
for, and it is the reason question 14 still has read-only `get`, `list` and
`watch` on `admissionregistration.k8s.io` open inside it rather than settled
here — with those verbs the operator can check its own bound and report
`Ready=False` with a named reason instead of looping, and whether it holds
them is 14's to answer.

**`matchConstraints.resourceRules[].operations` is itself the control for
DELETE.** Listing only `CREATE` and `UPDATE` means no policy is invoked on a
delete at all, so there is no hole for an object-side rule to miss — the
operations list is the decision, not an oversight to be patched in CEL. It
costs nothing here because the design holds no delete verb on `secrets`: the
controller `ownerReference` the policy already demands is what makes the
garbage collector remove the Secret when its resource goes away, which is the
mechanism question 7 is about. Should a `delete` verb ever be argued for, it
is a change to D-A and drags a `DELETE` entry in the operations list and a
third validation keyed on `oldObject` with it, where the object being removed
is populated and the rule is perfectly writable.

**The bound is subordinate to finding M, and the claim the ticket may make is
bounded accordingly.** Finding M establishes that the operator needs `create`
and `update` on `deployments` in every namespace, that whoever authors a
PodSpec chooses `hostPath`, `hostPID`, `hostNetwork` and `privileged`, and
that the Deployment controller then creates the pod under its own identity so
the operator's RBAC is never re-checked against what the PodSpec asked for.
That is an identity escape, and every identity-scoped admission policy is
downstream of it: a compromised operator writes a privileged pod, reaches the
kubelet's credentials, and from the node holds the tokens of every pod
scheduled there — identities the matchCondition does not name and the policy
therefore does not apply to. So the claim is that the policy removes a direct,
silent, one-request overwrite primitive and forces a loud, multi-step path
that leaves a privileged pod sitting in a namespace. It is never that a
compromised operator cannot overwrite an unrelated Secret. Whether the loud
path is also closed is question 18.

**If question 26 takes the upgrade hook, the bound acquires a second identity
it does not match.** Finding W records what the valkey-operator does — a Helm
pre-upgrade hook Job running a subcommand, with its own short-lived
ServiceAccount, ClusterRole and ClusterRoleBinding — and question 26 has not
decided whether this product ships a hook at all, one of its candidates being
no hook. Should a hook of that shape be taken, a Job under its own
ServiceAccount does not match `request.userInfo.username` in either direction:
the policy does not apply to it, so the hook is unbounded, and equally the
hook cannot rely on its writes being validated the way the operator's are.
Either the hook runs as the operator's own ServiceAccount and inherits the
bound, or the bound has a second hole with a name and a chart template. That
is part of question 26 and is not decided here.

---


## Accepted residual risks, 2026-09-16

These are risks the owner took with the trade-off in front of them. They are
recorded as accepted, with the mitigation that carries each, so that nobody
re-opens one as a defect and nobody cites one as unowned.

**Cluster-wide `get`, `list` and `watch` on every Secret in the cluster,
bounded by nothing.** The mechanism: admission runs on the write path only
(Kubernetes semantics, high confidence), so D-A's policy reduces the read
surface by not one Secret — cert-manager CA private keys, manually created
service-account-token Secrets, registry pull secrets, and Helm's own
`helm.sh/release.v1` objects carrying the rendered manifests of every
installed chart are all readable by the operator's token in every namespace.
It is accepted because each alternative candidate in question 14 gave up
something the operator exists to provide: admission-time validation and the
rotation watch, or one more credential per instance handed over by a human, or
self-service provisioning into a namespace nobody enrolled. The mitigation
that carries it is **not** the verb list — it is the cache decision of
question 21, which is now narrower and more urgent than it was, because the
surviving default is "cache everything" and that is the shape this repository
has already written against itself: `validateMonitoring` refuses a
non-loopback `monitoring.pprof_bind_address` at startup
(`internal/config/config.go:634-644`) for the reason its own comment gives at
`:630-633`, that "a heap or goroutine profile of this process contains DEKs
and plaintext buffers". A heap dump of a process caching every Secret in the
cluster is that argument applied to a bigger subject, and the operator has no
equivalent refusal today.

**A compromised operator forges an `ownerReference` the policy cannot
falsify.** The mechanism is under *Decided 2026-09-16*: a policy has no client
and no lister, `paramRef` is statically selected and is not an existence
check, and `authorizer` answers what a user may do rather than whether an
object exists — so an operator that already holds `get`, `list` and `watch` on
its own Custom Resources reads a real resource's name and `uid` and writes a
reference the garbage collector resolves and never acts on. It is accepted
because taking the fourth candidate of question 14 is taking this with it: no
admission policy can check an assertion about another object's existence, and
the alternatives that could — a webhook with a lister, a per-namespace Role —
are the candidates already rejected for their own costs. The mitigations that
carry it are two and both are inside the policy: the closed, enumerated name
set, which is what actually constrains the reachable name space and keeps pull
secrets and bootstrap tokens out of it; and the `oldObject` adoption refusal,
which forbids adding the forged reference to a Secret the operator did not
create. The bound they buy is exact and must be stated that way: a direct,
silent, one-request overwrite of an arbitrary Secret is removed, and a
compromised operator is not stopped — it is pushed onto the loud, multi-step
path of finding M, which leaves a privileged pod sitting in a namespace and is
question 18's subject.

**The operator is a distributor of licence material, and a namespace holds a
copy by default rather than by decision.** The mechanism: under D-C, obtaining
the company token requires writing a Custom Resource in a namespace you
already control and then reading the Secret the operator writes beside your
pod; under the administrator-supplied alternative it requires a human who
already holds the token to place it there. The population that gains is
everyone who can create a resource of this kind anywhere, and what they gain
is a bearer JWT with no cluster binding — `k8s_cluster_id` is parsed
(`internal/license/types.go:19`), logged (`internal/license/logger.go:41-42`)
and compared to nothing — valid until its `exp` and withdrawable by nothing
short of a new keypair and a rebuild of every image. It is accepted on ADR
0016 D12, which is precise about the split and both halves belong here: the
gate is a commercial control and is never presented as a security one, while
its *lapse* is documented as a security-relevant availability property, since
an expired licence stops all new encryption and stops reads as well until the
operator acts (`docs/adr/0016-the-license-is-a-startup-gate.md:138-144`). So a
stolen token buys the ability to run the product and no byte of anyone's data,
and the thing with a blast radius is expiry rather than theft — which is
finding AM's subject. The mitigation that carries it is one and it exists
today: the copy is written per resource and carries a controller
`ownerReference`, so it is removed with the resource by the garbage collector
rather than accumulating in namespaces nobody provisions into any more.
Whether a copy is written at all for an instance that needs none is question
40 and is not a mitigation this risk leans on.

**Forty-two configuration leaves become API surface, two validators must
agree, and the loader's fatal refusal of an unknown key does not survive the
resource boundary.** The mechanism: the loader's central promise is that a key
it does not define refuses the start and the error names it —
`dc.ErrorUnused = true` at `internal/config/config.go:325`, with the message
at `:329-333` telling the reader that a key this version does not define stops
the start instead of being ignored (ADR 0013 D11). A structural CRD schema
does not do that, and the replacement is not one behaviour but two, split by
who is writing. Kubernetes semantics, high confidence: `kubectl`'s
`--validate` defaults to strict, so a human's `kubectl apply` carrying an
unknown field is **rejected with an error**; the apiserver's own
`fieldValidation` default of `Warn` applies to a programmatic writer that
sends no parameter — a client-go typed client, which is what the operator
itself is — and there the field comes back as a `Warning:` response header and
is pruned. So the gap D-B accepts is **an error at `kubectl apply` and a
warning for programmatic writers**, not refusal versus silence, and the stated
mitigation covers exactly the second path: the operator's own client requests
strict field validation, and a drift check compares the generated CRD's leaf
set against the `mapstructure` paths of `Config`
(`internal/config/config.go:23-180`). The part with no CRD analogue at all is
the three by-name migration messages, which exist precisely because a generic
unknown-key error would mislead: `optimizations.multipart_session_max_age` at
`:252-258`, which says the replacement key counts from the last part rather
than from creation so the same number means something else;
`optimizations.streaming_segment_size` at `:264-270`, which says the value and
its checks are unchanged and only the name moved; and `s3_backend` at
`:275-280`, which says to move the block under a single `- ` entry of
`s3_backends`. A resource carrying any of those three field names has the
field pruned before any controller sees it, so the message cannot be produced
by the operator at all. It is accepted because the alternative arm of question
2 cost the grace-period refusal and every admission-time check with it; what
carries it is that the three messages are migration aids for a shape change
that has already shipped, and any future one has to be planned as a CRD
version decision under question 16 rather than as a loader message.

Raised 2026-09-14 by the owner, **announced only**. **Not scheduled, no work
started, nothing designed.** It is written down today because 5.0.0 is being cut
today: a configuration key the proxy does not define refuses the start
([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11),
so changing the *shape* of a key is a breaking change, and a breaking change
ships in a major ([ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md)
D5). Whatever this feature would need the configuration to look like is free
today and costs a 6.0.0 later.

~~This ticket carries no decisions. Everything that needs one is under
*Open questions* and is **undecided**.~~ **Struck 2026-09-16.** True when it was
written and false since the two refining rounds of 2026-09-16: the decisions are
under *Decided 2026-09-16*, what they cost is under *Accepted residual risks,
2026-09-16*, and questions 1, 2, 14 and 15 are closed. The rest of this
paragraph's block is the announcement as it stood on 2026-09-14 and is left
standing as the record of what was known then.

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

Verified in this repo on 2026-09-14, and corrected in place on 2026-09-16.

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
  (`internal/config/envexpand.go:55-101`). An unset or empty variable refuses the
  start, naming the field. So a rotated Secret reaches a running proxy through
  nothing at all — the variable is read once, into a value that never changes
  again.
- **A client-driven multipart session is process-local.** It is filed in an
  in-memory map on the manager (`internal/orchestration/segmented_session.go:189-195`)
  and no other replica can adopt it
  ([docs/developer/multipart.md](../developer/multipart.md), "Shutdown ends what it
  is still holding"); a part arriving at another pod is answered `404 NoSuchUpload`
  (`internal/proxy/handlers/multipart/upload.go:165`). No `sessionAffinity` is set
  anywhere under `deploy/`. Since ADR 0033 the chart refuses `replicaCount` above 1
  and refuses autoscaling outright (`templates/_helpers.tpl:232-239`), and the
  production profile installs one instance with no budget
  (`values-production.yaml:15,34-41`) — so *scaling instances is not the same thing
  as scaling replicas* is now enforced rather than assumed, and the operator still
  has to know which one a CR means.
- **The proxy has no API-server footprint.** The chart's ServiceAccount sets
  `automountServiceAccountToken: false` (`templates/serviceaccount.yaml:12`) and
  no Role or ClusterRole exists under `deploy/`. An operator introduces the first
  Kubernetes privilege this product has ever held.
- **The listener certificate is loaded once.** `ServeTLS(listener, cert, key)` at
  `internal/proxy/server.go:287`, and no `tls.Config` with a `GetCertificate`
  callback exists on the serving path (the only one in the tree is the backend
  transport's, `server.go:211`). *Not verified by experiment here*, but it follows
  that a cert-manager renewal is not served until the pod restarts — and the pod
  template hashes only what the chart itself renders
  (`templates/deployment.yaml:24-30`), which a cert-manager Secret is not. This is
  an argument **for** an operator, not against it.
- **A proxy now reports what it loaded, on a listener that is off by default.**
  Corrected 2026-09-16; what stood here was written before the probe round. The
  S3 listener registers `/livez` and `/readyz` and nothing else ahead of the
  middleware (`internal/proxy/router.go:73-75`), and the handler behind them has
  two methods: `Live`, a constant 200 checking no precondition, and `Ready`,
  which reports only the drain
  (`internal/proxy/handlers/health/handler.go:47-75`). Everything an operator
  would want to read is on the monitoring listener instead: `/status`
  (`internal/monitoring/server.go:50-56`) serves the build version, commit and
  build time; the active provider alias, its type and the KEK fingerprint; the
  backend's observed state with the time of its last response, its last
  transport failure and that failure's class; and, when a licence is held, its
  expiry, validity and the time remaining computed at read time
  (`internal/monitoring/status.go:14-42`, `:88-110`,
  `internal/monitoring/backend.go:29-43`). The same facts are scraped:
  `s3ep_encryption_provider_info` carries alias, type and fingerprint as labels
  (`internal/monitoring/status.go:58-68`) and backend reachability is five series
  ([docs/operations/monitoring.md](../operations/monitoring.md)). But
  `monitoring.enabled` defaults to `false` (`internal/config/config.go:415`), so
  a resource that wants status has to turn it on — and that listener is
  unauthenticated by decision (ADR 0030 D2), which is what makes open
  question 29 a security question rather than an API one.
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

**2. There is no file form for a secret value.** Corrected 2026-09-16:
`license_file` (`config.go:174`) is one of three keys that name a file —
`tls.cert_file` and `tls.key_file` are the others (`config.go:24-25`), and the
second of those is secret material, so a file route for a secret value already
has a precedent in this configuration. What has no file form is the KEK,
`s3_backends[].secret_key` and `s3_clients[].secret_key`, all three of which
reach the process only through its environment.
A `*_file` sibling is **additive, not breaking** — an old configuration keeps
working on a new binary. *5.0.0 could do*: nothing. The later cost is one
decision (precedence when both are written), not a shape change.

**3. `s3_clients[]` and `encryption.providers[]` are already lists with a
`type` discriminator** (`config.go:38-46`, `config.go:64-69`). New client types
and new provider types are additive, and a provider's `config` is a `,remain`
map. *5.0.0 could do*: nothing — the shape an operator would want is already
there.

**4. `tls:` is one struct and the process opens one listener**
(`config.go:22-26`, `server.go:266-300`): TLS or plaintext, never both, so an
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
(`templates/deployment.yaml:79-95`). Two are named after Helm. An operator either
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

## What 5.0.0 could have done — struck 2026-09-16, the release is cut

This section was a budget against a release being cut that day, and the premise
above it — that a configuration shape is free today and costs a 6.0.0 later —
closed when 5.0.0 shipped. 5.0.1, 5.0.2, 5.1.0 and 5.1.1 followed; the newest
release is 5.1.1, dated 2026-09-17 (`CHANGELOG.md:1`). What it said, and
what
became of each item: the `/version` item is void twice over, because the endpoint
it recorded as done was deleted the next day (ADR 0034) and the release that made
it cheap is cut; **the four Helm-named environment variables were not settled** —
`HELM_RELEASE_NAME` and `HELM_CHART_VERSION` are still read
(`internal/monitoring/metrics.go:15-16`) and still set by the chart
(`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:79-95`), so what was
free then is now a major's cost and is open question 5's remainder; "everything
else, nothing worth doing" was a judgement about a release that has happened; and
the one live item, giving the backend credential an external-Secret path, is
second-pass finding A and stays there. The heading is not renamed to the next
major, because nothing has decided what the next major is.

## Second pass, 2026-09-14: what else an operator inherits

Verified against the branch the same day, after ADR 0033 and the `s3_backends`
list had landed. Nothing here is decided either — it is what the next reader needs
in front of them before the first design session.

**A. The backend credential has no external-Secret path, and it is the first
thing an operator needs.** `secrets.encryption.existingSecret` and
`license.existingSecret` both exist; `secrets.s3` has neither
(`values.yaml:283-308`, `templates/secret.yaml:9-14`), so the backend access key
and secret reach the pod only through a Secret the chart renders from a plaintext
values field. A CR may not carry that value
([ADR 0021](../adr/0021-key-material-is-generated-never-committed.md)), so today
an operator would have to create the Secret itself and inject the pair through
`env`, going around `secrets.s3` entirely. Closing it in the chart is additive and
breaks nothing; whether the chart or the operator closes it is open.

**B. Three environment-variable names are an unwritten contract between the chart
and the configuration blob.** The pod is given `S3_ACCESS_KEY_ID`, `S3_SECRET_KEY`
and `S3EP_AES_KEY` (`templates/deployment.yaml:96-118`), and the shipped `config`
references exactly those three by name (`values.yaml:252-277`). Nothing checks the
pairing: a configuration naming a fourth variable renders, installs, and fails at
pod start with `environment variable ${...} is not set or empty`. An operator that
renders the configuration either adopts these three names as part of its own API
or validates the pairing at admission — which is open question 2 arriving through
the back door.

**C. The shipped default gives one key pair two roles, in every profile including
production.** `s3_backends[0]` and `s3_clients[0]` both read `${S3_ACCESS_KEY_ID}`
/ `${S3_SECRET_KEY}` in `values.yaml:252-261`, `values-production.yaml:122-132`,
`values-development.yaml:50-65` and `values-monitoring.yaml:94-104`. The chart
README carries it as *Security Considerations* item 3
(`deploy/helm/s3-encryption-proxy/README.md:711-717`) with the right consequence
— a client
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
`monitoring.enabled` is true (`internal/monitoring/metrics.go:228-240`). An
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

**F. Readiness says nothing about whether the instance can do its job — and
since 2026-09-15 that is a decision rather than an omission.** Corrected
2026-09-16. `Ready` reports the drain and nothing else
(`internal/proxy/handlers/health/handler.go:47-75`): no backend reachability, no
provider, no KEK, no bucket. ADR 0034 D3 and D5 decide that a probe reports the
process and never its dependencies, and D6 puts dependency health in a fourth
category — reported, never acted on by an automatic actor. So a CR status that
mirrors the Deployment's readiness reports "the listener answered", which is not
what anyone reads a status for, and a CR status that reaches past it into
`/status` is exactly the automatic actor D6 names. The verdict that would make
readiness mean something is [040](040-managed-buckets.md)'s startup readability
check; the two tickets are independent and meet here.

**G. The unauthenticated-exposure question was answered for the S3 surface and
moved to the monitoring listener.** Corrected 2026-09-16; the endpoints this
finding named are deleted, and the exposure it raised was resolved on exactly the
grounds it raised. The S3 listener now serves only `/livez` and `/readyz` ahead
of the authentication middleware (`internal/proxy/router.go:73-75`, `:169`), and
ADR 0034 D8 moved build information and everything naming the active provider off
that surface, because an `exit` provider means the backend holds plaintext
(ADR 0025) and that must not be readable without authentication from the data
path. The question therefore now bites on `/status`, which carries the provider
alias, the provider type and the KEK fingerprint
(`internal/monitoring/status.go:29-34`) on a listener ADR 0030 D2 leaves
unauthenticated by design and whose boundary D1 hands to the administrator.
Whatever a CR status names is drawn from that document, and a CR status has a
larger and less deliberate audience than a port an administrator chose to expose
— see open question 29.

**H. No configuration scopes an instance to a bucket.** `ListBuckets` is forwarded
as it stands (`internal/proxy/handlers/root/handler.go:66-101`) and no key
restricts what a client may reach. So "a proxy per team" is a credential boundary
onto the whole backend account, not a tenancy boundary: what separates tenants is
the backend's own IAM, and the operator would be provisioning a boundary this
product does not enforce. [040](040-managed-buckets.md) opens the nearest thing to
it.

**I. One instance is one Deployment, one Service, one ConfigMap, one Secret — and
TLS doubles it.** ADR 0033 fixes a chart install at one process, and `tls:` is one
struct with one listener (`internal/config/config.go:140`,
`internal/proxy/server.go:266-300`), so an instance asked to serve both plaintext
and TLS is two of everything, as the demo stack already is. Whatever "instance"
turns out to mean in the CR, the object count behind one is known today.

**J. The listener certificate is loaded once — now read in the code rather than
inferred.** `ServeTLS(listener, certFile, keyFile)` at
`internal/proxy/server.go:287`, and the serving path builds no `tls.Config` with a
`GetCertificate` callback anywhere. A renewed cert-manager Secret is therefore not
served until the pod restarts, and the pod template hashes only what the chart
renders (`templates/deployment.yaml:24-30`), which that Secret is not. Still not
verified *by experiment*; the code leaves no other reading.

## Third pass, 2026-09-16: what the valkey-operator decided, and what this inherits

Read on 2026-09-16 against
`/Users/hans.fischer/github/guided-traffic/valkey-operator`, **a different
repository**, whose paths are prefixed `valkey-operator/` throughout and are
evidence about that product and never about this one. Paths with no prefix are
this repository. The pass also carries what this product itself contributes to
the same questions, because several of the constraints an operator meets are
here rather than there. Nothing below is decided.

**K. The read-only Secret verb set is the right discipline and the wrong verb
list, because s3eo has to write.** In the other repository the operator's
marker is `get;list;watch;delete` on `secrets`
(valkey-operator/`internal/controller/valkey_controller.go:171`) while the
shipped ClusterRole grants only `get`, `list`, `watch`
(valkey-operator/`deploy/helm/valkey-operator/templates/clusterrole.yaml:60-67`);
neither carries `create` or `update`. Credentials reach the workload by
reference rather than by copy — `SecretKeyRef` selectors at
valkey-operator/`internal/builder/statefulset.go:326`, `:476`, `:665`, with
two more at `:737` and `:849` — which is structurally guaranteed by the
missing verbs rather than by discipline. The security effect is precise and
limited: the ServiceAccount cannot forge or overwrite a credential, so a
compromise exfiltrates rather than injects; it does nothing against reading
every Secret in the cluster. s3eo cannot copy the verb list, because the
decision of 2026-09-16 has it writing the proxy's own client credential. What
it can copy is the shape underneath: the backend credential is referenced and
never copied, the two needs are two rules rather than one, and a referenced
Secret's value never travels through the operator's own memory if the kubelet
can resolve it instead.

**L. `escalate` and `bind` on `roles`, cluster-wide, are the compromise
multiplier, and they entered once and were never revisited.** The marker is
valkey-operator/`internal/controller/valkey_controller.go:175` and the shipped
grant is
valkey-operator/`deploy/helm/valkey-operator/templates/clusterrole.yaml:128-154`,
in a ClusterRole, so cluster-wide. Nothing needs them: the only Role that
repository builds is `pods` `get`/`list`/`patch`
(valkey-operator/`internal/builder/rbac.go:39-45`), a strict subset of the
operator's own pods grant, which is exactly the case where neither verb is
required. What a compromised ServiceAccount does with them is write a Role
carrying `verbs: ["*"]` on `resources: ["*"]` in any namespace and bind it to
itself — which grants back precisely the `secrets create` and `update` that
finding K's verb list withheld, so every reduction in the Secret rule is
undone by the presence of these two. They entered in one commit,
valkey-operator `ce97f1b` ("feat: reliable valkey service (#9)"), which added
`escalate;bind` to both the marker and the chart in the same change, and no
later commit touches them. For this product the starting position is the
opposite one: the chart ships no Role, RoleBinding, ClusterRole or
ClusterRoleBinding at all — verified by listing
`deploy/helm/s3-encryption-proxy/templates/`, fifteen files, none of them RBAC
— and the proxy's ServiceAccount sets `automountServiceAccountToken: false`
(`deploy/helm/s3-encryption-proxy/templates/serviceaccount.yaml:12`).

**M. Nothing in either tree stops a Deployment the operator writes from
landing a privileged pod on a node, and refusing `escalate` does not close
it.** s3eo needs `create` and `update` on `deployments` in `apps` across every
namespace, because the resource is namespaced and one cluster-scoped operator
serves the cluster; the in-house precedent grants exactly that, cluster-wide
and with no `resourceNames`
(valkey-operator/`deploy/helm/valkey-operator/templates/clusterrole.yaml:68-80`).
Whoever authors the PodSpec chooses `hostPath`, `hostPID`, `hostNetwork` and
`privileged`, and the Deployment controller then creates the pod under its own
identity, so the operator's RBAC is never re-checked against what the PodSpec
asks for and a container mounting the host filesystem reaches the kubelet's
credentials. That is a takeover primitive independent of finding L: shortening
the path by refusing `escalate` does not close this one. Verified in both
trees: the string `pod-security.kubernetes.io` occurs zero times in this
repository and zero times in valkey-operator, so no namespace either
repository creates carries an enforce label, and neither contains any
admission configuration at all — `test/e2e/velero/kind-config.yaml` has no
admission block, and the namespaces are created bare on every path that
creates one (`test/e2e/velero/e2e-up.sh:163` for the proxy, `:118` for MinIO,
`:214` for Velero, `deploy/helm/install.sh:68` for a real install). This chart
does ship a hardened pod and container security context — `runAsNonRoot`,
`seccompProfile: RuntimeDefault`, all capabilities dropped, read-only root
filesystem (`deploy/helm/s3-encryption-proxy/values.yaml:33-47`, rendered at
`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:45`) — but that is
a workload declaring its own restraint, not a namespace refusing one that
declines to, and valkey-operator sets no security context whatsoever on the
workloads it builds (a grep for `SecurityContext` across
valkey-operator/`internal/` and `api/` returns nothing). There are two
distinct attackers here and they are not closed by the same thing: a
compromised operator authoring its own PodSpec, and a resource author steering
the PodSpec through the resource — which the valkey precedent already permits
by making the container image a required tenant-supplied field
(valkey-operator/`api/v1/valkey_types.go:432`) and passing `podLabels` and
`podAnnotations` through (`:70-75`). Question 18.

**N. The ConfigMap write verb reaches the one leg `SECURITY_ARCHITECTURE.md`
exists to defend.** s3eo has to write the rendered proxy configuration as a
ConfigMap — that is what the chart does today
(`deploy/helm/s3-encryption-proxy/templates/configmap.yaml:1-9`, hashed into
the pod template at `templates/deployment.yaml:25`) — and cluster-wide that
verb is not confined to objects the operator created: the precedent grants
`create`, `update`, `patch` and `delete` on `configmaps` with no
`resourceNames`
(valkey-operator/`deploy/helm/valkey-operator/templates/clusterrole.yaml:36-49`),
which reaches the `coredns` ConfigMap in `kube-system` and every namespace's
`kube-root-ca.crt`. Rewriting the Corefile redirects the hostname the proxy
resolves for `s3_backends[0].target_endpoint`, which puts an attacker on the
proxy-to-backend leg — the leg `SECURITY_ARCHITECTURE.md:96-134` draws as the
boundary that matters and `:30-47` declares outright hostile. What the proxy
has against that is certificate verification and nothing else:
`target_endpoint` and `insecure_skip_verify` are the only backend values
reaching the SDK options, and with the latter true the transport is built with
`InsecureSkipVerify` set (`internal/proxy/server.go:202`, `:241`), which
`SECURITY_ARCHITECTURE.md:936-939` already names as removing the only defence
against an additional attacker on that leg. Verified in the loader: a scheme
that is neither `https` nor `http` refuses the start
(`internal/config/config.go:540-557`), and plain `http://` refuses the start
under every provider that resolves, the exit provider included
(`internal/config/config.go:560-591`; ADR 0013 D4 and D5). So a DNS redirect
against a correctly configured proxy dies at the handshake, and against one
carrying `insecure_skip_verify: true` — which the demo configurations set — it
succeeds and the redirected endpoint receives the backend credential in a
SigV4 header, the one secret `SECURITY_ARCHITECTURE.md:284` records as
deliberately sent onto that leg. *Not verified by experiment here, but* the
timing differs by target: the proxy reads its configuration once at startup
and has no watcher — no `fsnotify` and no `WatchConfig` anywhere in
`internal/config/` or `cmd/` — so rewriting the proxy's own ConfigMap needs a
restart the operator can cause, whereas CoreDNS reloads its ConfigMap without
anyone's help. Question 17.

**O. A Secret reference is two bare strings, no reference type carries a
namespace, and every read hard-codes the resource's own.** In the other
repository `AuthSpec` is `secretName` plus `secretPasswordKey` and nothing
else (valkey-operator/`api/v1/valkey_types.go:93-103`); the TLS reference is
one string with the same shape (`:142-146`); both Secret reads in the
controller pass `Namespace: v.Namespace`
(valkey-operator/`internal/controller/valkey_controller.go:141-146` and
`:1003`); and the Secret watch mapper lists only within the Secret's own
namespace (valkey-operator/`internal/controller/valkey_controller.go:1714`)
and re-checks the name at `:1722`. In the generated schema no reference
carries a `namespace` property; the single occurrence of the word is
`scope: Namespaced`
(valkey-operator/`config/crd/bases/vko.gtrfc.com_valkeys.yaml:17`). That is
the operator confused deputy foreclosed structurally rather than by a rule:
the author cannot express the attack, so no admission rule has to reject it
and no webhook has to be available for the rule to hold — which matters
because that repository has no webhook at all. The one thing it demonstrates
and does not solve is placement: the invariant is spread across two packages,
so the rule holds by three separate lines agreeing rather than by one helper
being the only way to read a Secret.

**P. No ownerReference and no finalizer on any Secret, and a delete that is
always preceded by a get.** In the other repository no `AddFinalizer` or
`RemoveFinalizer` exists anywhere under `internal/`, `api/` or `cmd/`, and
`Reconcile` bails out on a deletion timestamp rather than running a teardown
(valkey-operator/`internal/controller/valkey_controller.go:195-198`);
cert-manager's Secret is consequently left orphaned when an instance is
deleted, which the code itself states at `:999-1001`. Deleting a resource
therefore cannot destroy a user's credential, at the price of one orphaned
private key per deleted instance. Beside it sits the best code in that
repository, and it is two rules rather than one: the legacy-certificate
cleanup gets before it deletes and deletes nothing until every consumer has
moved off it
(valkey-operator/`internal/controller/valkey_controller.go:948-1013`, gated by
`sentinelRolloutComplete` at `:1021-1073`), and the reason is written out at
`:979-983` — the apiserver evaluates authorisation before existence, so a
speculative delete on a cluster without the `delete` verb answers 403 rather
than 404 and loops the reconciler. For a Deployment the rollout gate is
simpler than a StatefulSet's revision comparison — `observedGeneration`, then
`updatedReplicas == replicas == availableReplicas` — but the ordering rule is
identical, and every optional cleanup s3eo writes meets the second. What
valkey only demonstrates half of is the asymmetry the 2026-09-16 credential
decision creates: there is now a Secret the operator generates and a Secret it
merely references, and they are not the same object for the purposes of
ownership. Existing open question 7 owns the answer.

**Q. Validation is the OpenAPI schema and nothing else, and the empty middle
is where an invalid resource costs the most.** In the other repository there
is no webhook package and no `SetupWebhookWithManager` anywhere; validation is
four enums, six numeric bounds, one `MinLength` and about thirty
`kubebuilder:default` markers, with zero `XValidation` markers in `api/` and
zero `x-kubernetes-validations` in the generated CRD. The cost is visible in
one field pair: `tls.certManager` and `tls.secretName` are documented mutually
exclusive (valkey-operator/`api/v1/valkey_types.go:138`, `:144`) and enforced
nowhere, and setting both makes both predicates true (`:562-564`, `:576-578`)
so the Certificate is built with the user's own Secret as its target
(valkey-operator/`internal/builder/certificate.go:48-52` feeding `:204`) and
cert-manager overwrites the user's key material. So an enum violation is
refused at `kubectl apply` and everything else is accepted and fails later, as
a pod that cannot start, with a status naming a symptom. The middle that
repository leaves empty is available here without a webhook and without a
serving certificate: CEL through `x-kubernetes-validations`, and this chart
already declares `kubeVersion: ">=1.34.0-0"`
(`deploy/helm/s3-encryption-proxy/Chart.yaml:10`). What the mechanism *cannot*
express is worth stating in the same breath, because it decides which refusals
can move to admission at all: CEL cannot ask whether a named Secret exists or
whether it carries a named key, so that class stays a reconcile-time
condition. Which of the three mechanisms — schema, CEL, reconcile condition —
carries which refusal is not decided here.

**R. cert-manager consumed as `unstructured`, `issuerRef` as three fields,
extra SANs unfiltered, and webhook-defaulted fields cleansed before diffing.**
In the other repository the Certificate is built as an
`unstructured.Unstructured` with the group-version-kind as plain string
constants (valkey-operator/`internal/builder/certificate.go:5-13` for the
imports, `:28-32` for the constants, `:194-213` for their use), and there is
no cert-manager module in that `go.mod` — so no third-party code sits in a
binary holding cluster-wide Secret access, and an absent CRD is a per-resource
runtime error rather than a startup failure. That shape matters for this
product beyond tidiness: ADR 0026 D4 keeps cert-manager optional, and a typed
import would promote it to a build dependency of the operator. `issuerRef` is
`kind` plus `name` plus an optional `group` with no namespace
(valkey-operator/`api/v1/valkey_types.go:106-118`, emitted only when non-empty
at `internal/builder/certificate.go:179-185`), and `kind` is enum-constrained
to `Issuer` or `ClusterIssuer` at `:113-114` — so a namespaced `Issuer`
resolves in the Certificate's own namespace and cannot cross one, and the
`ClusterIssuer` arm is the deliberate exception. Beside it, `extraDnsNames` is
appended with no suffix check and no allowlist, deduplicated and nothing else
(valkey-operator/`internal/builder/certificate.go:82-84`, `:86`), which makes
a `ClusterIssuer` plus author-supplied subject alternative names a
name-constraint bypass against whatever CA that issuer fronts. This chart's
templates emit `name` and `kind` only
(`deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml:19-21`),
so `group` would be an addition. The last part is a mechanism worth having and
worth reading before copying: webhook-defaulted fields are removed from both
sides before diffing so the Certificate is not rewritten every pass
(valkey-operator/`internal/controller/valkey_controller.go:1124-1130`,
`:1145-1156`), and the comment at `:1154` says the `privateKey` delete is
conditional while `:1155` deletes unconditionally — the code contradicts its
own comment, so a `privateKey` the operator deliberately set is discarded too.
Question 31.

**S. The only network-policy shape in reach has no field for "who may talk to
this", and a proxy is nothing but clients.** In the other repository the
generated policy selects the instance's own pods
(valkey-operator/`internal/builder/networkpolicy.go:152-157`) and admits the
data port from an enumerated peer set — other instance pods, Sentinel pods
when Sentinel is on, observer pods when the observer is on, and every pod in
the operator's own namespace matched by `kubernetes.io/metadata.name`
(`:51-88`) — with the TLS port taking the identical set at `:103-114`, and two
rules carrying no `From` at all: the sidecar health port (`:119-127`) and the
metrics port (`:133-143`), which is allow-from-anywhere on those ports. All
three policies are ingress-only (`:156`, `:246`, `:286`). The resource
expresses it in two fields, `enabled` and `namePrefix`
(valkey-operator/`api/v1/valkey_types.go:254-263`), and no peer field is
needed because a Valkey cluster's client set is the operator's own
construction. A proxy's client set is whatever workload the administrator
points at it, and nothing derivable from an s3eo resource names it — so that
generator, transplanted, produces a policy that denies every client the
instance exists to serve. Whether an operator is even the same actor as a
chart is genuinely open and worth stating precisely rather than settling: the
chart's argument is knowledge, that it cannot know which namespaces may reach
the proxy (`SECURITY_ARCHITECTURE.md:726-730`), and a resource is written by
the same administrator who writes a values file, so the knowledge is identical
at install time; what differs, and is verified, is that an operator holds a
reconcile loop and RBAC on `networkpolicies`
(valkey-operator/`config/rbac/role.yaml:84-95`), so it can keep a policy true
as a deployment changes. Then there is the separate proof problem:
`test/e2e/velero/kind-config.yaml:1-21` declares only nodes and port mappings
and no `networking` block, so the cluster runs kind's default CNI, and in the
other repository nothing under `test/` mentions NetworkPolicy and no kind
config disables the default CNI, so the control there is constructed in a
builder unit test and enforced nowhere. *Not verified by experiment here, but*
kindnet implements no NetworkPolicy enforcement, so a policy object would
apply, be stored, and be enforced by nothing — a green suite would prove that
the YAML parses. Question 32.

**T. The manager is built with four options and no cache configuration, and
leader election is a flag defaulting off that the chart turns on for one
replica.** In the other repository `ctrl.NewManager` is given `Scheme`,
`HealthProbeBindAddress`, `LeaderElection` and `LeaderElectionID` and nothing
else (valkey-operator/`cmd/main.go:87-92`), with no `Cache`, no `ByObject` and
no `DefaultNamespaces`, and `SetupWithManager` watches `corev1.Secret` with no
predicate and no label selector
(valkey-operator/`internal/controller/valkey_controller.go:1695-1698`) — so
every Secret in the cluster is decoded into the operator's heap, and a heap
dump is a cluster-wide credential disclosure. This product already applies the
opposite reasoning to itself and says why: `validateMonitoring` refuses a
non-loopback `monitoring.pprof_bind_address` at startup
(`internal/config/config.go:634-641`) because a heap profile contains DEKs and
plaintext buffers (`internal/monitoring/pprof.go:13-20`,
`internal/monitoring/server.go:58-61`), and the argument is stronger for a
process that reads S3 credentials. The distinction that has to travel with any
narrowing is that a cache narrowing is not a privilege narrowing: RBAC
PolicyRules carry no label selector, so a label-scoped informer reduces what
is decoded and not what the token can read. Leader election is the second half
of the same options struct: the binary defaults `--leader-elect` to false
(valkey-operator/`cmd/main.go:67-69`), the chart inverts it to true
(valkey-operator/`deploy/helm/valkey-operator/values.yaml:40-41`, rendered at
`templates/deployment.yaml:43-45`) against `replicaCount: 1`
(`values.yaml:3`), and `LeaderElectionNamespace` is unset so
controller-runtime reads the pod's own namespace and the lease lands wherever
the operator is installed — while the ClusterRole grants the full lease verb
set cluster-scoped
(valkey-operator/`deploy/helm/valkey-operator/templates/clusterrole.yaml:155-167`)
with no matching marker anywhere in the marker block at
`internal/controller/valkey_controller.go:161-176`. A cluster-scoped `leases`
grant lets a compromised ServiceAccount break leader election for
`kube-controller-manager` and every other operator in the cluster: denial of
service, not escalation. The cost of getting leader election wrong is not
symmetric between the two products. That operator only reads Secrets, so two
racing controllers duplicate reads; s3eo mints the proxy's own client
credential and writes it back, and two controllers without a lease each
generate a different random pair, each write it, and the last writer's Secret
is the one mounted while the other's may already be inside a rendered
configuration or a rolled pod. Questions 21 and 34.

**U. The operator's own metrics listener is parsed, never wired, and serves
unauthenticated on the library default — and a flag that does nothing is its
own defect class.** In the other repository `metricsAddr` is declared at
valkey-operator/`cmd/main.go:60` and bound to `--metrics-bind-address` with a
default of `:8080` at `:65`, and the manager options at `:87-92` carry no
`Metrics` field — the variable is never read after the flag parse, and the
compiler does not object because `flag.StringVar` takes its address. What the
process serves comes from controller-runtime instead: an empty `BindAddress`
defaults to `":8080"`, over plain HTTP, with secure serving off and no filter
provider, so the endpoint is unauthenticated whatever the operator writes and
the one documented value that would switch it off, `"0"`, is discarded with
everything else. The chart passes `--metrics-bind-address=:8080`
(valkey-operator/`deploy/helm/valkey-operator/templates/deployment.yaml:40`)
and opens `containerPort: 8080` (`:59-62`) while shipping no Service, no
ServiceMonitor and no NetworkPolicy — so the port is open on the pod IP to
anything in the cluster and scraped by nothing. The defect worth naming is not
the exposure but the flag: an administrator who sets it believes the listener
was moved, narrowed or turned off, and nothing in a rendered manifest, a log
line or a `helm diff` contradicts them. The gap for s3eo is specific and is
not the proxies it provisions — the chart already ships `servicemonitor.yaml`,
`prometheusrule.yaml`, `grafana-dashboard.yaml` and `service-monitoring.yaml`
— but the reconcile, workqueue and Go-runtime metrics of the operator binary
itself, which controller-runtime registers whether or not anybody decided to
expose them. Question 33.

**V. The CRD group, one served version, a templated CRD, and the brake that is
missing.** In the other repository the group is `vko.gtrfc.com` and the
version `v1`, declared once at valkey-operator/`api/v1/groupversion_info.go:3`
and `:14`; the CRD carries exactly one version entry with `served: true` and
`storage: true`
(valkey-operator/`deploy/helm/valkey-operator/templates/crd.yaml:721-722`) and
no `conversion:` key anywhere in its 724 lines, so the apiserver applies the
`None` strategy and no webhook is needed — which is true only while one
version exists. The CRD ships as a chart *template*, not under `crds/`:
`make sync-helm-crd` concatenates `config/crd/bases/*.yaml` into
`templates/crd.yaml` behind a "do not edit" banner
(valkey-operator/`Makefile:218-231`, `:337-339`) and `generate-all` chains
`manifests generate sync-helm-crd` at `:244`, so an `api/v1/` change cannot
land without it. The placement is the right decision and the reason is
mechanical: Helm never upgrades or deletes a file in `crds/`, so a chart that
puts a CRD there can ship a schema change only by telling an administrator to
`kubectl apply` it by hand, and the apiserver prunes the new fields silently
in the meantime. The cost that repository pays for the right placement and did
not mitigate is that a templated CRD is a release resource like any other, and
no `helm.sh/resource-policy: keep` annotation appears anywhere in `deploy/` —
so one `helm uninstall` removes the CRD, cascades to every custom resource,
and follows every `ownerReference` down. For this product that cascade removes
the only path that reads what those instances wrote. Question 25.

**W. The upgrade path is a Helm pre-upgrade hook running a subcommand, and
this image has none.** In the other repository the hook is
valkey-operator/`deploy/helm/valkey-operator/templates/pre-upgrade-job.yaml:11-13`
at weight `-5` with `hook-delete-policy: hook-succeeded,before-hook-creation`,
running `command: ["./manager", "migrate"]` at `:39`, with its own short-lived
ServiceAccount, ClusterRole and ClusterRoleBinding at weight `-10` under the
identical delete policy in `templates/pre-upgrade-rbac.yaml`, so the RBAC
exists before the Job and disappears with it. The cheap improvement it did not
take is larger than `resourceNames`: the hook's ClusterRole grants `get`,
`list`, `patch` and `update` on `customresourcedefinitions` cluster-wide
(valkey-operator/`deploy/helm/valkey-operator/templates/pre-upgrade-rbac.yaml:41-49`)
while valkey-operator/`cmd/migrate/migrate.go` registers only `clientgoscheme`
and its own API in the scheme (`:34-36`) and its single write is a `Patch` on
a custom resource at `:74` — it never touches a CRD, so the whole
apiextensions rule is unused, and even the used rule carries no
`resourceNames`. For this repository the implication is concrete:
`cmd/s3-encryption-proxy/main.go:30` defines one cobra root command with
`Run: runProxy` and an `init()` at `:55-58` adding only a persistent
`--config` flag, with no `AddCommand` anywhere, so the image has zero
subcommands, while `Containerfile:94-95` sets the entry point to the proxy
binary. *Not verified by experiment here, but* a cobra root command with no
subcommands takes arbitrary arguments, so `./s3-encryption-proxy migrate`
would start the proxy and ignore the word rather than fail — a hook of that
shape would appear to succeed while doing nothing. The image already carries a
second binary, `s3ep-keygen` (`Containerfile:80`), so "one binary per image"
is not the constraint. Question 26.

**X. The chart performs thirteen render refusals, and one of them is
arithmetic a Custom Resource is most likely to lose.** Read across every
template:
`deploy/helm/s3-encryption-proxy/templates/poddisruptionbudget.yaml:3` refuses
`minAvailable` and `maxUnavailable` set together and `:6` refuses neither set;
in `templates/_helpers.tpl`, `:108` refuses a `preStopSleepSeconds` below one
because the hold has no off switch (ADR 0034 D10); `:141` refuses a
`terminationGracePeriodSeconds` below `preStopSleepSeconds` plus
`shutdown_timeout` plus five; `:158` refuses a `values.config` that is not
parseable YAML, once rather than twice because two templates read it; `:234`
refuses `replicaCount` above one and `:237` refuses `autoscaling.enabled` (ADR
0033 D1, D2, D3); `:244` refuses `serviceTLS.enabled` with neither
`existingSecret` nor `issuer.name` (ADR 0026 D5); `:248` refuses a `tls:`
block inside `values.config` beside `serviceTLS.enabled` and `:254` refuses a
`monitoring:` block the same way (ADR 0026 D3); `:259` refuses an enabled
Ingress with an empty `ingress.tls` and `:269` refuses an Ingress host no TLS
entry covers (ADR 0026 D9); and `:282` refuses a cert-manager Certificate
nothing consumes (ADR 0026 D7, D10). A fourteenth refusal is not a `fail` and
a resource has no equivalent for it: `Chart.yaml:10` carries
`kubeVersion: ">=1.34.0-0"`, and the comment beside it says the `-0` is
load-bearing — the native `preStop` sleep action is stable only from 1.34 and
the runtime image is distroless with no shell and no `sleep` binary, so on an
older cluster the hook silently is not one. Eleven of the thirteen are covered
by helm-unittest cases in
`deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml`; the
`monitoring:` drift refusal and both PodDisruptionBudget refusals are not,
because `tests/` holds only `deployment_test.yaml` and
`prometheusrule_test.yaml`. The grace-period item is the one refusal that is a
derivation rather than a validation and the one most likely to be lost:
`_helpers.tpl:131-132` reads `shutdown_timeout` out of the rendered
configuration rather than duplicating it into a second values key, precisely
so the two numbers cannot drift, and `:135` computes the sum. A schema
exposing a shutdown budget and a termination grace period as two independent
fields rebuilds exactly the failure the chart refuses — the pod is killed
inside its own drain, the sweep of ADR 0029 D1 step 4 never runs, and every
multipart upload the process was holding is left open at the backend (ADR 0029
D2, D3), which is unreachable storage nothing but an
`AbortIncompleteMultipartUpload` lifecycle rule will ever collect (ADR 0029
D6). Structural OpenAPI validation cannot express a cross-field inequality, so
where that refusal lands is question 28's neighbour and is not decided here.

**Y. Zero is legal in two of this product's keys and refused in six, and only
a pointer keeps them apart.** The split is not the one the configuration table
implies. Zero is legal and meaningful for exactly two listener budgets:
`validateListenerBudgets` refuses only a negative `read_timeout` and
`write_timeout` (`internal/config/config.go:604-610`), `setDefaults` ships
both at zero (`:403-404`), and the comment at `:143-152` says why — zero is
Go's "no deadline", which is what makes a transfer bounded by the client
rather than by a server wall clock (ADR 0015 D4). Zero is refused for six:
`read_header_timeout` and `idle_timeout` at
`internal/config/config.go:615-621`, and `multipart_session_idle_timeout`,
`multipart_session_cleanup_interval` and `max_request_document_size` at
`:292-299`, `:304-311` and `:316-322` — which are not in
`validateOptimizations` at all. That third group is the whole argument for
pointers stated in Go: `validateOptimizations` guards each of them with a
truthiness test (`:1054`, `:1069`, and no check on the idle timeout
whatsoever), so a written zero sails past the decoded struct, and the refusal
had to be lifted out of the struct and asked of the parsed document with
`viper.InConfig` — because after `setDefaults` an absent key and a written
zero are the same `int`. `shutdown_timeout` is a third class again: `:624`
refuses only a negative value and ADR 0015 D4 uses 30 when it is unset *or*
zero, so a written zero is accepted and silently reinterpreted. The
consequence for a schema is that the distinction viper needed a second pass
over the source file to recover is free in a pointer — and the trap is that a
`Minimum` paired with a `kubebuilder:default` writes the default into every
stored resource, so a later change to the default reaches none of them and the
two populations diverge invisibly. Question 28.

**Z. The Renovate carry is one rule, and the warning is one manager not to
bring with it.** In the other repository `renovate.json` carries a
`packageRules` entry grouping manager `gomod` package names matching
`^k8s.io/` and `^sigs.k8s.io/` under `groupName: "Kubernetes Go modules"`,
with no automerge key of its own so it falls through to that file's rule
automerging `gomod` minor and patch updates. That is one line of intent worth
carrying: `client-go`, `apimachinery`, `api` and controller-runtime move
together or they do not compile, and four separate pull requests against a
module graph pinned to one Kubernetes minor is a day spent closing them. This
repository has no such rule and does not yet need one — `go.mod` requires
nothing under `k8s.io/` or `sigs.k8s.io/` — and its closest analogue is the
`golang.org/x packages` group. The warning is that the same file also carries
a custom manager matching `GO_VERSION:` in `.github/workflows/*.yml` and
another for a release-template badge, and neither belongs here: the Go version
is spelled out in exactly two files, every `setup-go` step uses
`go-version-file: go.mod`, and the README badge is the shields.io
`go-mod/go-version` endpoint, so importing those managers would add a manager
for a literal this repository deliberately does not have and invite someone to
create one — a third source of truth against the Makefile's `GO_VERSION`,
which is parsed from the Containerfile precisely because a toolchain mismatch
corrupts the combined coverage merge silently. The narrower half: that
repository's go.mod manager uses the depName `golang` where this one uses
`go`, so importing it would register the same literal twice under two names
and split the existing "Go version" group.

**AA. Status is a subresource, printcolumns are cheap, the phase string is
prose and the Conditions are the contract — and this product's `/status`
already holds the two fields that make the choice sharp.** In the other
repository the status subresource is declared at
valkey-operator/`api/v1/valkey_types.go:511` and
`config/crd/bases/vko.gtrfc.com_valkeys.yaml:721-722`, with seven printcolumns
at `valkey_types.go:513-519` — five at default priority and two at
`priority=1`, so the wide view carries the fields a support question needs and
the narrow view stays short. `ValkeyStatus` (`:480-509`) is observation only,
seven fields, none secret-derived, with `conditions []metav1.Condition` and
`ObservedGeneration` set on every one of nine call sites. The
phase-versus-Conditions split is visible in the code rather than in a doc
sentence: there are six phase constants (`:40-56`) but the controller
interpolates progress into them
(valkey-operator/`internal/controller/rolling_update.go:373` and `:1110`), the
CRD gives `phase` no enum (`vko.gtrfc.com_valkeys.yaml:709-712`), and the
README documents the value as a sentence — so the phase is prose for a human
reading `kubectl get` and anything machine-readable lives in `conditions`,
whose declared types each carry a reason, a status and an observed generation
a caller can branch on. What this product contributes is the raw material and
two bounds on it: `/status` serves the build, the provider alias and type, the
KEK fingerprint, the backend's observed state and the licence remaining
(`internal/monitoring/status.go:14-42`, `:88-110`,
`internal/monitoring/backend.go:29-43`); ADR 0034 D6 says dependency health is
reported and never acted on by an automatic actor, and an operator folding
`/status` into a resource's status is precisely such an actor; and ADR 0030 D4
already stripped a licensee-identifying label and a countdown from the open
scrape, which is the reasoning a KEK fingerprint in a cluster-readable object
has to answer. Question 29.

**AB. A TLS Secret is projected key by key when the consumer only verifies.**
In the other repository the observer's volume mounts the instance's TLS Secret
whole when mutual TLS is on, and when it is not, projects `ca.crt` alone
through an explicit `KeyToPath` list, with the comment saying why — the
observer only needs the CA certificate for server verification, so do not
expose the private key unnecessarily
(valkey-operator/`internal/builder/observer.go:250-276`, the projection at
`:260-266`). It is small, it is the kind of thing that gets collapsed into one
volume during a later refactor, and it is exactly the shape s3eo meets when a
sidecar, an init container or a probe helper needs to verify a certificate it
must not be able to present.

**AC. Two hand-maintained ClusterRoles, drifted in both directions, and a
drift check that only looks at CRDs.** In the other repository the
kubebuilder-generated role grants `delete` on `secrets`
(valkey-operator/`config/rbac/role.yaml:38-46`) and carries no `leases` rule
at all, while the shipped chart ClusterRole grants only `get`, `list`, `watch`
on Secrets (`deploy/helm/valkey-operator/templates/clusterrole.yaml:60-67`)
and does grant `leases` (`:155-167`) — so the two documents an auditor might
read disagree in both directions, and only the chart is ever deployed. The
consequence is live: the one Secret delete in the controller
(valkey-operator/`internal/controller/valkey_controller.go:1004`) runs under a
role that lacks the verb, and a 403 is neither `NotFound` nor swallowed, so it
returns an error and the reconciler requeues. The drift check does not catch
it and cannot: `make generate-all` regenerates `config/rbac/role.yaml`, but
`sync-helm-crd` copies only `config/crd/bases/*.yaml` into the chart, so the
hand-written `clusterrole.yaml` is compared to nothing — and the one
verification step that exists
(valkey-operator/`.github/workflows/build.yml:159-171`) runs in a workflow
triggered on `release: types: [published]`, after the tag and the image
already exist. Here the drifting resource would carry Secret write verbs, and
an over-grant in that direction produces no error at all. Question 27.

**AD. Three mechanisms exist in that repository that this product must not
rebuild, and one of them is a fail-open credential read.** A credential is
interpolated into a container command line —
`exec valkey-server … --requirepass "$VALKEY_PASSWORD" --masterauth "$VALKEY_PASSWORD"`
(valkey-operator/`internal/builder/statefulset.go:613-625`) — which puts the
plaintext in the running process's argv twice over. A placeholder plus an
init-container `sed` into an `emptyDir`
(valkey-operator/`internal/builder/sentinel.go:170-177`, `:648-655`, with the
`emptyDir` at `:279` and `:285`) exists because Sentinel cannot read a
password from its environment; this proxy can, and `expandConfigEnvVars`
refuses an unset **or empty** variable naming the field
(`internal/config/envexpand.go:30-33`), so neither mechanism has a job here.
The third is the one worth reading twice:
valkey-operator/`internal/controller/valkey_controller.go:134-149` swallows
the error from a Secret read, returns an empty string, and the caller then
connects unauthenticated (`:128-131`), with the comment at `:135-136` saying
so — which makes "authentication not configured" and "configured but
unreadable" byte-identical. This product takes the opposite line everywhere
the loader touches a credential, and an operator that rendered an empty
credential and let the pod start would be softer than the product it
provisions.

**AE. An operator test suite is two test kinds this repository has never had,
on top of a bring-up that is already twenty-two steps.** What exists is one
kind-based environment with a fixed order: test PKI
(`test/e2e/velero/e2e-up.sh:30-31`), local key material (`:37-41`), the
licence (`:46-55`), the cluster (`:58-64`), a context pin and a kubeconfig
repoint for containerised runners (`:72`, `:77-83`), a proxy image built for
the node architecture and side-loaded with its image id carried into the pod
template (`:88-114`), MinIO over TLS with a bucket Job (`:117-130`), the
snapshot CRDs and controller (`:138-145`), five CSI RBAC manifests
(`:147-152`), the CSI hostpath driver (`:154-159`), the proxy namespace with
four Secrets and a Helm upgrade that recovers from a stuck release and from a
field-manager conflict (`:162-210`), then Velero with its credentials, a
generated kopia password, a rendered values file and a wait for the
BackupStorageLocation (`:213-276`); teardown is the whole cluster.
`make test-e2e-velero` allows Go sixty minutes (`Makefile:245-248`), the CI
job allows forty-five (`.github/workflows/test-pipeline.yml:800-803`), the two
client jobs thirty each, and all three are on `semantic-release`'s `needs:`
(`:1059`). The licence is where the bring-up aborts: `e2e-up.sh:46-54` exits
when neither `S3EP_LICENSE_TOKEN` nor `config/license.jwt` is present, and CI
injects the secret into that one step (`:853-854`), creating a single
`s3ep-license` Secret in one namespace at `:171-173`. An operator adds envtest
— a real apiserver and etcd pair downloaded by `setup-envtest`, which the
other repository does use, pinning `ENVTEST_K8S_VERSION = 1.29.0`
(valkey-operator/`Makefile:4-5`) and `setup-envtest` at `release-0.19`
(`:302-303`) and exporting `KUBEBUILDER_ASSETS` from every test target
including the `-short` one (`:69-103`), so a Kubernetes version is pinned
separately from any node image and its own `-short` run is not hermetic, and a
CRD is validated against a 1.29 apiserver while the product targets a 1.36.1
kind node (`test/e2e/velero/versions.env:21`, substituted into
`test/e2e/velero/kind-config.yaml:7`) and `k8s.io/*` at 0.36 — and a kind
suite that provisions real
instances, which needs everything the Velero bring-up already does plus the
operator image, the CRDs, cert-manager, and a licence token in every namespace
it provisions into. The shape is fixed by convention before any of it is
designed: one tool, one suite, one job, never bundled, named
`E2E <tool> (<backend>)`, and a job that is to gate the release needs a step
that is not in this repository — its name on the required-check list in branch
protection, merged after the workflow. Question 35.

**AF. The KEK has exactly one delivery route into a pod, and it is the process
environment.** Verified in the loader: `expandConfigEnvVars` expands `${VAR}`
in three groups and nowhere else — the four fields of every `s3_backends`
entry (`internal/config/envexpand.go:55-71`), the two of every `s3_clients`
entry (`:74-86`), and every string value under `encryption.providers[].config`
(`:89-101`), where a non-string value is skipped untouched (`:91-94`) and an
unset or empty variable refuses the start naming the field (`:30-33`). Since
`providerConfigKeys` lets type `aes` read `aes_key` and nothing else and type
`exit` read nothing (`internal/config/config.go:914-917`), that third group is
today exactly one key. The chart takes that route and only that route:
`deploy/helm/s3-encryption-proxy/values.yaml:277` ships
`aes_key: "${S3EP_AES_KEY}"`, and `templates/deployment.yaml:108-118` renders
`S3EP_AES_KEY` from a `secretKeyRef` — the chart's own Secret under key
`aes-key` (`templates/secret.yaml:15-17`) or an externally managed one
(`values.yaml:298-299`) — but `env: []` (`values.yaml:280`) is spliced
verbatim at `templates/deployment.yaml:120-121`, so anything a caller puts
there becomes a literal in the PodSpec. *Not verified by experiment here, but*
the two mechanisms differ in exactly one way that matters: a `secretKeyRef`
keeps the value out of the PodSpec, so `kubectl get pod -o yaml` and the
container runtime's inspect output show only the reference, whereas a literal
`env` entry shows the key to everyone who may read the Pod; in both cases the
expanded value sits in the container's environment and is readable at
`/proc/<pid>/environ` by anything sharing the PID namespace or holding node
access. Nothing zeroes it afterwards, and `SECURITY_ARCHITECTURE.md:281`
already records the KEK's lifetime as the process lifetime. Questions 19
and 20.

**AG. Every provisioned instance needs a licence of its own, and the chart
delivers it the way the KEK is not delivered.** `ValidateProviderType` refuses
every provider type but `exit` when no valid licence is held
(`internal/license/validator.go:152-164`), the check is part of configuration
validation and a failure is fatal with no degraded and no grace-period mode
(ADR 0016 D1), and `cmd/s3-encryption-proxy/main.go:75` runs it before a
server exists — so an unlicensed instance does not become unready, it never
starts, and a licence that lapses later ends the running process as well
(`internal/license/validator.go:244-259`, second-pass finding D). The token
reaches a pod either as `S3EP_LICENSE_TOKEN`, the one name with no alias, or
from `license_file` (`internal/config/config.go:174`), and the chart uses the
file route: `templates/configmap.yaml:10-11` injects
`license_file: "/app/license/license.jwt"` and
`templates/deployment.yaml:137-139` with `:157-167` mounts the Secret there.
That asymmetry is worth naming before an operator is designed — the chart
keeps the licence, a commercial control ADR 0016 D12 says is never a security
one, off the process environment, and puts the KEK into it. The per-instance
cost is visible in the one suite that provisions a real instance and creates
exactly one licence Secret in one namespace
(`test/e2e/velero/e2e-up.sh:171-173`); N instances in N namespaces need N, and
nothing in this tree performs that copy. Nothing in the product counts or
binds instances either: `k8s_cluster_id` is parsed into the claims
(`internal/license/types.go:19`) and logged
(`internal/license/logger.go:41-42`) and compared to nothing — its only other
appearance is in `cmd/license-tool`, which mints it. Question 15.

**AH. One `--set` renders two environment references against a Secret that has
one key, and a typed resource makes that state unrepresentable.**
`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:96` opens a single
guard,
`{{- if or .Values.secrets.s3.accessKeyId .Values.secrets.s3.secretKey }}`,
over both entries — `S3_ACCESS_KEY_ID` reading `access-key-id` at `:97-101`
and `S3_SECRET_KEY` reading `secret-key` at `:102-106`, closed at `:107` —
while `templates/secret.yaml:9` and `:12` guard the two keys independently. So
`--set secrets.s3.accessKeyId=someuser` alone renders a valid Deployment
referencing a key the Secret does not contain: the render succeeds, the
install succeeds, and the failure is deferred to the kubelet, which cannot
create the container and holds the pod in `CreateContainerConfigError` with an
event naming the missing key. There is no crash loop and no proxy log line at
all, because the process never starts, which is the most expensive shape of
failure to diagnose from outside. The helm-unittest case covering this path
sets both values
(`deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml:79-83`), so it
cannot see the asymmetric case, and the adjacent guard at
`templates/deployment.yaml:108` uses `or` correctly for a different reason —
`secrets.encryption.aesKey` and `secrets.encryption.existingSecret` are two
sources for one key rather than two halves of a pair — which is probably how
the wrong shape was copied. A resource modelling the backend credential as one
object with two required subfields, or as a reference the operator resolves
before it writes anything, makes the state unrepresentable rather than merely
refused, which is a thing the schema gets for free and the chart never had.

**AI. "Operator" already names the human in this repository, and one of those
places is a trust-boundary role.** Counted on 2026-09-16: 236 occurrences
under `docs/` outside the ticket directory, 25 in `SECURITY_ARCHITECTURE.md`,
4 in `CLAUDE.md`, and none in `README.md`. The sharpest is the roles table at
`SECURITY_ARCHITECTURE.md:89`, whose role is literally named **Operator** and
defined as "Whoever writes the proxy configuration and holds the KEK
material", with the access column reading "Everything. The operator chooses
the KEK and the backend" — once a program called the operator writes the proxy
configuration and holds Secrets of key material, that row does not become
ambiguous, it becomes true of the wrong subject, and it is the row the
existing Done-when box at lines 412-413 wants the new program's privileges
written into. Three more flip outright: `SECURITY_ARCHITECTURE.md:727` and
`:734` restate the network-boundary rule as the operator's own, `:1013` says
"a Secret the operator manages", and `:1002` describes an operator rotating a
provider alias and key material. The documentation home is named for that
reader (`docs/operations/README.md:1-3`) and so are the contributor
instructions (`CLAUDE.md:47`, `:135`, `:583`). One ADR already uses both words
for one actor: ADR 0030 D1 says "the administrator writes the policy for their
own cluster and maintains it"
(`docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md:57-60`)
and D3 eleven lines later calls the same human "an operator who set
`networkPolicy.enabled: true`" (`:67-70`). The ticket's existing open question
3 — does ADR 0030 D1 bind the operator — is that collision wearing a question
mark: read one way it asks whether a chart rule binds a program, read the
other it asks whether a rule binds the human it was written about, which is
not a question at all. Question 38.

## cert-manager in the kind setup

**Nothing in this repository installs cert-manager today.** The chart ships
two Certificate templates — one for an Ingress secret
(`deploy/helm/s3-encryption-proxy/templates/certificate.yaml:1-17`) and one
for the proxy's own Service listener
(`templates/servicetls-certificate.yaml:3-8`) — and both are rendered and
never run: the `helm-chart` job renders every values file that ships, the
Velero end-to-end values included
(`.github/workflows/test-pipeline.yml:249-253` calling `make helm-test`, whose
loop is `Makefile:498-501`), and no script anywhere creates an Issuer or a
Certificate object. A grep over every shell script, workflow, values file and
Makefile finds cert-manager only in chart templates, values and documentation.
The Velero suite runs the bring-your-own arm with PKI it generates itself, and
the values file says so: the certificate is the test PKI's, generated by the
bring-up script into the `s3ep-tls` Secret, "so this run exercises the
bring-your-own arm — the kind cluster has no cert-manager"
(`test/e2e/velero/values-proxy.yaml:67-72`, with the generation at
`test/e2e/velero/e2e-up.sh:31` and `:164-169`). Adopting cert-manager turns
ADR 0026's stated gap from a claim into a behaviour, which is the whole reason
to do it.

**What the other repository does, step by step, and it is directly liftable.**
Apply the pinned upstream release manifest, wait `Available` on
`cert-manager`, `cert-manager-webhook` and `cert-manager-cainjector`, then
apply a three-object chain: a `selfSigned` ClusterIssuer, a CA Certificate in
the `cert-manager` namespace with `isCA: true` and
`secretName: e2e-ca-secret`, and a CA ClusterIssuer backed by that Secret
(valkey-operator/`test/e2e/testdata/cert-manager-issuer.yaml:4-37`). Its
Makefile does it with 120-second waits followed by `sleep 5` before the issuer
apply (valkey-operator/`Makefile:121-131`), while CI hardens the same steps
with 300-second timeouts, an additional
`kubectl -n cert-manager wait --for=condition=Ready pods --all`, and a
five-attempt retry around the issuer apply
(valkey-operator/`.github/workflows/release.yml:245-263`) — because the
validating webhook reports `Available` before its own serving certificate is
usable, which is the ordering hazard the retry exists for. That retry has no
`exit 1` after the loop, so five failed attempts leave the step green. This
repository's rule is that a workstation and a runner run the identical script,
so there is one loop to write rather than two, and it has to fail the run when
the last attempt fails.

**It sits beside `test/ssl-setup/gen-certs.sh`; it cannot replace it.** That
one generated leaf carries the compose demo stack at `DNS.1-4`
(`test/ssl-setup/gen-certs.sh:60-63`), the kind cluster's Service names at
`DNS.5-14` (`:66-75`) and `IP.1 = 127.0.0.1` (`:76`), from a single
`openssl x509 -req` at `:86-90`. It is consumed by nine files —
`start-demo.sh`, `scripts/conformance-run.sh`,
`test/integration/minio_test_helper.go`, `test/perf/client.go`,
`test/e2e/harness/backend.go`, `test/e2e/harness/harness.go`, and all three
`e2e-up.sh` scripts — of which eight have no Kubernetes anywhere near them.
cert-manager can replace at most the kind half, and there is a concrete
blocker even there: both Certificate templates emit `dnsNames` and no
`ipAddresses`
(`deploy/helm/s3-encryption-proxy/templates/servicetls-certificate.yaml:22`,
`templates/certificate.yaml:17-18`), while the Velero suite reaches the proxy
at `https://127.0.0.1:30443` both from the host-side `velero` CLI and through
the BackupStorageLocation's `publicUrl`
(`test/e2e/velero/values-velero.yaml:49`, whose comment at `:47-48` says
pre-signed URLs are minted against it and fetched by a CLI on the host that
cannot resolve cluster DNS). A cert-manager-issued listener certificate has no
`127.0.0.1` in it; host-side verification fails, and the tempting repair is
disabling verification, which removes a real assertion from a release gate.
Either the Certificate template gains an `ipAddresses` field — and then so
does the resource — or the suite reaches the proxy by a DNS name. Neither is
decided anywhere. Question 37.

**Adopting it inverts the bring-up ordering.** Today the PKI is stage zero
because the CA must exist before the cluster: it is generated at
`test/e2e/velero/e2e-up.sh:31`, base64-encoded into the Velero
BackupStorageLocation at `:244`, used for MinIO's TLS material at `:121-122`,
and handed to the cluster as a `ca.crt` file at `:169`. With cert-manager the
CA is minted inside the cluster, so the order becomes create the cluster,
install cert-manager, apply the issuer chain, wait for the CA Secret, export
`ca.crt` to the host, and only then render the Velero values and create the
MinIO material. Getting it wrong produces a BackupStorageLocation that never
goes `Available`, which reads as a Velero problem rather than an ordering one.

**Pin the version where this repository pins versions.** The other repository
writes `v1.17.2` as a literal in two places (valkey-operator/`Makefile:124`
and `.github/workflows/release.yml:247`) with none of its five custom Renovate
managers matching a cert-manager release URL. Here the convention is a
`versions.env` beside the suite, grouped by Renovate and never automerged
(`renovate.json:267-280` for the client suites, `:255-266` for Velero),
because a version move is an experiment whose verdict is the finding — and
cert-manager sits in the trust path of a TLS verdict.

**The effect on the three existing suites is small if it is additive.** rclone
and s3cmd run against the compose stack and have no cluster, so they are
untouched. Velero is the only suite with a kind cluster, so cert-manager
arrives there, on a bring-up that already costs minutes and a job that budgets
forty-five (`.github/workflows/test-pipeline.yml:800-803`). Making
cert-manager the only tested path would leave ADR 0026 D4's bring-your-own arm
— the arm every current user, every air-gapped install and the Velero suite
itself is on — with no run behind it, which is the same gap being closed,
moved.

**The renewal gap is the proxy's, not the operator's, and this is a finding
about this product rather than a task for s3eo.** Verified on 2026-09-16:
`internal/proxy/server.go:287` calls
`ServeTLS(listener, s.config.TLS.CertFile, s.config.TLS.KeyFile)`, that is the
only `ServeTLS` in `internal/`, `cmd/` or `pkg/`, and `GetCertificate` appears
in none of the three — so the certificate is read and parsed once for the life
of the process. cert-manager rewrites the Secret, the kubelet refreshes the
file, and the process keeps serving the leaf it parsed at startup until that
leaf expires and every client refuses the handshake at once. The chart cannot
force a roll and structurally never could: it hashes only what it renders
itself (`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:25`,
`:30`), and the cert-manager Secret is neither. This is a defect in the proxy
that affects chart users, compose users and anyone rotating an
`existingSecret` by any means, and it exists whether or not an operator is
ever written. An operator-side workaround — hash the TLS Secret into the pod
template and roll on renewal — covers one of those three deployment paths and
pays for it with a fleet-wide rolling restart on every renewal cycle, each one
aborting the multipart uploads those pods hold (ADR 0029 D2): a silent expiry
traded for a scheduled outage on a timer. *Not verified:* cert-manager's
default `duration` and `renewBefore`, which the chart's Certificate templates
do not set, so whatever cert-manager defaults to is what bounds the window.

**One consequence for the suite itself.** The other repository's test CA runs
ten years (valkey-operator/`test/e2e/testdata/cert-manager-issuer.yaml:21`),
so no run ever observes a renewal, and a suite asserting issuance —
Certificate `Ready`, Secret populated, pod mounts it, handshake succeeds —
passes against a proxy that can never pick up a new certificate. A green gate
would then say "cert-manager works here", which is the one thing it must not
say while the reload gap is open. A case that forces a renewal inside the run
and asserts the **new** leaf is served is red on day one, and ADR 0031 D2 and
D3 make that allowed and wanted — D3 explicitly permits committing such a test
before the fix — but it is a deliberate decision about a release gate and not
a surprise.

## Fourth pass, 2026-09-16: what the day's decisions pull in behind them

**AJ. CRD validation ratcheting decides two things D-B would otherwise get
wrong, and it is a Kubernetes behaviour rather than a fact in this tree.**
Kubernetes semantics, moderate-high confidence: `CRDValidationRatcheting` is
on by default from 1.30, so an update to a custom resource is not re-validated
against a tightened rule for any field the update does not change. Two
consequences follow and both bear on decisions already taken. First, a bound
added later binds new resources and not stored ones: a tightened minimum
placed on `shutdown_timeout`, `multipart_part_size`,
`multipart_short_part_buffer_size` or `multipart_upload_concurrency` refuses a
written zero on a fresh resource while an existing resource carrying zero
keeps being accepted on every unrelated edit — and the real minima differ per
key rather than being a uniform 1 (5 MiB at
`internal/config/config.go:1029-1030`, 5 MiB at `:1047-1051`, and the 1-to-32
range at `:1076-1082`), while `shutdown_timeout` is only refused when negative
(`:624-626`). Second, what a written zero means today is not uniform either,
so the schema choice is a behaviour choice: `MultipartShortPartBufferSize` and
`MultipartUploadConcurrency` are guarded by `!= 0` tests (`:1047`, `:1076`)
and fall through to a default, but `multipart_part_size` does not —
`internal/proxy/handlers/object/operations.go:395` compares the declared
plaintext length against `h.config.Optimizations.MultipartPartSize` raw, so a
written zero sends every sized PUT into the internal multipart producer, and
only the producer's own part size falls back to 12 MiB
(`internal/proxy/handlers/object/helpers.go:264-270`). That asymmetry is the
substance question 28 now has to name. And ratcheting is not merely a
convenience: without it, tightening any of the 42 leaves on a cluster-wide
operator's CRD would make the operator's own finalizer addition or removal on
an already-invalid tenant resource fail validation, which bricks that
resource's deletion and, through a namespace terminating on it, that
namespace's. Ratcheting is the mechanism relied on, and it should be written
down as such rather than left as an absence nobody noticed.

**AK. The `ownerReference` D-A mandates may require a verb on the owner's
`finalizers` subresource, and it is the one verb the must-not-break list never
names.** Kubernetes semantics, high confidence on the mechanism and moderate
on the distribution: controller-runtime's `SetControllerReference` sets
`blockOwnerDeletion: true` by default, and the
`OwnerReferencesPermissionEnforcement` admission plugin requires the writer to
hold `update` on the owner's `finalizers` subresource before it will accept a
reference carrying that field. The plugin is not in the default enabled set on
a vanilla kube-apiserver, so it does not bite on the kind cluster this
repository runs (`test/e2e/velero/kind-config.yaml:7`, `kindest/node:v1.36.1`)
and does bite on hardened distributions that enable it — which is the worst
shape of failure, a ClusterRole that passes every test here and answers 403 on
every Secret write at a customer. There are exactly two ways out and one must
be chosen deliberately rather than discovered: grant `update` on
`<crd-plural>/finalizers` in the operator's ClusterRole, or set
`blockOwnerDeletion: false` on every reference the operator writes and record
that the owner can then be deleted while its dependents are still being
resolved. The existing prohibition list enumerates verbs the operator must not
hold and names no verb it must; this is the one.

**AL. The chart's pod-template checksum does not cover an externally managed
licence Secret, so rolling on renewal is new code the operator has to write
rather than behaviour it inherits.** Verified:
`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:24-30` hashes the
rendered ConfigMap and the rendered Secret, and the comment at `:27-29` says
in as many words that an externally managed one "stays invisible here";
`SECURITY_ARCHITECTURE.md:1007-1014` records the same closure and its
remaining gap — "a Secret the operator manages themselves: the chart cannot
hash what it does not render" — and `templates/secret.yaml:18-19` renders
`license.jwt` only under `.Values.license.jwt`, so the
`license.existingSecret` route (`values.yaml:303-311`, projected at
`templates/deployment.yaml:157-168`) is outside the hash by construction. That
is exactly the shape D-C produces: a Secret the operator writes and the chart
never renders. The consequence for D-C is the opposite of inheritance. The
token is read once, at startup (`internal/config/config.go:378`, inside
`LoadAndStartLicense` at `:371-391`), and the runtime monitor compares an
already-parsed expiry (`internal/license/validator.go:193-194`), so a renewed
file under an existing mount changes nothing in a running process — the
default today is a no-op until the fleet dies, and rolling the fleet on
renewal means the operator computing its own annotation over the copy it just
wrote. Which of those it does is question 24's subject, and the finding is
that neither is free and neither exists yet.

**AM. One token guarantees a fleet-wide simultaneous expiry rather than merely
permitting one, and the only forewarning is opt-in.** Verified:
`StartRuntimeMonitoring` captures the already-parsed licence info and its
ticker fires every 60 minutes (`internal/license/validator.go:184`), comparing
`time.Now()` against `v.info.ExpiresAt` (`:193-194`) — it re-reads neither
`S3EP_LICENSE_TOKEN` nor `license_file`, ever — and on expiry it runs the
shutdown handler that exits 1, after which the startup gate refuses the
restart (`internal/config/config.go:786-800` into
`internal/license/validator.go:152-165`, ADR 0016 D1). One token therefore
means one expiry instant for N instances: each pod dies at its own first tick
after that instant, so the whole fleet ends inside a 60-minute window whose
only spread is the pods' start offsets, and any pod restarting for any other
reason inside that window dies immediately at startup instead. What warns
beforehand is one alert and one gauge, and both have limits worth stating:
`S3EPLicenseExpiringSoon` fires on
`(s3ep_license_expiry_timestamp - time()) / 86400 < 30` with `for: 1h`
(`deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml:65-67`, the
threshold at `values.yaml:363`), and it resolves rather than escalating when
the process exits; `S3EPLicenseExpired`, whose expression is
`s3ep_license_info == 0` (`prometheusrule.yaml:76-77`), cannot fire from a
running proxy, because the only non-test caller of `SetLicenseInfo` sits
inside the `result.Valid && result.Info != nil` branch at
`cmd/s3-encryption-proxy/main.go:97-102` and therefore only ever sets 1. So at
the instant N pods enter crash-loop, every licence series in the cluster stops
being scraped and no licence alert is firing anywhere. All of it is behind
`monitoring.enabled`, which defaults to `false`
(`internal/config/config.go:415`). There is one upside and it is real: N
instances share one deadline, so an administrator tracks one date instead of N
— and the cheapest place to surface it is the operator, which holds the token
and can put the expiry on every resource it provisions without any listener in
any pod. The unfireable alert is a defect in the shipped chart today,
independent of any operator and outside this ticket's scope: it belongs in a
ticket of its own and is not a condition on archiving this one.

## Open questions

Thirty-six of the forty are open and four are closed — 1 by the decision block of
2026-09-14, and 2, 14 and 15 by the decisions of 2026-09-16. A closed question is
struck rather than deleted, with what remains open inside it named, because what a
decision did *not* settle is the part a later reader gets wrong.

1. ~~**Chart and operator: coexist, or one replaces the other?**~~ **Struck
   2026-09-16.** The decision block of 2026-09-14 answers it — they coexist and
   do different jobs — and the question was left standing in this list by
   mistake. What is still open is not *whether* they coexist but what each owns,
   which is questions 25 and 27.
2. ~~**What does the CR carry?**~~ **Closed 2026-09-16 by D-B**: a fully typed
   schema over the proxy's configuration keys, not an opaque `config` string,
   not a reference to an operator-managed ConfigMap, and not a hybrid — so
   `x-kubernetes-preserve-unknown-fields` over the per-type provider `config:`
   block is out, since that block is where a hybrid would hide, and the
   discriminated union that replaces it duplicates `providerConfigKeys`
   (`internal/config/config.go:914-917`) in the schema on purpose. The price
   is what the question named and is now measured: 42 leaves of API surface
   under nine structs, each with its own compatibility rules, and the loader's
   `validateProviderConfig` (`:952-977`) restated in CEL. What remains open is
   per-leaf and not structural: which of the 42 the operator sets rather than
   exposes — `license_file`, `tls.cert_file`, `tls.key_file`, `bind_address`
   and the two monitoring addresses are the candidates, and the chart already
   refuses a `tls:` or a `monitoring:` block inside `values.config`
   (`deploy/helm/s3-encryption-proxy/templates/_helpers.tpl:248`, `:254`) for
   the same reason. That remainder is a design list, not a decision, and it
   belongs with question 28.
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
   (`deployment.yaml:24-30`, and the chart README's *Known limitations*, which
   since 2026-09-16 carries external ConfigMaps and probe schemes rather than
   this — the shared-credential warning moved to *Security Considerations*
   item 3). It is
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
    Corrected 2026-09-16. ADR 0030 D4 answers it for the scrape and ADR 0034 D8
    answers it for the S3 surface; neither answers it for `/status`, which
    carries the active provider, its type and the KEK fingerprint on a listener
    nothing authenticates (G). Whatever the operator surfaces as status is drawn
    from these, so this answer bounds the resource's status as well — question 29
    is the same question aimed at the Custom Resource rather than at the port.
12. **Is a custom resource a tenant?** Nothing in the proxy scopes an instance to a
    bucket (H). If the pitch is one proxy per team, the isolation that claim rests
    on lives in the backend's IAM — say so, or build the scope.
13. **Where does the operator live, and what does that cost the release?** The
    header leaves the repository open. In this tree it shares the version, the
    pipeline and every release gate of the proxy, and a CRD becomes part of what
    5.x means; in its own it needs a second pipeline, a second licence story and a
    stated compatibility range against proxy images. Neither is free and the
    difference is not cosmetic. **Answered in part on 2026-09-16**: it lives in
    this repository. What that costs is under *Decided 2026-09-16*, and what is
    left of this question is questions 16 and 36.

14. ~~**What may the operator's ServiceAccount hold cluster-wide, and does it
    read Secrets at all?**~~ **Closed 2026-09-16 by D-A**: cluster-wide `get`,
    `list`, `watch`, `create`, `update` and `patch` on `secrets`, bounded on
    the write path by a `ValidatingAdmissionPolicy` — the fourth candidate,
    and the only one that keeps self-service provisioning. `patch` is in the
    grant because a controller-runtime client doing server-side apply or a
    merge patch needs it and the policy is unaffected, a PATCH reaching
    admission as `UPDATE`. The three rejected candidates each cost something
    different: no `secrets` verb at all costs admission-time validation that
    the Secret exists, the rotation watch, and the claim that a provisioned
    proxy comes with working credentials; read-cluster-wide-write-nowhere
    keeps those two and costs one more credential per instance for a human to
    generate and hand over; a namespaced Role bound per namespace costs
    self-service provisioning into an unenrolled namespace. **No `delete` and
    no `deletecollection` is part of this closure and is derived**: the
    controller `ownerReference` the policy demands is what makes the garbage
    collector remove the Secret with its resource, so the verb has no
    consumer, and acquiring one is a change to D-A that drags a `DELETE` entry
    in the operations list and a third validation on `oldObject` with it. The
    bound, its clauses and what it does not reach are under *Decided
    2026-09-16*; the unbounded cluster-wide read and the
    forged-`ownerReference` weakness are under *Accepted residual risks,
    2026-09-16*. **What remains open inside 14** is two things: whether the
    operator holds read-only `get`, `list` and `watch` on
    `admissionregistration.k8s.io` so it can see its own bound and refuse to
    run unbounded rather than looping — the mitigation for a policy nobody
    installed, and the only verb on that group the operator may ever hold; and
    which Secrets the informer decodes, which is question 21. It narrows and
    does not close questions 17 and 18, each of which gains a candidate built
    from the same machinery. Listed to be decided, not proposed.
15. ~~**Where does a provisioned instance's licence come from, given that no
    Custom Resource may reach across a namespace?**~~ **Closed 2026-09-16 by
    D-C**: the operator holds one token and copies it per resource into the
    provisioned namespace as a file-mounted Secret carrying a controller
    `ownerReference`, reproducing the chart's route exactly — `license_file`
    injected into the rendered configuration as
    `templates/configmap.yaml:10-11` does it, the Secret projected with its
    key mapped to path `license.jwt` (`templates/deployment.yaml:157-168`) and
    mounted read-only (`:137-141`), and `S3EP_LICENSE_TOKEN` never rendered,
    because the environment route wins silently over the file
    (`internal/license/validator.go:372-389`, `:332-341`). The accepted
    trade-off is recorded under *Accepted residual risks, 2026-09-16*, on ADR
    0016 D12's own split: the gate is a commercial control, its lapse is a
    security-relevant availability property
    (`docs/adr/0016-the-license-is-a-startup-gate.md:138-144`). **One
    precondition remains and it blocks the licence ADR rather than the
    decision: whether the commercial terms permit one token across many
    namespaces.** That is not in this tree and cannot be settled in it. It
    goes at the top of the licence ADR as a blocking item with a named owner,
    not at the bottom as a caveat; question 4's identical gap about instance
    counts travels with it; and what a refusal would do to D-C is the owner's
    to decide, not something this list may pre-empt. Whether an instance that
    needs no token gets a copy anyway is question 40.
16. **Is a change to the Custom Resource Definition a breaking change under
    ADR 0018 D5?** D5 says a commit carries the breaking marker whenever the
    change breaks stored data, an existing configuration or a client-visible
    answer, and never softens a marker to route around the guard
    (`docs/adr/0018-a-major-release-is-declared-by-a-label.md:129-132`).
    Whether a CRD field is "an existing configuration" is not answered in D5's
    text. Taken literally, renaming a field carries the marker, takes the
    major label, and ships in the same major
    [ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md) reserves
    for making every stored object unreadable; in the other direction a proxy
    `fix:` bumps the operator's chart version and image tag with nothing in
    the operator changed, because one `semantic-release` job covers everything
    the repository contains. **D-B makes this blocking rather than
    deferrable.** Under the opaque-string arm a new proxy configuration key
    was additive everywhere and no API object moved; with a fully typed
    schema, every key added to `Config` is a field added to the CRD, every
    rename is a field rename, and every removal leaves a field the apiserver
    keeps accepting and pruning until the schema changes — so the CRD now
    moves on the same cadence as `internal/config/config.go`, on one version
    stream, and the choice is load-bearing on the *first* key added after the
    CRD ships rather than on some later rename. It also has a consequence
    inside D-A that travels with it: the served-version candidate is why the
    policy's owner clause is group-pinned and version-agnostic rather than
    pinned to one `apiVersion`, because an `ownerReference` keeps the version
    its writer used and a pinned clause would silently stop matching the
    operator's own older Secrets. The candidates are amending D5 to name the
    CRD explicitly as an existing configuration; amending it to exclude a CRD
    field on the grounds that the apiserver, not the proxy, refuses an unknown
    one; a second version stream, which contradicts the decision that the
    operator lives here; or a served-version policy that makes a rename
    additive by construction, which costs a conversion path and, at a second
    version, the webhook finding V says is not needed while there is one.
    Listed to be decided, not proposed.
17. **How is the `configmaps` write grant narrowed so that it reaches the
    proxy's configuration and not `coredns`?** Finding N is why this cannot be
    waved through. The candidates: **`resourceNames` on the rule**, which does
    not apply to `create` — so the operator can still create a ConfigMap of
    any name in any namespace — and which pins the rendered ConfigMap's naming
    convention into the ClusterRole, so a name derived from the resource means
    a ClusterRole edit per resource unless the name is fixed per namespace;
    **a namespace allowlist enforced in the operator's own code**, which
    constrains a buggy operator and not a compromised one, while the grant an
    auditor reads still says every namespace; **a per-namespace Role created
    on demand with no `configmaps` rule in the ClusterRole at all**, which
    needs `create` on `rolebindings` plus `bind` or `escalate` to hand out a
    permission the operator holds — the exact privilege finding L argues for
    refusing — and turns the first reconcile in a namespace into a multi-step
    that can half-succeed; **no ConfigMap at all**, rendering the
    configuration into the Secret that already has to exist, which adds no
    verb but puts non-secret settings behind the same audit trail as key
    material and makes the rendered configuration invisible to
    `kubectl describe`, which is the first thing support asks for. This cannot
    be settled independently of question 14, because one candidate trades away
    what finding L wants refused. Listed to be decided, not proposed.

18. **What, if anything, enforces a pod security standard on a namespace s3eo
    writes a Deployment into?** The `create deployments` grant is not
    negotiable — it is what the operator is for — so the question is what sits
    between the PodSpec and the node, and today nothing in either repository
    does (finding M). The candidates: **s3eo stamps
    `pod-security.kubernetes.io/enforce=restricted` on the namespace when it
    first reconciles a resource there**, which costs a cluster-wide `patch` on
    `namespaces` — another cluster-wide write verb on an object the operator
    does not own — and breaks every unrelated workload already in that
    namespace that is not compliant; **the kind cluster ships a cluster-wide
    admission configuration defaulting every namespace to restricted**, which
    proves something about the test cluster and nothing about a customer's,
    and which needs an exemption list because the CSI hostpath driver the
    Velero suite installs needs privileged
    (`test/e2e/velero/e2e-up.sh:154-159`) — and that exemption list is itself
    the hole; **the standard is documented as an operator precondition and an
    end-to-end preflight asserts the label**, which is a claim about the
    environment rather than a control, and a preflight that runs only in the
    suite says nothing about a real install; **nothing, with
    `SECURITY_ARCHITECTURE.md`'s privilege footprint stating plainly that
    installing s3eo is a node-level-code-execution grant**, which is the
    honest and cheapest option and means s3eo cannot be recommended where
    namespace tenants are part of the threat model; **the resource carries no
    pod-shaped field at all** — no image override, no pod annotations, no
    tolerations — which closes the resource-author attacker, leaves the
    compromised-operator attacker exactly where it was, and removes the image
    override an air-gapped registry needs. It bears on the kind setup as much
    as on a customer cluster, because adopting cert-manager touches the same
    bring-up script an admission configuration would live in. Listed to be
    decided, not proposed.

19. **Does a Custom Resource reference the KEK Secret at all, or is the KEK
    outside the operator's scope?** ADR 0021 D1 keeps key material out of the
    repository and existing question 7 asks what deleting a resource deletes,
    but neither says whether the operator ever learns the Secret's name. The
    candidates: **the resource names an existing Secret in its own namespace
    and the operator renders `${S3EP_AES_KEY}` from it**, which gives the
    operator's ServiceAccount a read of key material in every namespace it
    serves and makes one component the place a cluster's keys converge; **the
    resource names nothing and the key arrives through whatever `env`
    passthrough exists**, which costs the operator any ability to validate the
    pairing (second-pass finding B) and turns a missing key into a pod failing
    at start with `environment variable ${S3EP_AES_KEY} is not set or empty`
    (`internal/config/envexpand.go:32`) and a status that cannot say why;
    **the operator generates the key and owns the Secret**, which is cheap to
    provision, is exactly the data-loss shape existing question 7 describes,
    and satisfies ADR 0021 D1 and D2 only if the generated value is never
    written back into a resource or a values file; **the KEK is out of scope
    and a resource naming type `aes` is refused**, which leaves the operator
    provisioning only `exit` instances that write plaintext. The answer also
    bounds what the resource's status may name, because a KEK fingerprint is
    one of the fields question 29 puts in scope. Listed to be decided, not
    proposed.

20. **One KEK across every namespace, or one per namespace?** This is the
    direct consequence of the namespaced decision, and the tree already
    decides what each answer feels like. The fingerprint is derived from the
    master key with HKDF (`pkg/encryption/keyencryption/aes.go:56-66`, ADR
    0004 D6) and written on every object as `s3ep-kek-fingerprint`
    (`internal/orchestration/metadata.go:116`); a read looks the provider up
    by the fingerprint the object carries
    (`internal/orchestration/segmented.go:351-356`), and when no loaded
    provider has it the unwrap returns `ErrUnknownFingerprint`
    (`internal/orchestration/providers.go:245`), which becomes
    `ErrKeyMaterialUnreadable` (`internal/orchestration/segmented.go:366-372`)
    and the handler answers `403 InvalidObjectState`, "Object key material
    failed authentication"
    (`internal/proxy/handlers/object/operations.go:258-265`) — the same status
    and the same shape of message a genuinely damaged object gets two branches
    earlier (`:245-252`), so a client cannot tell a foreign key from
    corruption. The candidates: **one KEK copied into every namespace**, where
    namespace isolation buys nothing cryptographically because whoever reads
    one namespace's Secret decrypts every namespace's objects, and rotation is
    a fleet event rather than a tenant's; **a distinct KEK per namespace**,
    where two instances over one shared bucket each refuse the other's objects
    with a 403 that reads as corruption, and a cross-namespace restore is an
    unreadable object with a correct-looking error; **a distinct KEK per
    namespace with every other namespace's provider also listed in each
    instance**, which restores readability and is the first candidate wearing
    a longer list, with the resource now carrying the key set; **a bucket
    scope per instance so no two instances address the same objects**, which
    nothing in the proxy provides today (second-pass finding H, existing
    question 12). *Not verified by experiment here, but* the retired-key path
    is the same code, so the operator inherits this whether the second key
    belongs to another namespace or to yesterday. Listed to be decided, not
    proposed.

21. **Which Secrets does the operator cache, and how are they labelled?**
    Finding T is the shape of the mistake: a cache narrowing is not a
    privilege narrowing, and conflating them is how an over-broad role
    survives a review that believes it was narrowed. A label-scoped
    `Cache.ByObject` only works if every Secret the operator reads carries the
    label, and a backend credential written by a human will not. The
    candidates, and D-A has already removed one of them: ~~label it on first
    read~~ — **struck 2026-09-16**, because that is exactly the write D-A's
    policy refuses: a backend-credential Secret written by a human carries no
    controller `ownerReference` and does not match the operator's closed name
    set, and the `oldObject` adoption rule forecloses the operator adding one,
    so the label write is denied and the reconcile loops. What is left is
    three: **read Secrets uncached through the direct reader**, which costs an
    apiserver read per reconcile and forfeits the rotation watch; **require
    the label as a documented precondition**, which means refusing an
    otherwise valid resource and produces a failure whose cause is a missing
    label rather than a missing credential; and **cache everything, as the
    precedent does**, which is now the default if nobody decides — and it is
    the one this repository's own refusal condemns, `validateMonitoring`
    rejecting a non-loopback pprof address
    (`internal/config/config.go:634-644`) because, in its own comment at
    `:630-633`, "a heap or goroutine profile of this process contains DEKs and
    plaintext buffers". Applied to a process that would decode every Secret in
    the cluster into its heap, that is the same argument with a larger subject
    and no equivalent refusal anywhere, which is why the accepted residual
    risk of D-A's cluster-wide read names this question as its mitigation.
    This is an API decision rather than an implementation detail, because the
    second surviving candidate changes what a valid resource is. Listed to be
    decided, not proposed.
22. **Does the operator render `${VAR}` references or values into the
    configuration it writes?** The whole configuration, `s3_clients` included,
    is one templated blob today
    (`deploy/helm/s3-encryption-proxy/templates/configmap.yaml:36` splicing
    `.Values.config`), and the shipped values already use references for both
    the backend and the client credential
    (`deploy/helm/s3-encryption-proxy/values.yaml:255-256`, `:260-261`), so
    the risk is regressing from the chart rather than inventing something. A
    ConfigMap is readable under a weaker permission than `get secrets` and is
    conventionally outside the apiserver's encryption configuration — *not
    verified here; standard platform behaviour.* Against that, `validate()`
    requires only `target_endpoint` (`internal/config/config.go:484-487`) and
    by exhaustion the only emptiness and length checks in the loader are on
    `s3_clients` entries (`:1106`, `:1110`, `:1115`, `:1119`), so nothing
    anywhere checks `s3_backends[].access_key_id` or `.secret_key` and
    `internal/config/envexpand.go:31-32` refusing an unset or empty reference
    is the only thing between a misspelled Secret key and a proxy signing
    every backend request with empty credentials. The candidates: **references
    only, with every referenced variable a `secretKeyRef` in the PodSpec**,
    which keeps the loader's floor and makes the configuration-to-environment
    pairing the operator's to get right — a fourth variable name renders,
    installs and fails at pod start (second-pass finding B); **values
    inlined**, which removes the floor and puts the credential in the weaker
    object; **references for credentials and values for everything else**,
    which is the chart's shape and needs the set of credential fields written
    down somewhere that cannot drift from the loader's three expansion groups.
    Listed to be decided, not proposed.

23. **What exactly does the operator generate for the client credential, and
    what proves it?** The floors invite the weak answer: `validateS3Clients`
    enforces an 8-character access key id and a 16-character secret and
    uniqueness, and nothing else — no charset rule, no entropy rule, no
    maximum (`internal/config/config.go:1114-1121`) — so sixteen identical
    characters pass. SigV4 hands an attacker who captures one signed request
    the canonical request, the string-to-sign and the final signature, and the
    derivation is four HMAC-SHA256 passes over the secret, entirely offline;
    ADR 0014 D7 records that the proxy performs no rate limiting and no
    per-address blocking, and D8 that the client address is a log field and
    never an identity, so there is not even a counter to throttle on. The
    blast radius is complete for one instance, because `S3ClientCredentials`
    carries no scope and no expiry (`internal/config/config.go:63-69`) and
    nothing scopes a client to a bucket. The candidates are a specified mint —
    a stated number of bytes from a cryptographic source, base64url-encoded,
    for each half — against a value derived from the resource's name or UID,
    which is reproducible by anyone who can read the resource, against leaving
    it to whatever the implementation does. Whichever is chosen, the loader
    accepts the weak version, so the thing that proves it is a test rather
    than a validator rule — and a test asserting only that an error is nil
    stays green against every candidate. Listed to be decided, not proposed.

24. **Which triggers may roll a proxy, and is that set a subset of the
    chart's?** Today exactly one actor restarts a pod: a human running
    `helm upgrade` on a chart that hashes only the two templates it renders
    itself
    (`deploy/helm/s3-encryption-proxy/templates/deployment.yaml:24-30`), with
    the comment at `:27-29` recording that an externally managed ConfigMap or
    Secret stays invisible there. s3eo adds a Secret edit, a certificate
    renewal, an operator upgrade, a periodic resync, and a rendering
    difference between operator versions — and none of the five moves the
    resource's generation, so `kubectl get` shows a resource that has not
    changed while its pod restarts. **One of the five is smaller than it
    looks.** A licence renewal under D-C rewrites N copies cheaply and then
    does nothing at all to any running pod: the chart's checksum covers only
    what the chart renders, and `SECURITY_ARCHITECTURE.md:1007-1014` says the
    same in its own words; the token is read once at startup
    (`internal/config/config.go:378`) and the monitor compares an
    already-parsed expiry (`internal/license/validator.go:193-194`). So
    rolling on renewal is not inherited behaviour that has to be suppressed —
    it is new code the operator would have to write, computing its own
    annotation over the copy it just wrote — and the default if nobody writes
    it is a renewal that changes nothing until the fleet stops on the old
    expiry date (finding AL, finding AM). The question is therefore which of
    the five the operator *adds*, not which it inherits. Two others deserve
    naming on their own. An operator upgrade that stamps its own version into
    the pod template restarts every managed workload in one reconcile sweep:
    that is the default of the pattern being copied, where an operator-version
    change alone replaces `Spec.Template` and triggers a rolling restart
    (valkey-operator/`internal/controller/valkey_controller.go:816-823`, and
    `:906-913` for the second workload), and the comparison behind it is a
    bare annotation check
    (valkey-operator/`internal/builder/annotations.go:42-47`) so every
    workload matches on the first sweep after an upgrade. And a rendering that
    is not byte-stable rolls the fleet on the resync interval forever — Go map
    ordering reaching a YAML marshal, or a generated timestamp, is enough —
    with the only trace a restart count climbing on a cadence nobody wrote
    down. Every one of the five is a data-plane event, because a rollout
    aborts every multipart upload the pod holds (ADR 0029 D2). The candidates:
    **the pod template is a function of the resource's spec and nothing else,
    and everything external gets a condition a human acts on** — which is ADR
    0034 D6 transposed from probes to reconciles and costs the automatic
    rotation that is the main thing people want from an operator, and requires
    the operator to report a difference it may not act on; **an opt-in policy
    field per trigger**, which multiplies the resource's API by the number of
    triggers; **a maintenance window**; **a held-upload count the operator
    waits on**, which needs a number no endpoint reports today. This extends
    existing question 8 from "may the operator roll" to "which of five things
    that are not the resource may cause one". Listed to be decided, not
    proposed.
25. **Where does the CRD live in the chart, what group does it carry, and what
    does uninstalling the operator delete?** Finding V is the mechanics: a CRD
    in `crds/` is never upgraded or deleted by Helm, so a schema change
    reaches no existing cluster and the apiserver prunes the new fields
    silently; a CRD under `templates/` upgrades correctly and is deleted by
    `helm uninstall`, cascading to every custom resource and, through their
    owner references, to every proxy Deployment — which for this product
    removes the only path that reads what those instances wrote. The
    candidates are `templates/` with `helm.sh/resource-policy: keep` and an
    install toggle, which leaves the CRD and every resource behind on
    uninstall so a clean removal becomes a manual step with no chart-level way
    to ask for one; `templates/` without the annotation, which is the
    precedent and is the cascade above; and `crds/`, which needs an
    out-of-band apply for every schema change that the chart cannot verify
    happened. Riding along and cheap to get wrong because it is in every
    stored object: the group name, and whether one served version with no
    conversion strategy is the shape — which it is while there is one version,
    and stops being when there are two. Listed to be decided, not proposed.

26. **Does the operator ship an upgrade hook, and what subcommand does it
    imply?** Finding W is the precedent and its cost. The candidates: **a
    cobra subcommand on the existing root command**, which keeps one image and
    grows the proxy's entry point a mode that must never be reachable by
    accident — and the current arbitrary-argument parsing means a typo starts
    the proxy instead of failing, so the argument handling has to be tightened
    in the same change; **a second binary invoked by its own path**, which the
    image already does for `s3ep-keygen` (`Containerfile:80`), at the cost
    that the hook's command and the Containerfile's copy list become a pair
    nothing in the build checks; **a separate operator image with its own
    entry point**, which is a second image to build, scan, sign and version,
    and two application versions that have to agree about which proxy image
    the operator writes into a Deployment; **no hook at all**, which means a
    schema change that needs existing resources rewritten has no automatic
    path and becomes a documented manual step. Listed to be decided, not
    proposed.

27. **Is the operator's ClusterRole generated from markers or hand-written in
    the chart, and what proves they agree?** Finding AC is what happens when
    both exist: drift in both directions, one of them producing a reconcile
    loop and the other producing no error at all, with the only verification
    running in a release-published workflow and covering CRDs alone. Here the
    drifting resource would carry Secret write verbs. The candidates are one
    rendered ClusterRole generated from the markers with a pull-request job
    that fails on a diff; a hand-written chart role with the markers deleted
    so there is one document; or both kept with a check that actually compares
    them, which is the precedent plus the missing half. This repository
    already ships exactly one chart and already has a `helm-chart` job that
    lints, renders every values file and runs helm-unittest in seconds
    (`.github/workflows/test-pipeline.yml:225-253`, `Makefile:498-501`), so
    the place for such a check exists. Listed to be decided, not proposed.

28. **Which CRD numerics are pointers and which are values?** Finding Y is the
    split the loader already draws and the reason it needed a second pass over
    the source file to draw it. Whatever is chosen, the answer has to name its
    population, because a CRD bound does not apply uniformly: with validation
    ratcheting on by default from 1.30 (Kubernetes semantics, moderate-high
    confidence — finding AJ), an update that does not touch an offending field
    is not re-validated against a rule tightened later, so a minimum added to
    a key where a zero is stored today refuses that zero on a new resource and
    keeps accepting it on a stored one. The minima also differ per key rather
    than being a uniform 1 — 5 MiB for `multipart_part_size`
    (`internal/config/config.go:1029-1030`), 5 MiB for
    `multipart_short_part_buffer_size` (`:1047-1051`), 1 to 32 for
    `multipart_upload_concurrency` (`:1076-1082`), and nothing but
    non-negative for `shutdown_timeout` (`:624-626`) — and a written zero does
    not mean the same thing in each: two fall through to a default on a `!= 0`
    test, while `multipart_part_size` is compared raw on the routing path
    (`internal/proxy/handlers/object/operations.go:395`), so a zero there
    sends every sized PUT into the internal multipart producer. The candidates
    below are therefore four candidate lists over two populations, and the
    answer states both. The candidates: **`*int32` with no minimum for
    `read_timeout` and `write_timeout`, value `int32` with a per-key minimum
    and a default for the six that refuse zero** — which keeps absent apart
    from a deliberate zero and moves six refusals to admission, at the cost
    that defaulting writes the number into every stored resource so a later
    change to a default reaches none of them; **`*int32` with a per-key
    minimum everywhere and no defaults, the operator supplying the default at
    render time** — which keeps the stored resource clean and means
    `kubectl get -o yaml` no longer shows the value in force without reading
    the generated ConfigMap; **value `int32` with a minimum on all eight** —
    which removes the legal zero from the two keys where it is the shipped
    default and the thing that makes a transfer bounded by the client (ADR
    0015 D4), so it is a behaviour change rather than a schema choice; **no
    numeric bounds at all** — which accepts a bad number, writes it into a
    ConfigMap, and surfaces it as a crash loop whose reason is in a pod log,
    with the operator reproducing every validator's message in a status
    condition instead. Listed to be decided, not proposed.
29. **What may a Custom Resource's status name, and which of it is a machine
    contract?** A status is not the monitoring listener: it is readable by
    anyone holding `get` on the kind in that namespace, which under a
    cluster-scoped operator over namespaced resources is a larger and less
    deliberate audience than a port whose reachability an administrator
    controls. The two sharp fields are the ones the proxy itself moved off the
    S3 surface for this reason. The **provider alias and type** are the
    deciding field of ADR 0034 D8 — an `exit` provider means the backend holds
    plaintext (ADR 0025) — and a printcolumn makes that readable by every
    namespace tenant. The **KEK fingerprint** identifies which key wrote the
    objects, is stable by construction, correlates instances across
    namespaces, and survives in `-o yaml` output, etcd backups and support
    bundles long after the pod is gone; ADR 0030 D4 rejected a
    deployment-identifying label on the open scrape on that reasoning, and
    whether the same reasoning reaches a status has not been decided — D4
    forbids a licensee-identifying label and a countdown, not an expiry
    timestamp, which is the nuance the answer has to respect. The candidates:
    **status carries only what the operator itself observes** — replicas
    ready, generation reconciled, the Secret it minted — which costs any
    report of a failing backend or a lapsing licence; **status carries the
    backend state and the licence remaining but never the provider or the
    fingerprint**, which costs the one field that says whether the backend
    holds plaintext; **status carries everything `/status` serves, with the
    provider and fingerprint at printcolumn priority one** so they stay out of
    the narrow view and remain in every `-o yaml`, which costs the boundary
    ADR 0034 D8 drew; **Conditions only, no phase string**, which costs the
    one-line `kubectl get` view a human reads; **a phase string for humans
    plus Conditions as the contract**, the precedent's shape (finding AA),
    which costs a second thing to keep true and invites callers to parse the
    prose anyway. *Not verified, and this is the gap:* nothing in this tree
    says how the operator would read `/status` at all — the document sits on
    the monitoring listener, which is off by default
    (`internal/config/config.go:415`) and whose reachability from an operator
    pod is the boundary ADR 0030 D1 declines to draw. Listed to be decided,
    not proposed.

30. **Who owns reloading the listener's certificate?** The gap is the proxy's
    (section 4): `internal/proxy/server.go:287` passes file paths to
    `ServeTLS` and no `GetCertificate` callback exists anywhere in
    `internal/`, `cmd/` or `pkg/`, while the chart already renders
    cert-manager Certificates. The candidates: **a `GetCertificate` callback
    in the proxy**, which needs no operator and covers chart users, compose
    users and anyone rotating an `existingSecret` by any means; **the operator
    hashes the TLS Secret into the pod template and rolls on renewal**, which
    covers one deployment path and costs every in-flight upload on every
    instance at each renewal (ADR 0029 D2); **neither, with the expiry
    documented as a known limitation and the renewal window set long enough
    that it is somebody's calendar problem**. The two are not the same size of
    change and they are not owned by the same product, which is the thing to
    record. Listed to be decided, not proposed.

31. **May a Custom Resource name a `ClusterIssuer`, and may its author add DNS
    names to what the operator generates?** A namespaced `Issuer` resolves in
    the Certificate's own namespace and therefore cannot cross one; a
    `ClusterIssuer` fronts a cluster-wide CA, and with an unfiltered
    extra-name list an author who can write one resource obtains a valid
    certificate for a hostname they do not own — which is what the precedent
    does today (finding R). The candidates: **`Issuer` only**, which puts a CA
    private key in every tenant namespace, a worse distribution problem than
    the one it solves; **`ClusterIssuer` allowed with an operator-side issuer
    allowlist**, which is a second piece of operator configuration nobody
    edits until it is wrong; **`ClusterIssuer` allowed with no extra-name
    field at all**, so the generated names are the Service's and nothing else,
    which forecloses the bypass and forecloses a legitimate additional name;
    **cert-manager's approver-policy as a documented prerequisite**, which
    moves the control outside this product and outside its threat model.
    Listed to be decided, not proposed.

32. **If s3eo ships a network policy, what names the peers — and what enforces
    it in the test cluster?** This is the actionable half of existing question
    3 and it has two parts that have to be answered together, because the
    second decides whether the first can ever be tested (finding S). Neither
    part has an obviously right default: a product whose purpose is to be
    talked to cannot ship a deny-all, and a policy with an open peer set is
    the blanket grant ADR 0030 D1 declined to ship. The peer candidates: **no
    policy at all**, reading D1 as binding on the product and not only on the
    chart, which costs nothing to build, keeps `networkpolicies` out of the
    operator's RBAC, and leaves the unauthenticated monitoring listener as
    exposed as it is today (ADR 0030 D2); **an explicit list of client peers
    on the resource as namespace-local selectors**, which costs a peer API
    with its own compatibility rules and is wrong from the moment a client
    workload moves or is relabelled; **a single label the administrator puts
    on client pods**, one field instead of a list, at the price that anything
    wearing the label is admitted and nothing in the resource records who that
    turned out to be; **a policy over the non-S3 ports only** — the metrics
    and health ports, which is where D2's residual risk actually sits —
    leaving the data port to the administrator, which is the smallest useful
    policy and the one whose peer set the operator can genuinely know. The
    enforcement candidates: **`disableDefaultCNI: true` plus a
    policy-enforcing CNI in the same kind step that is about to gain
    cert-manager**, which is a second bring-up dependency and more minutes on
    a job already budgeted at forty-five; or **the written statement that the
    feature ships unenforced and untested**, which is a documentation decision
    rather than a testing one and is the position ADR 0030 already holds about
    controls this project cannot aim. Listed to be decided, not proposed.

33. **What serves the operator's own metrics, and on what address?** Finding U
    is why this cannot be left to a library default. The subject is not the
    proxies s3eo provisions — the chart already ships a ServiceMonitor, a
    PrometheusRule, a Grafana dashboard and a monitoring Service — but the
    reconcile, workqueue and Go-runtime metrics of the operator binary, which
    controller-runtime registers whether or not anybody decided to expose
    them. The candidates: **secure serving with controller-runtime's
    authentication and authorisation filter**, which costs a token review and
    a subject access review per scrape, a serving certificate, and RBAC the
    scraper must hold; **a loopback bind**, which costs every in-cluster
    scrape and leaves port-forwarding as the only reader, the answer this
    repository already took for pprof (`internal/config/config.go:634-641`);
    **an open bind on the pod IP with the boundary left to the
    administrator**, which is ADR 0030 D1 and D2 applied to a second binary
    and reopens whether that rule is about charts or about this product; **off
    entirely**, which costs the only view anybody has of a stuck or hot
    reconcile loop. Whichever is taken, the value has to reach the manager's
    options and be asserted somewhere, or the flag is decoration. Listed to be
    decided, not proposed.

34. **How many replicas does the operator run, and what does a standby hold?**
    One replica makes provisioning and drift correction cluster-wide dependent
    on one pod — running proxies keep serving, which is the correct failure
    mode and is an availability property to write down rather than assume.
    More than one needs leader election, and the cost of getting it wrong is
    not the precedent's: that operator only reads Secrets, so two racing
    controllers duplicate reads, while s3eo mints the client credential and
    two controllers each generate a different random pair and each write it,
    with the last writer's Secret mounted while the other's may already sit in
    a rendered configuration (finding T). *Not verified by experiment here,
    but* controller-runtime starts the informer cache with the manager rather
    than with leadership, so a standby that reconciles nothing still holds
    everything it watches — which makes question 21's answer apply to the
    standby too. The candidates are one replica with leader election on, so a
    second can be added without changing anything; one replica with it off,
    which is honest about the topology and has to be turned on before a second
    exists; and two or more from the start, which pays the lease and the
    standby's cache for an availability property nothing has asked for. Also
    to settle in the same breath: whether the reconcile performs any blocking
    I/O outside the apiserver, because the library's default concurrency of
    one is defensible if it does not and is a denial of service one namespace
    can trigger if it does — the precedent leaves it at one while its
    reconcile dials workload pods with a blocking dial
    (valkey-operator/`cmd/main.go:87-92` with
    `internal/controller/valkey_controller.go:1684-1699`, and the dial at
    `internal/valkeyclient/client.go:390-393`). Listed to be decided, not
    proposed.

35. **What does an s3eo test suite consist of, where does it run, and what
    does each shape prove?** Finding AE is the cost. **The blocker this
    question named is gone.** D-C makes the licence copy product behaviour
    rather than suite scaffolding: a multi-namespace run creates one Secret in
    the operator's own namespace and the operator performs the N copies, where
    today `test/e2e/velero/e2e-up.sh:46-54` aborts the bring-up unless a token
    is present and `:171-173` creates exactly one `s3ep-license` Secret in one
    namespace. The copy becomes something a suite asserts rather than
    arranges, and it brings a second assertion that is cheap because it is
    apiserver-side — that D-A's policy actually refuses a Secret write
    carrying no controller `ownerReference`, since a policy nobody has watched
    deny anything is decoration. What is open is the shape and the venue, and
    the remaining costs are cert-manager and the CNI decision, not the
    licence. The candidates: **envtest only** — a controller suite against a
    real apiserver with no proxy pod anywhere, proving reconcile logic, schema
    validation and ownership, needing no image, no cluster and no licence, and
    proving nothing about a provisioned instance; **envtest plus one kind job
    provisioning a single instance in a single namespace**, the smallest shape
    that proves an instance actually serves, at the cost of a second kind
    bring-up beside the forty-five-minute Velero job on the same self-hosted
    pool, sharing a Docker daemon, a disk and a host port space; **a
    multi-namespace kind suite**, the only shape that tests the cluster-scoped
    operator as designed, and the only one that exercises the N copies D-C
    promises, needing cert-manager and a CNI decision if policies ship; **a
    kind suite pinned to the `exit` provider**, which needs no licence and
    exercises none of the encryption the product exists for. Two constraints
    sit on every candidate: envtest pins a Kubernetes version separately from
    any node image, so a schema validated against 1.29 is validated on a
    server older than the product targets, and the precedent even resolves
    envtest assets for its own `-short` run, which is hermetic here today; and
    the repository's convention gives one tool one suite and one job named
    `E2E <tool> (<backend>)`, with a required-check context that is not in
    this repository and must be added after the workflow merges or every pull
    request waits on a check that never reports. Listed to be decided, not
    proposed.
36. **One Go module or two?** Sharing `go.mod` hands the proxy's `gosec`,
    `govulncheck`, coverage merge and image build the whole Kubernetes client
    graph, against a module that today requires none of it. The cost is not
    hypothetical on the security jobs: the `gosec` job already pins
    `GOMAXPROCS: 4` on self-hosted runners because the Go runtime sizes its
    thread pool from the host's CPU count rather than the pod's limits, so
    gosec's parallel package load forks `go list` into the pod's process limit
    and fails with `EAGAIN`, which it reports as "package has type errors,
    skipping SSA analysis", prints zero issues, and exits 1 — observed twice
    on 2026-09-11 with different package counts each time, which is what gives
    it away as load-dependent (`.github/workflows/test-pipeline.yml:152-170`).
    Adding several hundred packages to what that job walks is a change to an
    already-bounded resource, and the durable fix named in that comment lives
    in the runner configuration rather than in this repository. A second
    `go.mod` isolates the graph and splits every `./...` target, the lint
    configuration and the coverage story. Listed to be decided, not proposed.

37. **Does cert-manager replace the generated test PKI or sit beside it?**
    Section 4 is the shape. `test/ssl-setup/gen-certs.sh` emits one leaf
    covering the compose stack, the kind cluster's Service names and
    `IP.1 = 127.0.0.1` (`:60-76`), consumed by nine files of which eight have
    no Kubernetes near them, while the chart's Certificate templates emit
    `dnsNames` and no `ipAddresses` and the Velero suite reaches the proxy at
    `https://127.0.0.1:30443` from the host. The candidates: **cert-manager
    beside the generated PKI, as a second values case exercising the chart's
    cert-manager arm alongside the bring-your-own one**, which keeps ADR 0026
    D4's arm under a run and costs a second install path in the same bring-up;
    **cert-manager replacing the kind half only**, which needs either an
    `ipAddresses` field on the Certificate template — and then on the resource
    — or the suite reaching the proxy by a DNS name instead of a loopback
    address; **cert-manager replacing nothing and being installed only to
    prove it installs**, which is the cheapest and proves the least. Riding
    along: whether the run asserts a renewal at all, given that a long-lived
    test CA means no run ever observes one and a green gate would claim more
    than it tested. Riding along since 2026-09-16: D-A's policy requires
    `object.type == "Opaque"` on every Secret the operator writes, which
    forecloses the fallback this question would otherwise reach for. If
    cert-manager is rejected for the kind setup or for a customer install, the
    obvious alternative is the operator minting the listener certificate
    itself — and that is a `kubernetes.io/tls` Secret, which the type clause
    refuses. Either that fallback is out, or the clause acquires a second,
    enumerated exception alongside the name set, which is the same deliberate
    act the name-set rule already demands. Listed to be decided, not proposed.
38. **Which word does each reader get?** A program named the operator and a
    human called the operator share one word across 265 counted occurrences,
    and the collision is not cosmetic in the one place it matters: the
    trust-boundary table at `SECURITY_ARCHITECTURE.md:89` defines a role of
    that name as whoever writes the proxy configuration and holds the KEK
    material, which is a description of what the program would do (finding
    AI). The candidates: **keep "operator" for the human and give the program
    a name of its own** — the controller, or `s3eo` — which costs nothing in
    the existing tree and contradicts the word the CRD, the chart name, the
    Kubernetes ecosystem and this ticket's own title use, so every external
    reader translates on arrival; **keep "operator" for the program and rename
    the human to "administrator"**, which costs a sweep of 236 occurrences
    under `docs/`, contradicts the name of `docs/operations/` and the sentence
    that opens it, and rewrites the role name in the trust-boundary table;
    **split by document**, the human under `docs/operations/` and the program
    under `docs/developer/`, which costs least to write and fails in the one
    document that holds both readers, where two roles of the same name would
    sit in one table; **disambiguate only where both appear in one passage**,
    which costs nothing up front and is invisible to a reader who arrives at a
    single passage, which is how the security architecture is read. It has to
    be settled before the ADRs of the decision block are written, because an
    ADR names the product's own vocabulary exactly (ADR 0022 D8) and the scope
    ADR would be the first document to use the word in its new sense. It also
    settles existing question 3 as a side effect, since that question exists
    because the word is overloaded. Listed to be decided, not proposed.

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
- **The operator's own reach is not the Custom Resource's reach.** "No
  cross-namespace references" constrains what a resource's author can name;
  the controller's ClusterRole is a second and wider boundary.
  `SECURITY_ARCHITECTURE.md` section 2 carries **neither** entry today — the
  roles table at `:85` lists the human operator, the S3 client, the proxy
  process, the S3 backend and the two network legs — so both have to be added
  as separate rows rather than one, and nothing may be written that lets the
  first be mistaken for the second.
- **The provisioned pod gains no API-server token it has never needed.** The
  chart gives it no Role, no RoleBinding and
  `automountServiceAccountToken: false`
  (`deploy/helm/s3-encryption-proxy/templates/serviceaccount.yaml:12`), and
  the process behind that ServiceAccount is the one holding the KEK in memory.
- **No reconcile may produce a pod that is killed inside its own drain.** The
  termination grace period has to cover the pre-stop hold plus
  `shutdown_timeout` plus the listener close and process exit, because
  otherwise the multipart sweep of ADR 0029 D1 never runs and every upload the
  process holds is left open at the backend (ADR 0029 D2, D3) — unreachable
  storage nothing but a lifecycle rule collects (ADR 0029 D6). How that
  relation is expressed is question 28's neighbour; that it must hold is not
  open.
- **A credential reaches the process through its environment or an expanded
  reference and through nothing else.** The loader expands `${VAR}` in exactly
  three groups (`internal/config/envexpand.go:55-101`) and refuses an unset or
  empty one naming the field (`:30-33`). There is no argv path and no
  placeholder-file path in this product, so neither is a mechanism to build.
- **The operator may not be softer than the product it provisions.** The
  loader refuses an unset or empty credential reference at startup; an
  operator that renders an empty credential and lets the pod start would
  accept what the proxy refuses.
- **No reconcile may make a stored object unreadable as a side effect of an
  edit about something else.** Removing a provider makes every object wrapped
  by it permanently unreadable (ADR 0002 D7), and a provider that wrote
  existing objects must stay configured alongside the exit provider or those
  objects become unreadable (ADR 0025 D4) — while the alias is a local label
  that is never stored, so the constraint binds key material and not names
  (ADR 0002 D8). The operator is the first actor in this product able to do
  this automatically.
- **The metadata prefix is not a per-instance value, and the consequence is
  worse than unreadability.** ADR 0009's residual risks record that changing
  one valid prefix to another is undetectable at startup, and that under the
  exit provider a renamed prefix hands the client the ciphertext behind a
  `200 OK` together with the `x-amz-meta-*` keys the old prefix carries — the
  wrapped data key among them
  (`docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md:174-184`).
  That is key material handed out, not just an object lost.
- **Every provisioned instance under an encrypting provider holds a valid
  licence before it serves anything.** The gate is part of configuration
  validation and its failure is fatal, with no degraded and no grace-period
  mode (ADR 0016 D1); `exit` is the one provider type admitted without one
  (ADR 0025 D2), and it writes plaintext.
- **A Custom Resource may not be described as a tenancy boundary while nothing
  enforces one.** `SECURITY_ARCHITECTURE.md:90` states outright that there is
  no per-client bucket or prefix scoping, and `ListBuckets` is forwarded
  unfiltered (`internal/proxy/handlers/root/handler.go:66-101`). Whether to
  build the scope is existing question 12; what may be claimed while it is
  unbuilt is not open.
- **cert-manager stays optional.** ADR 0026 D4 makes bringing your own
  certificate a first-class arm precisely so cert-manager is not required, and
  an end-to-end suite that installs it must exercise the cert-manager arm **in
  addition to** the bring-your-own arm, never instead of it.
- **The operator holds no verb on `admissionregistration.k8s.io` beyond read,
  and none at all on `rbac.authorization.k8s.io`.** Whether it holds even
  `get`, `list` and `watch` on the first is open inside question 14; what is
  not open is the ceiling. D-A's bound is a cluster-scoped object the
  operator's own identity must not be able to delete, re-scope or neuter —
  editing `matchConditions` so its username no longer matches, excluding a
  namespace through the binding's `namespaceSelector`, flipping
  `validationActions` from `[Deny]`, or flipping `failurePolicy` from `Fail`
  to `Ignore` each converts the bound into decoration. `escalate` and `bind`
  on roles are the same hole one step out, and finding L is the precedent that
  they enter once and are never revisited.
- **No `create` on `serviceaccounts/token`, and no `delete` or
  `deletecollection` on `secrets`.** An identity-scoped policy is only as
  strong as the operator's inability to become somebody else, and cleanup is
  the garbage collector's job through the controller `ownerReference` D-A
  already requires, not a verb. Acquiring either is a change to D-A, not a
  detail of an implementation.
- **Every Secret the operator writes carries a controller `ownerReference`, a
  name from the closed, enumerated set, and `type: Opaque`.** Two shapes exist
  today — the minted proxy client credential and D-C's licence copy — and
  those three clauses are what actually constrain the reachable name space and
  the reachable Secret types; the type clause in particular is what keeps
  `create secrets` in every namespace from being a service-account token in
  every namespace. Adding a third shape, or a type exception, widens the bound
  and is a deliberate act with its own line in `SECURITY_ARCHITECTURE.md`,
  never a side effect of a feature needing somewhere to put a value.
- **The policy's owner clause is group-pinned and version-agnostic.** An
  `ownerReference` keeps the `apiVersion` its writer used, so pinning the
  clause to one version means the operator silently loses the ability to
  update the credentials of its own longest-serving instances the moment
  question 16 takes a served-version answer; matching on `kind` alone is the
  opposite error, because `kind` is not unique across groups.
- **A licence copy's `ownerReference` is not a precedent for a KEK Secret's.**
  The cascade is correct for a licence — deleting a copy destroys nothing,
  loses access to no byte, and the remedy is another copy — and catastrophic
  for key material, where deleting the Secret makes every object that instance
  wrote permanently unreadable. The existing rule that key material outlives
  the resource that provisioned it stands unchanged, and question 7 is neither
  answered nor narrowed by D-C.
- **The operator renders exactly one licence route, and it is the file.** ADR
  0016 D6 makes `S3EP_LICENSE_TOKEN` the route the licence reaches every
  environment by and keeps `license_file` as "the on-disk route for a
  deployment that mounts the token as a file"
  (`docs/adr/0016-the-license-is-a-startup-gate.md:110-114`) — which is the
  permission this takes, not a departure from it. `LoadLicense` reads the
  variable before the file (`internal/license/validator.go:372-389`,
  `:332-341`), so rendering both makes the environment win silently and
  reproduces the "which one do I rotate" failure the same ADR closed as a
  residual-risk item on 2026-09-14 (`:226-235`). The copy is projected as a
  file and the rendered configuration names it, exactly as
  `templates/configmap.yaml:10-11` with `templates/deployment.yaml:137-141`
  and `:157-168` already do.
- **No schema tightening may make an existing tenant resource undeletable.**
  Validation ratcheting is what keeps a bound added later from failing the
  operator's own finalizer write on a stored resource that violates it
  (finding AJ, Kubernetes semantics); any deliberate departure from that — a
  rule the operator evaluates itself, a conversion that rewrites stored fields
  — has to keep the deletion path valid, because a resource that cannot be
  deleted takes its namespace with it.
- **A CEL rule may not become a second, quieter home for a refusal the loader
  already makes.** Where both exist they must agree, and the drift between
  them is a test's job, not a reviewer's: the loader writes its bounds as
  literals inside error messages, so the comparison needs named constants
  before it can be mechanical.
- **There is no keyless AWS path and an operator cannot add one.** The only
  credential construction outside the test tree is
  `credentials.NewStaticCredentialsProvider(...)` with an empty session token
  (`internal/proxy/server.go:113`); there is no default-config load, no STS
  assume-role and no web identity anywhere in non-test code; and
  `S3BackendConfig` carries no session-token field
  (`internal/config/config.go:29-35`), so adding one is a configuration key
  change under ADR 0013 D11. Even with both, the configuration is read once,
  so an injected temporary credential expires while the process still holds it
  — s3eo may not present a capability the proxy does not have.

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
- [ ] What a Custom Resource's status may claim beyond the Deployment's
      readiness is decided. (Rewritten 2026-09-16: what `Ready` claims is no
      longer open — ADR 0034 D3 and D5 decide that a probe depends on nothing
      outside the process.)
- [ ] What `/status` may carry, and what of it may reach a Custom Resource's
      status, is decided. (Rewritten 2026-09-16: the box named `/version`, which
      no longer exists.)
- [ ] The operator's scope — one cluster-scoped controller, namespaced Custom
      Resources — is decided and recorded in an ADR, in the session the
      decision was taken (ADR 0022 D2).
- [ ] The no-cross-namespace rule is recorded with what it forbids: a Secret,
      a ConfigMap or a backend outside the resource's own namespace, and the
      fact that it constrains the resource's author and not the controller.
- [ ] Reading a Secret that holds backend credentials and writing the proxy's
      own client credentials back as a Secret are each in
      `SECURITY_ARCHITECTURE.md` as a privilege with its blast radius, before
      any code exists.
- [x] The ADR numbering is settled: 0036 went to the high-availability work
      and 0037 to the backend-trust work, both on 2026-09-18, so the two ADRs
      owed here start at 0038 — re-checked against `docs/adr/` before use.
- [ ] The word the trust-boundary table uses for the human is decided, and
      `SECURITY_ARCHITECTURE.md:89` either carries the program as a second
      role or renames the first.
- [ ] cert-manager in the kind end-to-end setup is recorded, and ADR 0026's
      stated gap — the cert-manager arm ships with a render test and no run —
      is amended or closed in the same change.
- [ ] What the operator's ServiceAccount may hold cluster-wide is decided per
      verb and per resource, `secrets`, `configmaps` and `deployments`
      included, and written into `SECURITY_ARCHITECTURE.md` rather than only
      into a ClusterRole.
- [ ] Where a provisioned instance's licence comes from is decided, and the
      end-to-end bring-up's one-Secret assumption is either generalised or
      recorded as a limit of the suite.
- [ ] Whether a CRD change carries the breaking marker under ADR 0018 D5 is
      decided, and D5 is amended in place if the answer narrows it (ADR 0022
      D9).
- [ ] What enforces a pod security standard on a namespace the operator writes
      a Deployment into is decided, or the absence is stated in the privilege
      footprint as a node-level grant.
- [ ] Whether the resource ever names the KEK Secret is decided, and one KEK
      per cluster versus one per namespace is decided with the shared-bucket
      consequence written down.
- [ ] The certificate reload gap is owned: either a proxy-side callback is
      scheduled, or the expiry is documented as a known limitation of every
      deployment path.
- [ ] The operator's own metrics listener has a decided address and a decided
      authentication posture, asserted somewhere, so the flag is not
      decoration.
- [ ] A determinism check exists for the rendered pod template, or the resync
      interval is recorded as a restart schedule.
- [ ] The operator's test layers are decided, and if a new end-to-end job
      gates the release, its context is on the required-check list in branch
      protection after the workflow merges.
- [ ] The `ValidatingAdmissionPolicy` and its binding exist — as chart
      templates or as a documented administrator step — and which of the two
      is decided and recorded (question 39).
- [ ] The policy carries all five clauses: the username `matchCondition`, the
      group-pinned controller `ownerReference` on `object`, the closed name
      set, `type == "Opaque"`, and the `oldObject` adoption refusal on
      `UPDATE`; a render test asserts each is present, because four of the
      five are silent when omitted.
- [ ] `failurePolicy: Fail` and `validationActions: [Deny]` are asserted
      rather than assumed, and the fleet-wide stall that `Fail` implies is
      written into the privilege footprint as its accepted cost.
- [ ] An end-to-end case attempts each forbidden Secret write with the
      operator's own token — no owner reference, a foreign name, an adoption
      update, a non-`Opaque` type — and asserts the refusal, and one further
      case asserts that the legitimate write still succeeds.
- [ ] The operator's ClusterRole is asserted by a test over the rendered chart
      to carry no verb on `rbac.authorization.k8s.io`, nothing beyond read on
      `admissionregistration.k8s.io`, no `create` on `serviceaccounts/token`,
      and no `delete` or `deletecollection` on `secrets`.
- [ ] `<crd-plural>/finalizers` `update` is either granted or
      `blockOwnerDeletion: false` is set deliberately, and which one, with the
      reason, is recorded (finding AK).
- [ ] The unbounded cluster-wide Secret read and the forged-`ownerReference`
      weakness are each in `SECURITY_ARCHITECTURE.md` as an accepted residual
      risk with its mitigation named, before any code exists.
- [ ] Whether the commercial terms permit one token across many namespaces is
      answered by a named owner and recorded at the top of the licence ADR as
      a blocking item; what a refusal does to D-C is decided by the owner at
      that point, not assumed here.
- [ ] Renewal behaviour is decided and written down: the operator either
      computes its own annotation over the licence copy and rolls, or it does
      not and the no-op until expiry is recorded as the product's behaviour
      (finding AL).
- [ ] The CRD-to-loader drift check exists over the leaf set, the defaults and
      the bounds, and the operator's own client requests strict field
      validation so a pruned field is at least a warning it can report.
- [ ] This ticket is archived, its decisions extracted into ADRs first.
39. **Who installs the `ValidatingAdmissionPolicy` and its binding, and what
    happens if nobody does?** D-A's bound is two cluster-scoped objects that
    are neither the operator nor the chart it provisions. The candidates:
    **the operator's own chart ships both**, so the bound is present by
    construction and `helm install` is one act, at the price that the
    installing human needs `create` on `validatingadmissionpolicies` and
    `validatingadmissionpolicybindings` — a cluster-wide verb they already
    need for the ClusterRole, so it costs nothing new — and the objects are
    then release resources that `helm uninstall` removes, which
    `helm.sh/resource-policy: keep` prevents at the cost of orphans; **the
    cluster administrator installs them out of band**, which has one silent
    failure mode that is the whole hazard, nobody installs them and the
    operator runs with a cluster-wide Secret write and no bound at all. The
    mitigation under either is the read-only `admissionregistration.k8s.io`
    verb set that question 14 leaves open, with the operator refusing to
    serve, or reporting `Ready=False` with a named reason, when its own
    binding is absent or its `validationActions` is not `[Deny]` — so 39 and
    that half of 14 are answered together or neither is. Two things are
    settled rather than hedged, Kubernetes semantics at moderate-high
    confidence: creating a binding carries no RBAC-`escalate`-style
    authorisation check, since `escalate` and `bind` are specific to
    `rbac.authorization.k8s.io` resources; and there is no Helm
    uninstall-ordering window of the shape it is tempting to fear, because the
    ClusterRoleBinding, the ServiceAccount and the operator's Deployment are
    in the same release and a projected ServiceAccount token is pod-bound.
    Listed to be decided, not proposed.
40. **Does an instance whose active provider is `exit` get a licence copy
    anyway?** D-C as decided copies the token into each provisioned namespace,
    and one class of instance needs no token at all: `ValidateProviderType`
    refuses every provider type but `exit` when no valid licence is held
    (`internal/license/validator.go:152-165`), and the gate examines only the
    provider the active alias names (`internal/config/config.go:786-800`),
    which ADR 0025 D2 states as the product's intent — the exit provider
    requires no licence, and a configuration with `exit` active starts without
    one even while an encrypting provider stays registered
    (`docs/adr/0025-leaving-is-a-supported-mode.md:58-61`). The condition is
    computable from the resource's own spec at reconcile time, so both answers
    are buildable. The candidates: **copy unconditionally**, which is one code
    path, makes the Secret's presence independent of a spec field a user may
    edit, and widens the population holding licence material to every
    namespace with a resource in it, including ones that can never use it;
    **copy only where the active provider needs one**, which narrows that
    population at the cost of a copy whose existence depends on a spec field,
    so a resource edited from `exit` to `aes` needs the copy written in the
    same reconcile pass before the Deployment rolls, or it produces a pod that
    fails the startup gate with a message about licensing rather than about
    the edit; **copy unconditionally and delete on transition to `exit`**,
    which keeps the write path simple and adds a removal the garbage collector
    will not do for it, since the `ownerReference` tracks the resource and not
    the provider. Whichever is chosen decides what the accepted residual risk
    about licence distribution may name as a mitigation; today it names only
    the per-resource copy and its controller `ownerReference`. Listed to be
    decided, not proposed.
