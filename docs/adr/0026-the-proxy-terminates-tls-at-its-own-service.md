# ADR 0026: The proxy terminates TLS at its own Service

## Status

**Accepted.** Date: 2026-09-11. Owner decision the same day: it ships in 5.0.0.

**Implemented on the 5.0.0 branch**, in the chart round that closed
[ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md)'s deployment half. The chart
issues or accepts a certificate for the in-cluster Service names, mounts it, and turns the proxy's
own listener on; the end-to-end suite runs on the bring-your-own arm of it.

**Not covered by a run:** the cert-manager arm. The end-to-end cluster has no cert-manager, so
that arm is exercised by rendering only. It is a real gap and is named here rather than left to be
discovered.

## Context

The deployment this product is actually used in is not an Ingress. It is **one proxy beside each
S3 client, inside the cluster**: Velero in a namespace, a proxy next to it, the client reaching it
at `s3ep-proxy.<namespace>.svc.cluster.local`. Every client gets its own proxy, and the traffic
between them never leaves the cluster.

That traffic carries the client's S3 credentials in a Signature V4 header and every object key in
a URL, and — on the client side of the proxy — the plaintext of every object. Under
[ADR 0001](0001-the-backend-is-hostile.md) the backend is hostile; the cluster network is not the
same threat, but it is not a private channel either. A proxy that decrypts objects and hands them
over a plaintext Service has moved the exposure rather than removed it.

The proxy has been able to serve TLS since before this decision: `tls.enabled`, `tls.cert_file`
and `tls.key_file` in its own configuration. **The chart could not.** It had no `tls` value of any
kind. The only way to turn the listener on was to write the certificate paths into the raw
`config` string by hand and mount the secret through the chart's generic `volumes` and
`volumeMounts` — which is exactly what the end-to-end suite does, and has done for as long as it
has existed. A workaround that has been in the tree that long is not a workaround; it is the
missing feature, being paid for over and over.

The reason it stayed missing was one technical objection, recorded when the chart round was
scoped: injecting certificate paths into the configuration string would make the chart **rewrite
the operator's YAML**. That objection is real and this decision does not dismiss it — it answers
it (D3).

## Decision

**D1. The chart can give the proxy its own TLS listener, and it is off by default.** One values
block, `serviceTLS`, turns it on. Nothing changes for a deployment that does not set it.

**D2. The certificate covers the Service names the chart itself computes**, not names an operator
has to keep in sync with the release. Four of them, from the release and the namespace:
`<fullname>`, `<fullname>.<namespace>`, `<fullname>.<namespace>.svc` and
`<fullname>.<namespace>.svc.<clusterDomain>`. An operator may add more; they may not replace
these. A name the Service actually answers to and the certificate does not is a failure the
operator only sees when a client refuses the connection.

**D3. The chart adds the `tls:` block to the rendered configuration; it never edits what the
operator wrote.** The ConfigMap template already prepends a key this way — `license_file` — so the
mechanism is not new. The one hazard is a duplicate key, and it is closed by refusing rather than
by merging: **if `serviceTLS` is enabled and the operator's own `config` already carries a `tls`
key, the render fails and says so.** Two sources for one setting is how the trap gets rebuilt; the
chart takes the setting or the operator does, never both.

**D4. Bringing your own certificate is a first-class arm, not a fallback.** `existingSecret` names
a Secret holding `tls.crt` and `tls.key`; the chart mounts it and issues nothing. cert-manager is
then not required at all, which matters for clusters that do not run it and for a certificate
minted by something else.

**D5. Enabling it without a way to get a certificate is a startup-time failure, made a
render-time one.** `serviceTLS.enabled` with neither `existingSecret` nor an issuer name refuses
the render and names both values. Without this the pod starts, fails to read its certificate and
crashloops, and the reason is in a log nobody is watching.

**D6. The probe scheme follows the chart's decision as well as the operator's.** The scheme is
derived from whether the listener speaks TLS, which is now two things: `tls.enabled` inside the
operator's `config`, or `serviceTLS.enabled`. A derivation that only looked at the first would
probe a TLS listener in plaintext, and the pod would never become Ready — the original defect this
project already fixed once, reintroduced through the new door.

**D7. A pod that mounts the certificate is a consumer of it.** The chart refuses a cert-manager
`Certificate` that nothing consumes; with this decision the pod becomes the second thing that can
consume one, beside an `ingress.tls` entry.

**D8. The Ingress is not replaced and not deprecated.** Terminating TLS at an Ingress stays
supported and keeps its own values. The two are independent: a deployment may do both, and one
that does neither is refused only if it *claims* to do one.

## Consequences

An operator who wants in-cluster TLS sets four lines instead of hand-writing a volume, a volume
mount and three configuration lines whose paths have to agree. The names on the certificate cannot
drift from the Service, because neither is written down twice.

The `clusterDomain` value is new and is `cluster.local`. A cluster built on another domain has to
set it; the chart cannot discover it, and guessing would produce a certificate that fails
verification for the one name most clients use.

The end-to-end suite stops carrying its hand-rolled TLS and uses the feature, which is what puts
the bring-your-own arm under test on every run. Its CA mount stays manual and moves to a path of
its own: that mount is for the **backend** leg — `SSL_CERT_FILE`, so the proxy verifies MinIO for
real — and has nothing to do with the listener.

The cert-manager arm ships with a render test and no run. Two ways to close that later, neither
scheduled: install cert-manager in the end-to-end cluster, or add a second cluster profile that
does. Until one of them happens, this ADR's status block is where the gap is recorded.

## Alternatives rejected

- **Leave it to `volumes`, `volumeMounts` and the raw `config` string.** This is the status quo,
  and the end-to-end suite is the evidence against it: the same eight lines, in every deployment
  that wants TLS, with three paths that have to agree and nothing checking that they do.
- **A second values key for the scheme instead of deriving it.** Rejected for the same reason the
  probe derivation was written in the first place: two sources of truth for "is this listener TLS"
  drift, and the one that loses is the one nobody looks at.
- **Merge the operator's `tls:` block with the chart's.** Rejected by D3. A merge has to decide
  which side wins per key, that decision is invisible in the values file, and the failure it
  produces is a proxy serving with a certificate the operator did not think they had configured.
- **Discover the cluster domain at render time.** Helm cannot; a lookup would need a live cluster
  and would make `helm template` behave differently from `helm install`.
- **Issue the certificate for a wildcard.** Rejected: a wildcard over `*.<namespace>.svc` covers
  every service in the namespace, which is a certificate the proxy has no business holding.
