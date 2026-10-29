# Operational security: what the deployment can undo

A correct proxy with a configuration that never reached it is not a correct
deployment. This page carries the two places where the operational layer — the
chart and the published defaults — decides something the code cannot. A licence
expiry was a third, and stopped the data path in both directions; the proxy
checks no licence any more, so nothing on a calendar can stop it
([ADR 0040](../adr/0040-the-proxy-is-apache-licensed-and-checks-no-license.md)).

## A configuration change has to reach the pods

Everything that decides how the proxy encrypts lives in one string: the active
provider alias and the key material. The pod template hashes the rendered
ConfigMap and the rendered Secret
([deployment.yaml:17-28](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L17)),
so a configuration change and a rotated credential both roll the pods.

What is still invisible to the chart, and therefore still needs a manual
`kubectl rollout restart deployment/<release>-s3-encryption-proxy`, is an
externally managed ConfigMap (`configMap.useExistingConfigMap: true`) or a
Secret the operator manages themselves: the chart cannot hash what it does not
render.

Until 2026-09-11 the template rendered only `.Values.podAnnotations` and carried
**no `checksum/config` annotation**, so `helm upgrade` with a changed `config`
string updated the ConfigMap, reported success, and left the old pods running
the old configuration. An operator who rotated a KEK and was told the rotation
had succeeded, while the old key was still encrypting every new object, was
handed a false statement about the security of their data by the deployment
tooling — rule 2, precisely.

Related, and fixed with it: turning TLS on used to require rewriting both probe
blocks by hand, and a pod whose probes stayed on plaintext never became Ready —
which pushed operators towards running the proxy without TLS. The scheme is
derived from the configuration the pod receives now, and `serviceTLS`
([ADR 0026](../adr/0026-the-proxy-terminates-tls-at-its-own-service.md)) turns
the listener on without touching a probe block at all.

## A published chart default that was a working key

Historic, fixed on this branch, recorded because anyone who installed the chart
before it is affected. `deploy/helm/s3-encryption-proxy/values.yaml` shipped
`aes_key: "0123456789abcdef0123456789abcdef"` as the default provider key, and
`values-monitoring.yaml` shipped a real base64 AES-256 key. **Any `helm install`
that did not override the value encrypted every object with a key published in
this repository.** Both are now `${S3EP_AES_KEY}` environment references.

If a deployment ever ran with either value: treat every object written under it
as compromised, configure a new KEK, re-write the data through the proxy, and
only then remove the old provider.

## What this does not cover

### H-4 Velero kopia repositories default to a published password

**Operator action required. Upstream, not a proxy defect.**

Velero creates the `velero-repo-credentials` secret with the well-known default
password **`static-passw0rd`** unless the operator sets it **before the first
backup**
([velero#6443](https://github.com/vmware-tanzu/velero/issues/6443),
[velero#8137](https://github.com/vmware-tanzu/velero/issues/8137)).

With the default, kopia AES-GCM and its content HMACs are **forgeable by anyone
who can read the bucket**, because the repository salt sits in
`kopia.repository` in the same bucket. Kopia is then neither confidentiality nor
integrity against this backend. The objects Velero writes itself — resource
tarballs including Secrets, backup logs, results — are never encrypted by Velero
at all.

That leaves the proxy as the only protection for both. The proxy does hold up
its end — kopia's ranged reads are verified segment by segment
([what a ranged read proves](stored-objects.md#what-a-ranged-read-proves)) — but
a second layer that is decoration is still worth fixing: a strong repository
password makes kopia's own encryption real rather than a published default.

**Create `velero-repo-credentials` with a strong random value before the first
backup.** Changing it later does not re-key an existing repository.
