# Tenancy and privilege: the blast radius

What one compromised object, one compromised client and one compromised process
each cost. Read with [the threat model](threat-model.md): the roles table there
says who is trusted for what, and this page says what that trust is worth in
practice.

## What the design gives you

- **Object isolation.** Every object has its own DEK. Compromising one DEK
  compromises one object. Recovering the KEK compromises all of them.
- **Provider isolation.** Several KEK providers can be configured at once. Each
  object records the fingerprint of the KEK that wrapped its DEK, so objects
  written under an older provider stay readable while new writes use the active
  one ([KEK rotation](key-management.md#kek-rotation-by-fingerprint)).
- **Client authentication.** A request without a valid SigV4 signature over a
  configured `s3_clients` credential never reaches a handler
  ([router.go:70-83](../../internal/proxy/router.go#L70)).
- **Metadata isolation, both ways.** The `s3ep-*` keys are stripped from every
  client response, and a client cannot write into that namespace: a request that
  carries one is refused with `400 InvalidArgument`
  ([object metadata](stored-objects.md#what-is-written-into-s3-object-metadata)).

## What the proxy can do to the backend bucket

The proxy holds one static backend credential and needs it to be broad. The
operations it actually issues are:

<details>
<summary>Backend operations the proxy calls (from <code>S3BackendInterface</code>)</summary>

| Operation | Why the proxy needs it |
|---|---|
| `ListBuckets`, `CreateBucket`, `DeleteBucket` | Bucket CRUD proxied for the client. Note the destructive pair: a bug in sub-resource routing once made `DELETE /bucket?encryption` delete the bucket — fixed by the allowlist at [handler.go:99-133](../../internal/proxy/handlers/bucket/handler.go#L99) |
| `ListObjectsV2`, `ListObjects`, `HeadBucket` | Listings, and `HEAD /bucket`, which is the real operation since 2026-09-10 ([operations.go:130-155](../../internal/proxy/handlers/bucket/operations.go#L130)). The `ListObjectsV2` probe with `MaxKeys=0` it replaced answered `200` for a bucket that does not exist, because the backend short-circuits the listing before it checks the bucket |
| `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `DeleteObjects` | The object data path |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` | Both the client-driven multipart path and the internal multipart producer |
| `GetObjectTorrent` | Passed through verbatim ([operations.go:799-829](../../internal/proxy/handlers/object/operations.go#L799)) |
| Bucket sub-resources: ACL, CORS, policy, location, logging, versioning, tagging, notification, lifecycle, replication, website, accelerate, requestPayment | Passed through so S3 tooling works, with one dent in the write direction: the `PUT` arms of accelerate, requestPayment, replication and website answer `NotImplemented` outright, and the `PUT` arms of versioning, tagging, notification and lifecycle answer it for any request carrying a body — only a body-less `PUT` reaches the backend, so those four `PutBucket*` rights are barely exercised. Every `GET` arm forwards, and so does every `DELETE` arm S3 defines (CORS, policy, tagging, lifecycle, replication, website) |
| `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`, `GetObjectRetention`, `PutObjectRetention`, `GetObjectLegalHold`, `PutObjectLegalHold` | The object sub-resources that carry their document to the backend since ADR 0007 D4. Each acts on the ciphertext object, so the proxy adds nothing to either direction |

The interface is 52 methods and **every one of them has a production caller**.
The 17 that had none — `CopyObject`, `ListParts`, `ListMultipartUploads`, the
object ACL, tagging, legal-hold and retention families, `SelectObjectContent`
and the accelerate, requestPayment, replication and website `PUT` arms above —
were declared for handler arms that refuse, and were dropped. Nine came back
with the arms that call them: the object tagging, retention and legal-hold
families (ADR 0007 D4) and, on 2026-09-11, `ListMultipartUploads` and
`ListParts` — the latter only for the exit provider, where the proxy keeps no
part table of its own. `HeadBucket` is the one addition rather than a return.
That matters beyond tidiness: a declared method is a capability the credential
is expected to have, so an interface that names operations no code issues
overstates the privilege the deployment needs.

**Refused at the handler, and therefore on no interface:** `CopyObject` and
`UploadPartCopy` (`422 NotSupportedWithEncryption`), and `GetObjectAttributes`,
object ACL and `SelectObjectContent` (`NotImplemented`) — see
[refusals](refusals.md).
`ListParts` is a second case: under an encrypting provider it is answered from
the proxy's own session part table and never reaches the backend, and it is
forwarded only under the exit provider, where there is no such table.
`ListMultipartUploads` is forwarded always.

</details>

There is no least-privilege story to configure: the credential is one pair, used
for everything. The realistic hardening is on the backend side — scope the
backend credential to the single bucket the proxy serves.

## What an attacker who takes the proxy gets

Everything.

- The **KEK**, in process memory, and therefore the ability to unwrap every DEK
  ever written under it — retroactively, for every object still in the bucket.
- The **DEK cache**, an LRU of up to 1024 already-unwrapped DEKs, plus the data
  key of every multipart upload currently in flight.
- Every **plaintext in flight**, in both directions.
- The **backend credential**, and with it direct read, write and delete on the
  bucket, bypassing the proxy entirely.
- Every **client credential** in `s3_clients`, which are stored as plaintext
  secrets in the configuration, not as hashes.

There is no key isolation, no HSM path and no separate signing identity that
survives a proxy compromise. The proxy is the trust anchor; protect it like one:
non-root container, read-only root filesystem, no shell, secrets from a
Kubernetes Secret rather than a baked-in config, and `${VAR}` references rather
than literals in any file that reaches a registry or a chart repository.

## What it does not give you

- **No multi-tenancy.** `S3ClientCredentials` carries `type`, `access_key_id`,
  `secret_key` and `description` and nothing else
  ([config.go:60-65](../../internal/config/config.go#L60)). There is no bucket
  allowlist, no prefix scope, no per-client policy. **Every authenticated client
  can do everything any other authenticated client can do.** Two clients
  sharing one proxy — two Velero installations, or a Velero and a CNPG Barman
  deployment — share one blast radius.
- **No per-client keys.** The active provider is global
  (`encryption.encryption_method_alias`). All clients write objects under the
  same KEK, so a client that can read an object can always decrypt it.
- **No isolation from the backend credential.** `s3_backends` is a list whose
  second entry is refused at startup, so the proxy holds one static credential
  pair for the backend ([server.go:108-112](../../internal/proxy/server.go#L108)) and
  uses it for every request from every client. Whatever that credential can
  reach, any authenticated client can reach through the proxy.
- **No rate limit and no blocking**, by decision rather than by omission
  (ADR 0014). An authenticated client may issue as many requests as it likes, and
  an unauthenticated one is refused per request without anything being counted or
  remembered. Nothing in the proxy derives an identity from a client address any
  more: a security event logs `remote_addr` and the raw `X-Forwarded-For` as two
  separate fields and interprets neither
  ([s3auth_robust.go:418-428](../../internal/proxy/middleware/s3auth_robust.go#L418)).
  That closes the state an attacker used to control; it does not add a control.
  The keys that claimed otherwise are gone
  ([where rule 2 came from](threat-model.md#where-rule-2-came-from)).

If tenant separation is required, run one proxy per tenant with its own KEK, its
own client credentials and its own backend credential.

---
