# Threat model and trust boundaries

Who the adversary is, which three rules follow from that, where the trust
boundary runs, and which transport carries which leg. Every other page under
`docs/security/` settles its open questions by the rules stated here.

## The S3 backend is hostile

The objects this proxy stores belong to whatever S3 client writes through it —
cluster backups with Velero, database backups with CNPG Barman, anything an
`aws` CLI, rclone or SDK puts in a bucket — and their data is worth protecting.
The S3 endpoint they land on is treated as **hostile**, not merely
untrusted. Assume the backend can:

- read every byte it stores,
- change any byte,
- swap one object for another,
- serve a stale version of a key it once held,
- truncate a response,
- lie in a listing, in object metadata, in an ETag, and in an error.

**Nothing the backend says or does counts as authentication.** "The backend
returned 200" and "the transport was TLS" are statements about availability and
about the network, not about integrity of the stored object.

## Three rules

These three rules decide every open question under `docs/security/`.

1. **Integrity means the proxy verifies.** Authentication performed by the
   backend, or implied by TLS to the backend, is not integrity under this model,
   because the backend is the adversary.
2. **A control that exists only in configuration or in documentation is worse
   than no control**, because it gets relied upon. [Refusals](refusals.md) is
   that rule applied to a handler, and *Where rule 2 came from* below is the
   configuration that claimed controls the product did not have.
3. **The stored-object format may change without a migration path**
   ("no backward compatibility", [CLAUDE.md](../../CLAUDE.md)). It did: 5.0.0 stores
   the authenticated segment chain and there is no read path for what earlier
   releases wrote. An object written by 3.x or 4.0.x is **refused**, not read
   (ADR 0017). The precondition — that no deployment holds data which must stay
   readable across the change — was confirmed with the repository owner rather
   than assumed.

## Where rule 2 came from

Two findings, both closed on 2026-09-11, are why rule 2 is a rule and not an
observation.

**Six configuration keys described controls that did not exist.** `s3_security`
carried `enable_rate_limiting`, `max_requests_per_minute`, `max_failed_attempts`,
`unblock_ip_seconds`, `strict_signature_validation` and `enable_security_logging`
— parsed, defaulted, range-checked and documented, and read by nothing. No rate
limiter, no block list and no unblock timer existed anywhere in the product.
Beside them, `s3_backend.use_tls` was read only to assign itself while the scheme
of `target_endpoint` decided the transport, `encryption.integrity_verification`
offered a choice between integrity settings that the format decides, and
`optimizations.streaming_threshold` claimed to choose a cipher that no longer
exists.

The one piece of machinery that looked like an implementation was worse than the
absence it hid. It counted authentication failures per client, keyed that count
on the first `X-Forwarded-For` value — an attacker-chosen string — compared it
against a hardcoded `5` rather than the configured value, only ever wrote a log
line, and never expired an entry. Unauthenticated requests therefore grew proxy
memory without bound, under a name that read like brute-force protection. All of
it is deleted: the type, the map, the accessors, the threshold, the `getClientIP`
helper that produced the attacker-controlled key, and the `client_ip` and
`failed_count` log fields (ADR 0013, ADR 0014). Per-IP rate limiting was also the
wrong tool, which is why nothing replaced it: a legitimate client is one
authenticated identity that may issue thousands of requests from one address —
Velero bursts from a single pod IP, and anything behind a NAT looks the same.
What is left under `s3_security` is `max_clock_skew_seconds` and
`max_presign_expiry_seconds`, both read and both range-checked at startup
([config.go:68-79](../../internal/config/config.go#L68),
[config.go:920-949](../../internal/config/config.go#L920)).

**An unauthenticated decrypt path existed only in dead code.** The old
whole-object GCM and streaming CTR readers, the HMAC verifier, the CTR multipart
session, the envelope layer and the whole of `internal/validation/` compiled and
were reached by nothing but tests; `Manager.DecryptDataWithMetadata`, the entry
point to the algorithm switch that chose between them, had no production caller.
It was not a vulnerability, because no request could reach it, and it would have
become one the moment somebody wired a caller to it — easy to do by accident,
because the function names read like the live ones. It is deleted:
`deadcode ./cmd/s3-encryption-proxy` reports four unreachable functions where it
reported 206 before, and not one of them is a decrypt path. Removing it also
removed the last thing that could read an object written by 3.x or 4.0.x, which
is rule 3 working rather than a loss (ADR 0017).

## Roles

| Role | Concretely | Trusted for | Explicitly not trusted for |
|---|---|---|---|
| **Operator** | Whoever writes the proxy configuration and holds the KEK material | Everything. The operator chooses the KEK and the backend | — |
| **S3 client** | Any S3 client: Velero and its kopia-based node agent, CNPG Barman, `aws` CLI, rclone, any AWS SDK | Reading and writing **any** key in **any** bucket the backend credential can reach, once its SigV4 signature verifies | Nothing finer-grained. There is no per-client bucket or prefix scoping ([tenancy and privilege](tenancy-and-privilege.md)) |
| **Proxy process** | `s3-encryption-proxy` | The KEK, every decrypted DEK in its cache, the data key of every upload in flight, the backend credential, and every plaintext in flight | — it is the single point of compromise ([tenancy and privilege](tenancy-and-privilege.md#what-an-attacker-who-takes-the-proxy-gets)) |
| **S3 backend** | MinIO, AWS S3, any S3-compatible endpoint | Storing and returning opaque bytes, best effort | Confidentiality, integrity, freshness, truthful listings, truthful metadata, truthful errors |
| **Client leg network** | Client to proxy; often pod to pod inside one cluster, but any host that reaches the listener | Nothing on its own. Proxy-side TLS (`tls.enabled`, [config.go:18-22](../../internal/config/config.go#L18)) protects it, and the chart's `serviceTLS` turns it on for the in-cluster Service without hand-written mounts ([ADR 0026](../adr/0026-the-proxy-terminates-tls-at-its-own-service.md)) | — |
| **Backend leg network** | Proxy to the S3 endpoint | Nothing. This is the adversary leg by assumption | — |

## Boundaries

```
        operator-controlled, plaintext lives here
 ┌───────────────────────────────────────────────────────────────────┐
 │                                                                   │
 │   ┌───────────────┐                ┌──────────────────────────┐   │
 │   │  S3 client    │   plaintext    │  s3-encryption-proxy     │   │
 │   │               │  ============> │                          │   │
 │   │  Velero/kopia │   SigV4 hdr    │  - SigV4 verify          │   │
 │   │  CNPG Barman  │   or presign   │  - KEK (aes | exit)      │   │
 │   │  aws cli/sdk  │  <============ │  - random DEK per object │   │
 │   └───────────────┘   plaintext    │  - AES-256-GCM segments  │   │
 │                                    │  - DEK cache (in memory) │   │
 │                                    └────────────┬─────────────┘   │
 │                                                 │                 │
 └─────────────────────────────────────────────────┼─────────────────┘
                                                   │
        ciphertext + s3ep-* metadata               │
 ══════════════════════════════════════════════════╪══════════════════
        TRUST BOUNDARY: everything below is the adversary
                                                   │
                                    ┌──────────────▼──────────────┐
                                    │  S3 backend (HOSTILE)       │
                                    │                             │
                                    │  learns: ciphertext bytes,  │
                                    │  key names, object sizes,   │
                                    │  timestamps, request order  │
                                    │                             │
                                    │  can: alter, swap, replay,  │
                                    │  truncate, strip metadata,  │
                                    │  fabricate listings         │
                                    └─────────────────────────────┘
```

The single boundary that matters runs between the proxy and the backend.
Everything above it is operator-controlled and handles plaintext; everything
below it is assumed adversarial. A second, weaker boundary runs between the
client and the proxy, and is defended by SigV4
([request authentication](request-authentication.md)).

## Transport

| Leg | Control | Reality |
|---|---|---|
| Client to proxy | `tls.enabled`, `tls.cert_file`, `tls.key_file` ([config.go:18-22](../../internal/config/config.go#L18)); in Kubernetes, `serviceTLS` in the chart | Works. The integration suite runs against both the HTTP and the TLS endpoint, and the Velero e2e runs the whole suite over the chart's own `serviceTLS` listener |
| Proxy to backend | `s3_backends[0].target_endpoint`, `s3_backends[0].insecure_skip_verify` | **The scheme in `target_endpoint` decides.** Those two are the only backend values that reach the SDK options ([server.go:173-222](../../internal/proxy/server.go#L173)). `s3_backend.use_tls` is gone with the mapping it sat in: it was read only to assign itself, and a key that describes a transport it does not select is exactly what rule 2 refuses (*Where rule 2 came from* above) |

`insecure_skip_verify: true` disables backend certificate verification and logs a
warning. Under this threat model that is a smaller loss than it looks — the
backend is the adversary regardless — but it also removes the only defence
against an *additional* attacker on that leg. Do not use it outside development.

A `target_endpoint` of `http://` refuses the start
(since 2026-09-11).
Under a provider that encrypts the object bytes would be sealed either way, but
the backend credential travels in a SigV4 header over plaintext and a listener on
that leg learns every key name and every object size. **Under the `exit` provider
the same refusal applies**, and the reason is stronger there, not weaker: the
object bytes travel in the clear as well, so plain HTTP exposes strictly more
than it does under an encrypting provider. The exception that used to admit it
was justified with an unseekable ciphertext stream that does not exist — the
exit write path hands the SDK an unseekable *plaintext* stream, which fails the
same way — and it let the proxy start and then refuse every upload below
`optimizations.multipart_part_size` at runtime.

## What is out of scope

- Denial of service by the backend. A backend that refuses to serve, or deletes,
  cannot be stopped by a proxy; it can only be detected by the client.
- The confidentiality of key *names*, object *sizes*, *timestamps* and *access
  patterns*. All four are visible to the backend today; see
  [what the backend learns anyway](stored-objects.md#what-the-backend-learns-anyway)
  and ADR 0023 (filename encryption, decided and not implemented).
- Side channels against the host the proxy runs on. An attacker with code
  execution on that host is covered in
  [what an attacker who takes the proxy gets](tenancy-and-privilege.md#what-an-attacker-who-takes-the-proxy-gets),
  not defended against.
