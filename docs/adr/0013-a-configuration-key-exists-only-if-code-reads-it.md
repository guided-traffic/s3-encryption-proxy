# ADR 0013: A configuration key exists only if code reads it, and an unworkable configuration refuses to start

## Status

**Accepted.** Date: 2026-09-07.

Partly implemented. Built and shipped today: profiling on its own loopback listener with a
startup refusal for any non-loopback address, startup validation of
`encryption.metadata_key_prefix`, the range checks on `optimizations.streaming_segment_size`,
`optimizations.multipart_upload_concurrency` and `s3_security.max_clock_skew_seconds`, the
minimum length of a configured client secret, and the fix for a process-terminating race in
the per-address authentication-failure accounting that this decision goes on to delete
anyway.

Decided and specified, not implemented — it lands with the 5.0.0 release: deleting the six
`s3_security` keys that no code reads together with the failure accounting behind them,
deleting `s3_backend.use_tls`, refusing to start on a plain-HTTP backend endpoint under an
encrypting provider, adding `s3_security.max_presign_expiry_seconds`, honouring
`s3_security.max_clock_skew_seconds` on the header-signed authentication path, and deleting
`optimizations.clean_http_transfer_chunked` and the legacy top-level S3 block with the
migration that reads it. The `Decision` section is the rule either way.

## Context

The threat model has a rule that this decision is the configuration surface of: **a control
that exists only in configuration or in documentation is worse than no control, because it
gets relied upon.**

Reviewing the configuration surface while building the end-to-end backup suite produced four
concrete failures, all of the same shape.

**Security-sounding keys that nothing reads.** Six keys under `s3_security` —
`enable_rate_limiting`, `max_requests_per_minute`, `max_failed_attempts`,
`unblock_ip_seconds`, `strict_signature_validation` and `enable_security_logging` — were
parsed, defaulted, range-checked where numeric, written into the user-facing reference, set
in every shipped example configuration, in the production deployment values and in the
end-to-end values. No rate limiter, no block list and no unblock timer existed anywhere in
the product. The one piece of machinery that looked like an implementation counted
authentication failures per client address, keyed that count by a caller-supplied
forwarding header, compared it against a hardcoded threshold rather than the configured
one, only wrote a log line, and never expired an entry. It was not a weak control; it was
unbounded memory growth with a security-sounding name — and, until it was fixed, a way for
two concurrent unauthenticated requests to terminate the process.

**A key describing a configuration that cannot work.** `s3_backend.use_tls` was read only to
copy itself onwards. The backend transport is decided by the scheme of
`s3_backend.target_endpoint` alone. Worse, a plain-HTTP backend endpoint cannot carry a
streaming upload at all: the AWS SDK the proxy uses signs a payload by hashing the body,
which needs a seekable stream, and only accepts `UNSIGNED-PAYLOAD` over TLS. The proxy hands
it an unseekable ciphertext reader, so every streaming upload fails with
`failed to seek body to start`. Nothing in the product said so; every shipped example uses
TLS, which is why it was never hit. A validation on `use_tls` would have refused the working
configurations and passed the broken one.

**A control an operator would want, hardcoded.** The pre-signed URL lifetime ceiling was the
AWS maximum of seven days, with no way to lower it. Seven days of bearer capability is the
wrong default for a proxy whose purpose is to bound exposure to a hostile backend; real
clients mint URLs that live minutes.

**A profiling endpoint on an open port.** The profiling handlers were registered on the
metrics listener, which has no authentication and binds every interface by default. On an
encryption proxy a heap profile contains data encryption keys, unwrapped key material and
plaintext buffers, so anyone who could reach the metrics port could recover plaintext without
touching the backend. The product logged a warning telling the operator to restrict access —
a control that exists only in documentation.

The same review found configurations that are accepted today and destroy data or silently
disable protection: an empty or non-lowercase `encryption.metadata_key_prefix` makes stored
objects read back as pass-through, serving ciphertext to the client with a 200.

## Decision

**D1.** A configuration key exists only if code reads it. A new key lands in the same change
as the code that reads it and as a test that proves the effect. A key with no reader is
deleted, never documented as aspirational.

**D2.** The six `s3_security` keys named above are deleted, together with the per-address
failure accounting behind them. `s3_security` keeps exactly two keys —
`max_clock_skew_seconds` and `max_presign_expiry_seconds` — and both are enforced on every
path they name. The authentication-failure log line stays and records the peer address and
the forwarding header as two raw fields, interpreting neither.

**D3.** `s3_security.max_clock_skew_seconds` governs both authentication forms, header-signed
and pre-signed. A configured value that is honoured on one path only is the same defect as a
key with no reader at all.

**D4.** `s3_backend.use_tls` is deleted. The backend transport is the scheme of
`s3_backend.target_endpoint`. A `target_endpoint` without a scheme is a startup error.

**D5.** The proxy refuses to start when `s3_backend.target_endpoint` is plain `http://` and
the active provider encrypts. The error names the endpoint, the provider, and the upload
failure the operator would otherwise spend an afternoon on. With the pass-through provider
the proxy warns and continues, stating that credentials, bucket names and object keys travel
in clear.

**D6.** `s3_security.max_presign_expiry_seconds` exists because an operator needs to bound the
lifetime a pre-signed URL may claim, and it lands with the code that enforces it. A value
outside the permitted range is a startup error, and the enforcing code clamps independently of
startup validation, so a configuration assembled in code cannot exceed the cap either. Its
default, its cap and what it is enforced against are ADR 0014.

**D7.** A configuration that cannot work, or that silently disables a protection, refuses to
start. The proxy does not start degraded and does not repair the value. Refused at startup:
a backend endpoint with no scheme or with plain HTTP under an encrypting provider; an
`encryption.metadata_key_prefix` that is empty or does not match `^[a-z0-9-]+$`; an
`optimizations.streaming_segment_size` outside its documented range; a
`monitoring.pprof_bind_address` that is not a loopback address while profiling is enabled;
a client secret shorter than 16 characters. Every such error names the field and the rule it
broke. There is no silent normalisation — a value that would have turned the proxy into a
shredder fails loudly rather than being quietly corrected.

**D8.** Profiling is served on its own listener bound to loopback
(`monitoring.pprof_bind_address`, default `127.0.0.1:6060`) and is never registered on the
metrics listener. `/metrics` stays on `monitoring.bind_address` so it can be scraped
cluster-wide. Only a loopback IP literal or the literal `localhost` is accepted: a name is
refused rather than resolved, because resolving at startup makes the proxy unbootable without
a resolver and a name that points at loopback today can point elsewhere tomorrow.
`monitoring.pprof_enabled` stands on its own and does not silently require
`monitoring.enabled`.

**D9.** The same deletion applies outside the security section.
`optimizations.clean_http_transfer_chunked` is deleted: it governs a decoder that can never
run, because the HTTP server strips the transfer encoding before the handler sees the
request. The legacy top-level backend keys (`target_endpoint`, `region`, `access_key_id`,
`secret_key`, `use_tls`, `skip_ssl_verification`) and the migration that folds them into
`s3_backend` are deleted with them: they are backward-compatibility scaffolding, and no
backward compatibility is owed.

**D10.** Removing a key is a breaking change. It is announced in the release notes of the
major release that carries it, never absorbed by a compatibility shim or a deprecation
period. The configuration loader ignores unknown keys silently, so a configuration written
for an older release keeps loading and merely loses documentation for a feature that never
existed; the release notes are the only channel that tells the operator so.

## Consequences

- **An upgrade rejects configurations that "worked" before.** A plain-HTTP backend endpoint
  under an encrypting provider, a scheme-less endpoint, a non-loopback profiling address and
  an invalid metadata prefix now stop the process at startup. In Kubernetes that is a crash
  loop with a readable reason instead of a pod that reports Ready and fails every streaming
  upload — deliberately the louder failure.
- **Operators who set the deleted keys get no error, only release notes.** Unknown keys are
  ignored. This is the cost of not adding an unknown-key decoder: silence where a warning
  would be kinder.
- **Honouring the configured clock skew on both paths breaks working clients.** A client
  whose clock is off by more than the configured window authenticates today and will not
  afterwards. That is the configured intent, and the failure message is explicit, but it is
  the one change here that can break a healthy deployment.
- **Pre-signed URLs longer than one hour need an explicit key.** Any client that mints
  multi-day URLs must set `max_presign_expiry_seconds`, and can never exceed seven days.
- **Remote profiling is gone.** A heap profile now requires loopback access to the pod — a
  port-forward, or a container sharing the network namespace. Nobody enjoys that on an
  incident call; it is the price of not exposing keys and plaintext on an unauthenticated
  port.
- **Deleting the failure accounting removes a per-address failure signal.** There is no
  counter of failed authentications per client, and no metric to build one from. The log line
  is what remains.
- **The rule is a discipline, not a mechanism.** Nothing automated proves that a declared key
  has a reader; a strict unknown-key decoder would not help, because a field that is declared
  and never read passes it. The guard is review.
- **Deleting a key is one-way but cheap in this direction.** If security-event logging should
  ever become suppressible, it comes back as a key with a reader and a test.

## Alternatives Considered

- **Implement what the keys promised** — a rate limiter, per-address blocking driven by the
  failed-attempt threshold and the unblock timer, plus a trusted-proxy list and eviction to
  make the forwarding header safe to key on. This was decided and then reversed within a day.
  Per-address limiting is the wrong tool for this product: a legitimate S3 client is one
  authenticated identity bursting thousands of requests from one address, and clients behind
  a NAT or an ingress share an address. A signed request needs a client secret of at least 16
  characters, which is not guessable, and denial-of-service defence belongs in the ingress.
  See ADR 0014.
- **Keep the keys and document them as unimplemented.** Rejected by the threat model rule
  this ADR exists to apply: the documentation is exactly where the reliance comes from.
- **Keep a bounded failure counter with eviction, feeding only the log line.** Rejected: a
  trusted-proxy allowlist is a lot of infrastructure for one log field.
- **Wire `s3_backend.use_tls` up so it forces the scheme.** Rejected: it duplicates
  information the endpoint already carries, and making it authoritative means rewriting the
  endpoint — a larger change for no gain.
- **Warn instead of refusing on a plain-HTTP backend under an encrypting provider.**
  Rejected: the process would be healthy and every streaming upload would fail. The warning
  is kept only for the pass-through provider, where the operator may genuinely want a plain
  proxy.
- **Leave profiling on the metrics listener and document restricting access.** Rejected for
  the same reason the dead keys are deleted; the exposure is plaintext and key material.
- **Normalise a bad metadata prefix** (lowercase it, or substitute the default). Rejected: a
  prefix that disagrees with what is stored turns the proxy into a pass-through that serves
  ciphertext with a 200. That must fail loudly.
- **A deprecation period or compatibility shim for the removed keys.** Rejected: no
  backward compatibility is owed (ADR 0017), and a shim is more configuration code that must
  itself be read and tested.

## Residual risks

- **Nothing prevents the next dead key.** The rule is enforced by review only.
- **`s3_backend.insecure_skip_verify` survived the cleanup unexamined.** It is live, it is read,
  and it disables certificate verification on the leg that faces the adversary — so it passes the
  rule this ADR states while being the one backend-transport setting most worth a second look. No
  decision has been taken about it, and the connection path it selects carries no dial or
  handshake budget of its own.
- **The metrics listener stays unauthenticated on every interface by default.** Only
  profiling moved to loopback. Whether any exported metric carries bucket or object names has
  not been verified.
- **The pass-through exception may be worthless.** The warning for a plain-HTTP backend under
  the pass-through provider assumes such an upload can succeed. Reading the code suggests the
  client's stream is handed to the SDK unchanged and is just as unseekable, in which case the
  warning becomes a second refusal. One manual upload above the streaming threshold settles
  it; it has not been run.
- **Keys of the same class remain in the performance section.** Verified while writing this
  record: `optimizations.streaming_buffer_size` is read only by an accessor that no
  production code calls, and `optimizations.enable_adaptive_buffering` has no buffering
  behaviour behind it — its only effect is to enable one validation branch. No deletion has
  been decided for either; under D1 they are deletion candidates.
- **The safe default of `encryption.integrity_verification` was left unresolved.** A
  deployment that omits the key gets `off`, that is, no integrity checking, while the
  documentation recommends a verifying mode. Flipping the default would make existing
  deployments reject every object stored without an integrity tag. It was deliberately not
  decided because the key disappears entirely with the authenticated segment chain (ADR
  0003); until then, saying nothing gets the permissive behaviour.
- **The metadata prefix rule is narrower than it looks.** It requires no trailing separator,
  so a short prefix silently swallows client metadata that happens to begin with it; it sets
  no maximum length, so an over-long prefix fails at the backend with an opaque error rather
  than at startup; and changing one valid prefix to another still makes every already stored
  object read back as pass-through, which no startup check can see. Failing closed on an
  object carrying a different known prefix belongs to the storage format (ADR 0003, ADR
  0009).
- **The pre-signed default of one hour is derived from one client's numbers.** A known backup
  client mints ten-minute URLs, which fits comfortably. No other client's URL lifetime was
  measured.
- **Unverified: whether any deployment outside this repository sets the removed keys.** Such
  a configuration keeps loading; it simply loses documentation for a control it never had.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0006 — The proxy serves any S3 client
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
- ADR 0015 — A transfer is bounded by the client and by shutdown, not by a server wall clock
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0018 — A major release is declared by a label, never discovered at merge
- [README.md](../../README.md) — the configuration reference an operator works from
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the threat model rule this decision applies, and the hardening checklist entry for the dead keys
