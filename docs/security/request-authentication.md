# Request authentication: what is checked before a handler runs

The two SigV4 forms the proxy accepts, everything it verifies on a request, the
one window that bounds a replay, and — at the end, because it is the longer
list — what it does not verify at all. The one check that covers the *payload*
rather than the request is [upload integrity](upload-integrity.md).

## Two authentication forms

`AuthenticateRequest` ([s3auth_robust.go:94](../../internal/proxy/middleware/s3auth_robust.go#L94))
accepts exactly what S3 accepts:

1. **Header form** — `Authorization: AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...`.
2. **Pre-signed query form** — `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
   `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`
   ([s3auth_presigned.go:57](../../internal/proxy/middleware/s3auth_presigned.go#L57)).

Both forms are needed by real clients. Velero, for example, signs headers on its
data path and uses pre-signed URLs for its download path (`velero backup
download`, backup and restore logs).

## What is verified on every S3 request

| Check | Where |
|---|---|
| `Authorization` header at most 8192 bytes | [s3auth_robust.go:43](../../internal/proxy/middleware/s3auth_robust.go#L43), checked at [:101](../../internal/proxy/middleware/s3auth_robust.go#L101) |
| Credential scope has 5 components, an 8-digit date, `service == "s3"`, `aws4_request` | [s3auth_robust.go:174-189](../../internal/proxy/middleware/s3auth_robust.go#L174) |
| Access key exists in `s3_clients` | [s3auth_robust.go:119-124](../../internal/proxy/middleware/s3auth_robust.go#L119) |
| Request timestamp within the clock-skew window, in both directions | [s3auth_robust.go:237-250](../../internal/proxy/middleware/s3auth_robust.go#L237) |
| Credential date matches the request date | [s3auth_robust.go:251-256](../../internal/proxy/middleware/s3auth_robust.go#L251) |
| Full SigV4 signature over method, canonical URI, canonical query, signed headers and payload hash, compared in constant time | [s3auth_robust.go:290](../../internal/proxy/middleware/s3auth_robust.go#L290) |
| Pre-signed only: `X-Amz-Expires` present, positive, and no larger than `s3_security.max_presign_expiry_seconds` (3600 # default, and never above the S3 maximum of 7 days); signing time not in the future beyond the skew; URL not expired | [s3auth_presigned.go:138-161](../../internal/proxy/middleware/s3auth_presigned.go#L138) |
| Bucket requests: every query parameter is on a known allowlist, otherwise `NotImplemented` | [handler.go:99-133](../../internal/proxy/handlers/bucket/handler.go#L99) |
| Object requests: the same allowlist one level down, so a sub-resource with no implementation cannot fall through to the base verb | [handler.go:105-178](../../internal/proxy/handlers/object/handler.go#L105) |
| A `PUT` delivers the plaintext length it declared. On the single-request path this is not an explicit check: the codec is given the length up front, so a body that ends early cannot fill the ciphertext the backend was promised and the upload fails with nothing stored. The multipart producer checks it outright, because a short body there would otherwise commit an object that verifies against its own trailer | [operations.go](../../internal/proxy/handlers/object/operations.go) `putObjectSegmented`, `putObjectAutoMultipart` |
| Every checksum a client declares matches the plaintext it sent, on every write path, with the verdict taken before anything is committed ([upload integrity](upload-integrity.md)) | [checksum.go](../../internal/proxy/request/checksum.go), [parser.go](../../internal/proxy/request/parser.go) |
| A body that stopped early never ends an object. Only a literal `io.EOF` counts as the end; the error a truncated aws-chunked stream raises is indistinguishable from the legitimate short last read through `io.ReadFull`, and treating them alike committed a silently short object that verified against its own trailer | [operations.go](../../internal/proxy/handlers/object/operations.go) `fillPart` |
| `DeleteObjects` carries a body digest at all, and it matches the document, checked before the document is parsed | [operations.go](../../internal/proxy/handlers/object/operations.go) `handleDeleteObjects` |

**The canonical request is built the way the signer builds it.** A header value
has its leading and trailing spaces removed and every run of spaces inside it
collapsed to one, matching `aws-sdk-go-v2`'s own canonicalisation byte for byte —
including what that does not do: only the space character is collapsed, never a
tab, and a quoted string is not exempt. The proxy used to trim only, so a
correctly signed request whose header carried repeated spaces was answered
`SignatureDoesNotMatch` while the backend accepted the identical request.
`Content-Disposition` with a filename is where that showed up, because filenames
contain spaces and that header is what a pre-signed download URL carries. The
failure was a false negative, never a false positive: no request was ever
accepted that should have been refused.

Authentication failures return a **fixed message per error code**. The raw error
text carries the attempted access key, signed header names and clock offsets;
reflecting it echoed attacker-controlled text into the response body and broke
the XML whenever a key contained `&` or `<`. It is now logged and not echoed
([middleware_setup.go:148-160](../../internal/proxy/middleware_setup.go#L148)).

## The clock-skew window

**One window, `s3_security.max_clock_skew_seconds`, 900 seconds by default, and
it governs both authentication forms.** Every shipped example narrows it to 300;
the configuration the image carries, `config/default.yaml`, leaves the default.

This used to be half true. The header form compared against a compile-time
constant and ignored the configured value, so an operator who narrowed the window
narrowed only the pre-signed path — the one most requests do *not* take. Closed
2026-09-11, together with the two other configuration decisions that were
specified and not built: `s3_security.max_presign_expiry_seconds` exists and
caps a pre-signed URL at one hour by default and seven days absolutely, and a
plain-`http://` backend endpoint refuses the start under every provider
(ADR 0013 D3, D5, D6; ADR 0014 D4, D5). The first of the three is the one that
can break a healthy deployment: a client whose clock is off by more than the
configured value starts being refused where it was accepted.

`0` is refused at startup rather than read as the default. It is the value an
operator would reach for to mean "no tolerance", and it used to widen the window
to the 900-second maximum instead. There is no value that disables the check.

The window is a replay window, and the proxy keeps no nonce cache: a captured
request can be replayed inside it. Narrowing it narrows the exposure and costs
tolerance for client clock drift; 900 is AWS's own figure, which is why it is the
default rather than something tighter.

## What is not verified

- **The request payload.** A missing `X-Amz-Content-Sha256` on a non-empty body
  becomes `UNSIGNED-PAYLOAD` rather than a rejection
  ([s3auth_robust.go:318-324](../../internal/proxy/middleware/s3auth_robust.go#L318)),
  and the pre-signed form defaults to `UNSIGNED-PAYLOAD` as well
  ([s3auth_presigned.go:201-204](../../internal/proxy/middleware/s3auth_presigned.go#L201)).
  The signature therefore authenticates the request line and headers, not the
  bytes.
- **Per-chunk signatures in aws-chunked uploads.** See
  [H-2](#h-2-per-chunk-signatures-are-never-verified).
- **Client checksums: verified since 2026-09-11, and this is the one control on
  the client leg.** See [upload integrity](upload-integrity.md) for what it
  does and does not buy.
- **Replay within the window.** There is no nonce store. A captured signed
  request can be replayed until its timestamp ages out of the 15-minute window.
- **A probe on `/livez` and `/readyz`.** Both are registered on a subrouter that
  carries no middleware, before the S3 subrouter that carries the auth middleware
  ([router.go:74-75](../../internal/proxy/router.go#L74)), and are unauthenticated by
  design. Those routes match a probe only — unsigned and with no query string
  (ADR 0014 D14). A signed request to either path, or one carrying S3 parameters,
  is an S3 request for a bucket of that name and goes through authentication like
  any other, so the exemption covers the probe and not the two names.
  **Both answer a fixed document and disclose nothing** (ADR 0034): `/livez` is a
  constant `200`, `/readyz` says only whether the process is draining and when
  the drain began. That is the whole unauthenticated surface of this listener.
  `/health` and `/version` were removed with ADR 0034 — `/version` had answered
  the build the binary was stamped with, so an unauthenticated probe learned the
  exact release; it is now `s3ep_server_info` on the monitoring listener, behind
  the same control as the rest of the operational data. **A drain is still
  observable without a credential**: `/readyz` answering `503` tells any reader
  that this instance is shutting down, which is exactly what a load balancer has
  to be able to see.
- **Anything on the monitoring listener.** `monitoring.bind_address`
  (`:9090` # default) serves `/metrics`, `/livez` and `/status` with **no
  authentication at all** ([monitoring/server.go:35-55](../../internal/monitoring/server.go#L35)).
  That is deliberate — it is what an ordinary Prometheus scrape needs, and it is
  what every exporter does. **Restricting who can reach the port is the
  operator's**, through whatever the cluster uses. The chart ships no
  NetworkPolicy (ADR 0030): it cannot know which namespaces may reach the proxy
  or where the backend listens, and the rules it used to ship were `from: []`
  and `to: []` — allow-from-anywhere and allow-to-anywhere, a blanket grant
  wearing the name of a control. So on any install the metrics port is reachable
  by anything that can route to the pod once the monitoring listener runs
  (`monitoring.enabled`, plus `monitoring.service.enabled` for a Service in front
  of it), until the operator writes a policy of their own.
  Thirteen metrics are declared. None carries a bucket name or an object key — the
  request labels are the gorilla/mux path *template*, not the request path
  ([middleware.go:79-86](../../internal/monitoring/middleware.go#L79)) — and none names
  the **licensee**: `licensed_to` and `company` were labels of
  `s3ep_license_info` and are gone, because a metric is scraped widely and
  retained long, and an unauthenticated endpoint is the wrong place for a
  customer name. What remains of the licence is its validity and its expiry.

  **What this listener does disclose, deliberately, is the active provider.**
  `s3ep_encryption_provider_info` carries `alias`, `type` and `kek_fingerprint`,
  and `/status` repeats them
  ([monitoring/status.go](../../internal/monitoring/status.go)). The fingerprint is
  designed to identify a key without revealing anything about it (ADR 0004), and
  the alias is a name the operator chose. **The `type` is the field that
  matters**: `exit` means this proxy is not encrypting and the backend holds
  plaintext (ADR 0025). An unauthenticated reader of this port therefore learns
  whether the data behind the proxy is encrypted at rest.

  That is the trade ADR 0034 D8 takes on purpose. An operator has to be able to
  see which provider is active — it is the difference between "encrypted at rest"
  and "not" — and the alternative was putting it on the S3 listener, where every
  client can reach it without a signature. It sits behind the one control this
  port has, which is who can route to it (ADR 0030), and on a default install the
  listener is off entirely. **If that disclosure is not acceptable in your
  deployment, the answer is a network policy in front of `:9090`, not a
  configuration key** — there is none, and `monitoring.enabled: false` removes
  the metrics with it.

  The rest of `/status` is the build, the backend's last observed answer or
  transport failure with its class, and the licence expiry — the same facts the
  metrics carry, rendered for a human. The endpoint issues no request of its own,
  so reading it cannot be used to make this proxy touch the backend
  (ADR 0034 D7). So the listener discloses little beyond the provider; it is
  still unauthenticated, and it is still the process that holds the KEK.
- **`/debug/pprof` is no longer on that listener (ADR 0013).** When
  `monitoring.pprof_enabled` is set (`false` # default) the profiling endpoints
  run on their own listener at `monitoring.pprof_bind_address`
  (`127.0.0.1:6060` # default, [monitoring/pprof.go](../../internal/monitoring/pprof.go)).
  A non-loopback value is a **startup error**, not a warning: `/debug/pprof/heap`
  on a proxy that holds KEK material, DEKs and plaintext buffers in memory is a
  key disclosure primitive, and the log line that previously told the operator to
  restrict access was a control that existed only in documentation. Reach it with
  an SSH tunnel or `kubectl port-forward`. The listener no longer depends on
  `monitoring.enabled` either — that coupling made `pprof_enabled: true` silently
  do nothing on its own, which is the same class of lie.

### H-2 Per-chunk signatures are never verified

**ADR 0014. Accepted.**

In an `aws-chunked` upload the seed signature in the `Authorization` header is
verified; the `chunk-signature` on each chunk is not, nor is
`x-amz-trailer-signature`. The decoder reads the chunk sizes, yields the payload
bytes and discards both signatures; the trailer lines themselves are kept,
because a checksum trailer is what the
[upload verifier](upload-integrity.md) compares against
([streaming_aws_decoder.go:26-28](../../internal/proxy/request/streaming_aws_decoder.go#L26)).

**Why this is judged acceptable:** the chunk signatures protect the **client
leg**, and the adversary in this model is on the **other** leg. The client leg
is operator-controlled ([boundaries](threat-model.md#boundaries)) and normally
runs over TLS. The seed signature never covered the body in any case,
`UNSIGNED-PAYLOAD` is already accepted (above), and the AWS SDK chooses the
unsigned-trailer framing over TLS precisely because transport integrity comes
from TLS. The residual exposure is a client that signs chunks over plain HTTP
and expects the proxy to catch a man in the middle.

Verifying the chain is a real implementation with real CPU cost, and the client
checksum verification of ADR 0012 buys most of the same benefit for much less —
it shipped on 2026-09-11 ([upload integrity](upload-integrity.md)). It is not a
substitute for TLS: a cyclic redundancy check catches corruption, not a
deliberate modification by someone positioned on that leg.

The mitigation is TLS on the client leg (`tls.enabled`). The checksum
verification is done and is a corruption check, not a defence against an active
attacker.
