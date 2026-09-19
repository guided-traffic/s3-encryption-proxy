# Monitoring the proxy

What the proxy exports, what a probe may ask it, and the one descriptive
document an operator reads. All of it is off on a default install:
`monitoring.enabled` is `false`, and switching it on switches on an
unauthenticated listener with it.

See also [configuration.md](configuration.md) for the `monitoring` keys,
[ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md)
for what a probe may report, and
[ADR 0030](../adr/0030-the-network-boundary-belongs-to-the-administrator.md)
for who owns the network boundary around that listener.

## Metrics

With `monitoring.enabled: true` the listener serves `metrics_path` in Prometheus
format. What it actually exports today:

| Metric | Type | Labels |
|---|---|---|
| `s3ep_requests_total` | counter | `method`, `endpoint`, `status_code` |
| `s3ep_request_duration_seconds` | histogram | `method`, `endpoint` |
| `s3ep_server_info` | gauge | `version`, `commit`, `build_time` |
| `s3ep_active_connections` | gauge | — |
| `s3ep_object_integrity_failures_total` | counter | `reason`, `phase` |
| `s3ep_license_info` | gauge | `expires_at` |
| `s3ep_license_expiry_timestamp` | gauge | — |
| `s3ep_backend_last_response_timestamp` | gauge | — |
| `s3ep_backend_last_failure_timestamp` | gauge | `class` |
| `s3ep_backend_observed` | gauge | — |
| `s3ep_backend_transport_failures_total` | counter | `class` |
| `s3ep_backend_responses_total` | counter | — |
| `s3ep_encryption_provider_info` | gauge | `alias`, `type`, `kek_fingerprint` |

**`s3ep_object_integrity_failures_total` is the one series worth an alert.** It counts reads
where an object did not authenticate: `reason` is what failed — `authentication`,
`key_material`, `foreign_object`, `stored_length` — and `phase` is when it was found.
`before_response` means the read was refused with `403 InvalidObjectState` and nothing of the
object reached the client; `mid_stream` means the status line was already out, the response was
cut, and **the request is counted as the `200` it announced** — which is exactly why this counter
exists. It is expected to stay at zero:

```promql
increase(s3ep_object_integrity_failures_total[15m]) > 0
```

Every series carries `kubernetes_namespace`, `kubernetes_pod_name`,
`helm_release` and `helm_chart_version` when those are present in the
environment; the chart sets them. The two license gauges appear once a valid
license is loaded.

The listener carries no authentication, so it names no licensee: `licensed_to`
and `company` were labels of `s3ep_license_info` until 5.0.0 and are gone.
Restricting who can reach the metrics port is the operator's, and the chart ships
no NetworkPolicy of its own: which namespaces may reach the pod is a property of
the cluster, not of the chart (ADR 0030). Write one against the proxy pod, or run
without one knowingly.

There is no remaining-days gauge. It would be written once, at startup, and
could never fall, so an alert on it could never fire. Ask the timestamp
instead: `(s3ep_license_expiry_timestamp - time()) / 86400`.

`endpoint` is the **route template** — `/{bucket}/{key:.*}`, not the path the
client requested — so no bucket or key name reaches a scrape.

The Go runtime and process collectors (`go_*`, `process_*`) are served as well.

> **Until 5.0.0 the two request metrics reached no scrape at all.** They were
> registered on the proxy's own registry while the endpoint served Prometheus's
> default one, so a proxy whose second goal is throughput exported no request
> rate and no latency; and the collectors that *were* served carried none of the
> Kubernetes labels, because those are attached only by the wrapper around that
> other registry. Labelled series were not exported, exported series were not
> labelled. There is one registry now.

Anything else an older dashboard charts — S3 operation counters, encryption or
HMAC timings, throughput gauges, provider info — no longer exists: those metrics
were removed together with the code that never observed them.

## Probe endpoints

The S3 listener answers exactly two unsigned paths, and each one answers a single
question ([ADR 0034](../adr/0034-a-probe-reports-the-process-never-its-dependencies.md)):

| Path | Answers | Point it at |
|---|---|---|
| `GET /livez` | A constant `200 {"status":"alive"}`. It never reports the drain and checks no precondition | A liveness probe |
| `GET /readyz` | `200 {"status":"ready"}`, and `503 {"status":"shutting_down"}` with the shutdown time from the moment a `SIGTERM` starts the drain | A readiness probe |

`/livez` is constant on purpose. The only reaction to a failing liveness probe is
to kill the container and restart it, and no precondition this proxy has is
repaired by a restart: a backend outage is not, a configuration that did not parse
never got the process this far, and an expired licence makes the process end
itself. What a restart *does* destroy is the multipart uploads this process is
holding, which is precisely what the drain exists to end. A liveness probe that
reported the drain therefore killed the shutdown it was watching.

`/readyz` is a lifecycle signal and never a load signal: back-pressure is answered
with `SlowDown` in a response, not by leaving the rotation. It keeps answering
throughout the drain, because the listener closes last — a probe during the sweep
reads a refusal rather than a connection error.

A request to either path counts as the probe **only when it is unsigned and
carries no query string**. Anything else addressed to them — a signed request, or
one carrying listing parameters — is an S3 request for a bucket of that name and
is routed, authenticated and answered as one, because `livez` and `readyz` are
legal bucket names and reserving them would make two buckets unreachable
([ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) D14). A
probe that is given credentials, or a probe URL that acquires a cache-busting
parameter, therefore stops being a probe and answers an S3 error.

Nothing descriptive is on this listener. `/health`, `/version` and the monitoring
listener's `/info` are gone as of this release, with no alias: the build, the
active provider, what the backend last did and the licence are one document,
behind the port whose reachability you control.

## The status document

With `monitoring.enabled: true` the monitoring listener answers `GET /status`
beside `/metrics` and its own `/livez`. It is the one descriptive endpoint, it is
read by a human, and **nothing automatic may act on it** — a probe that read it
would take every instance out at the same moment the one shared thing behind it
failed.

```json
{
  "service": "s3-encryption-proxy",
  "build": {"version": "5.0.2", "commit": "7bbc3f9", "build_time": "2026-09-15T08:12:03Z"},
  "encryption": {"provider_alias": "current-provider", "provider_type": "aes", "kek_fingerprint": "a1b2c3d4e5f60718"},
  "backend": {"status": "ok", "last_response": "2026-09-15T09:41:22Z"},
  "license": {"expires_at": "2027-01-31 23:59:59 UTC", "valid": true, "remaining": "3264h0m0s", "remaining_seconds": 11750400}
}
```

`backend` reports **what the real traffic showed**; the endpoint never issues a
request of its own. There is no S3 call that is universally permitted — a policy
may deny listing buckets, and the proxy owns no bucket of its own to head — so a
synthetic check could report a failure the real path does not have. Any HTTP
answer from the backend counts as reachability, a `403` included: the question is
whether it answered, not whether it agreed.

| `backend.status` | Meaning | Also present |
|---|---|---|
| `no request since start` | Nothing has been observed yet. It never says `ok` on a guess | — |
| `ok` | The last thing observed was an HTTP response | `last_response`, and `last_failure`/`last_failure_class` if there was ever a failure |
| `failing` | The last thing observed was a transport failure | `last_failure`, `last_failure_class` (`dns`, `connect`, `tls`, `timeout`, `other`), and `last_response` if there was ever one |

`license` is absent entirely when no licence information was ever recorded, and
`remaining` is computed when you read the document, not frozen at startup.

**A transport failure is also logged and counted, and the counter is what an
alert reads.** The document and the `*_last_failure_timestamp` gauge say *when*
it last broke; neither can express a rate, so the alert is written against
`s3ep_backend_transport_failures_total` over `s3ep_backend_responses_total` — the
share, never the count, because the AWS SDK retries and an ordinary network
produces some. **The rules ship with the chart**, off by default, as a
`PrometheusRule`: see
[the chart's alerting rules](../../deploy/helm/s3-encryption-proxy/README.md#alerting-rules).

Every failure is a `warn` line naming the class, the backend host, the method and
the error — **that line is the only record of it**, because a round trip that
failed and then succeeded on a retry never reaches a handler and is logged
nowhere else. Two failures are deliberately neither counted nor logged, because
neither says anything about the backend: one whose request was already cancelled
— a client that hung up, a shutdown — and one the proxy's own request body
raised, which is an upload checksum that did not verify or a segment that could
not be sealed. The client is still told, with `400 BadDigest` or a `500`.

Every field is a metric on the same listener as well — `s3ep_server_info`,
`s3ep_encryption_provider_info`, `s3ep_backend_*`, `s3ep_license_*`. The document
is the ad-hoc reading of them for an operator with no Prometheus, never their
replacement. It is **absent on a default install**, because `monitoring.enabled`
is `false`; switching it on switches on the unauthenticated metrics port with it,
which is why the default is not flipped.

> `encryption.provider_type` is the reason this document is not on the S3
> listener. An `exit` provider means the backend holds plaintext, and that must
> not be readable without a signature — see
> [docs/security/request-authentication.md](../security/request-authentication.md).

