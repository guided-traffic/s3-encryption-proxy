# 039 — A backend under a private CA is configured, and a certificate failure is named

Raised 2026-09-14 by the owner, out of the website documentation work: an
enterprise backend usually presents a certificate from a private CA, and neither
the docs nor the log said where the CA bundle is or what a missing CA looks like.

**Refined 2026-09-18.** The session took twelve decisions, added a feature the
ticket did not originally carry, and found that the tree had moved under the
ticket's own survey. Read *What changed on 2026-09-18* before anything else — the
work list below is the refined one, and the original one no longer applies.

## What changed on 2026-09-18

### The log half was mostly built the day after this ticket was written

`internal/monitoring/backend.go` landed in `edf88cb` on **2026-09-15**, one day
after the survey this ticket rests on. Everything under *What the tree looks like
today* that concerns error reporting is stale. What exists now:

- **Five failure classes, already resolved.** `classifyBackendFailure`
  ([backend.go:192](../../internal/monitoring/backend.go#L192)) returns `dns`,
  `tls`, `timeout`, `connect` or `other`, in that resolution order. `isTLSFailure`
  ([:209](../../internal/monitoring/backend.go#L209)) already matches
  `*tls.CertificateVerificationError`, `x509.UnknownAuthorityError`,
  `x509.HostnameError`, `x509.CertificateInvalidError` and
  `tls.RecordHeaderError`.
- **A log line per failed round trip.** `recordBackendFailure`
  ([:147](../../internal/monitoring/backend.go#L147)) writes
  `Backend round trip failed before any HTTP response` at **warn** with `class`,
  `host`, `method` and the error attached through `WithError` — so the x509 text
  is already in the line, and warn is visible at `log_level: info`.
- **The counter pair ADR 0034 D6 designates.**
  `s3ep_backend_transport_failures_total{class}` beside
  `s3ep_backend_responses_total`.
- **The observer sits below the SDK**, on `o.HTTPClient`, so it sees the raw
  transport error rather than the smithy-wrapped one. **Finding E is therefore
  moot for this path**: there is no `As` hook to walk and nothing a Renovate bump
  of `aws-sdk-go-v2` or `smithy-go` can silently break.

What this deletes from the original work list: building neighbouring classes,
building a classification helper, plumbing `backend_endpoint` onto the error
writer, adding a counter, and the unit test that was to pin the SDK unwrap chain.

### What is still missing, and it is one thing

`class=tls` puts *this certificate is not trusted* and *the TLS handshake failed
for a protocol reason* in the same bucket. In the log a human can tell them apart
by reading the error text. **On the metric nobody can** — and the metric is what
ADR 0034 D6 names as the surface an alert is written against. The two demand
opposite responses: an untrusted CA never recovers on its own and needs a person;
a protocol failure may pass.

### The ticket gained a feature: `ca_file` per backend

Asked for by the owner during the refining session. A backend entry gains an
optional `ca_file`. When it is set, that backend's chain is verified **only**
against the certificates in that file; the system roots do not apply to it. When
it is absent, the system roots apply as they do today. `insecure_skip_verify` is
untouched and was already per backend.

### Corrections to the original survey

- **`insecure_skip_verify` is already per backend.** It sits inside the entry
  ([config.go:34](../../internal/config/config.go#L34)) and
  `backendClientOptions` takes an `S3BackendConfig`
  ([server.go:173](../../internal/proxy/server.go#L173)). Nothing to build.
- **Finding A is incomplete.** `config/default.yaml` — the configuration the
  image starts with — sets no `insecure_skip_verify` at all, so the shipped image
  verifies the backend certificate by default. Two configurations in the
  repository verify, not one, and row one of *Measured* is therefore the normal
  path of an enterprise rollout rather than an edge case.
- **Finding C is half decided already.** ADR 0034 D6 puts dependency health in
  the "reported, never acted on" category and D9 refuses a startup probe *while
  the startup path does no network I/O* — and names the condition that would
  reopen it. The remaining question is a startup *check*, which is not a probe.
  Split out; see the work list.
- **Finding F is settled by deletion.** The error writer does not need
  `backend_endpoint`: the observer's line already carries `host`, read off the
  round trip.

## The twelve decisions taken on 2026-09-18

| # | Question | Decision |
|---|---|---|
| 1 | Does behaviour belong in this ticket? | Log and documentation only; retry and startup check are separate tickets |
| 2 | `backend_endpoint` on the error writer | Not needed — the observer's line carries `host` |
| 3 | How many failure classes | The five that exist; no second vocabulary |
| 4 | A counter for stream faults | No new counter; `s3ep_backend_transport_failures_total` is the one |
| 5 | A hardening item | Neither opened nor closed; *Transport* in `docs/security/threat-model.md` gains the alternative |
| 6 | A fifth config example | No — the demo stack's two examples become it |
| 7 | `ca_file` together with `insecure_skip_verify: true` | Refuse the start, naming both keys |
| 8 | The key's name and form | `ca_file`, exactly one PEM file, which may hold several certificates |
| 9 | What proves `ca_file` | The demo stack switches to it; the Velero e2e keeps `SSL_CERT_FILE` |
| 10 | One ADR or two | One — ADR 0037, the backend leg |
| 11 | The website | The owner said to do it directly, after the key is built |
| 12 | What is left of the log half | Split `tls` into `tls_certificate` and `tls`, in log and metric; the certificate case logs at error |

## Work list

### The feature

1. **`ca_file` in the backend entry.** Add `CAFile string` to `S3BackendConfig`,
   build an `x509.CertPool` from the file at startup, and hand it to
   `backendHTTPClient` so it sets `tr.TLSClientConfig.RootCAs`. Follow the
   existing "mutate, never replace" rule in that function
   ([server.go:228](../../internal/proxy/server.go#L228)) — assigning a fresh
   `tls.Config` drops `MinVersion: TLS 1.2` back to Go's default.
   Startup refusals, all three naming the key and the entry:
   - the file cannot be read, is empty, or `AppendCertsFromPEM` reports no
     certificate — never a fall back to the system roots, which would widen trust
     silently;
   - `ca_file` and `insecure_skip_verify: true` are both set;
   - (nothing else — an absent `ca_file` is the normal case.)
2. **The README configuration block gains the key.** The struct and that table
   move together, or an operator who writes the key gets a startup failure.
3. **`make test-conformance`.** `scripts/conformance-run.sh` writes its own proxy
   configuration and is the one configuration
   `TestCfgShippedExamplesCarryNoUnknownKeys` cannot see.
4. **The demo stack switches to `ca_file`.** Mount `test/ssl-setup/ca.crt` into
   both proxy containers and replace `insecure_skip_verify: true` with `ca_file`
   in `config/aes-example.yaml` and `config/aes-tls-example.yaml`. The MinIO
   certificate carries SAN `minio`, so it verifies as-is. This is the foundation
   every integration suite stands on: bring the stack up and prove it in the same
   change, not only with unit tests.

### The remaining log gap

5. **Split `tls` into `tls_certificate` and `tls`.** `tls_certificate` is the
   subset that carries `*tls.CertificateVerificationError` or a bare
   `x509.UnknownAuthorityError` / `HostnameError` / `CertificateInvalidError`;
   `tls` keeps the protocol-level rest. Log and metric label both.
   The certificate class logs at **error** rather than warn: it never recovers
   without a person. The shipped `PrometheusRule` sums the counter with no class
   selector ([prometheusrule.yaml:45](../../deploy/helm/s3-encryption-proxy/templates/prometheusrule.yaml#L45)),
   so no shipped alert changes meaning — but the label's value set is an
   interface, so `docs/operations/monitoring.md` and an upgrade note are owed.
6. **Unit tests for the split.** `httptest.NewTLSServer` produces a certificate
   the system pool refuses, which is the `tls_certificate` case directly; the
   protocol case needs a server that answers non-TLS bytes on a TLS dial. The
   existing backend-observer tests are where these belong.

### The documentation

7. **`docs/developer/configuration.md`** — new section after *3. `${VAR}`
   references*, suggested title *The CA bundle, and a backend under a private
   CA*. Content: `ca_file` as the documented way and what its three refusals are;
   the bundle's path and provenance (`/etc/ssl/certs/ca-certificates.crt`,
   Debian's, 150 certificates, no `update-ca-certificates` in a distroless
   image); Go's loading rule and what `SSL_CERT_FILE` / `SSL_CERT_DIR` each
   replace, as the mechanism underneath rather than the recommended path; **the
   precedence — `ca_file` wins for its backend, silently, because an environment
   variable read by the Go runtime is not a key this proxy can refuse**; that the
   pool is built once at startup, so a rotated CA is a restart, and the chart
   does not roll a pod for a volume the operator added; that
   `insecure_skip_verify` is not the answer. Cite
   `test/e2e/velero/values-proxy.yaml` as the worked `SSL_CERT_FILE` example
   rather than inventing one, and use the chart's real key names — `volumes`,
   `volumeMounts`, `env`
   ([values.yaml:166-172](../../deploy/helm/s3-encryption-proxy/values.yaml#L166)),
   not `extraVolumes`/`extraEnv`. Mark shown values `# default` / `# example`.
8. **`docs/developer/errors.md`** — what a backend transport failure is logged
   as, the five classes after the split, why the response class stays
   `500 InternalError`, and that the x509 text is a log field and never a
   response body.
9. **`README.md`** — one sentence beside `insecure_skip_verify` pointing at the
   developer section, plus the new key in the configuration block (item 2).
10. **`docs/security/threat-model.md`, *Transport*** — the paragraph that tells an
    operator not to use `insecure_skip_verify` outside development names no
    alternative. One sentence pointing at the new section. No hardening item is
    opened or closed (decision 5).
11. **The environment-variable boundary** — one line each in `README.md` and
    `docs/developer/configuration.md`: the proxy reads no configuration key from
    the environment, and `SSL_CERT_FILE` / `SSL_CERT_DIR` are read by the Go TLS
    stack underneath it, not by the loader. Without it the new section reads as a
    contradiction of the 5.0.0 removal argument.
12. **`docs/operations/monitoring.md`** — the class label's value set gains
    `tls_certificate` (item 5).
13. **The website.** `s3ep-website` carries
    `/documentation/configuration#backend-ca`, which will describe the
    second-best way once `ca_file` exists. The owner authorised editing that
    repository directly, **after** the key is built and the demo stack proves it,
    so the page can be written from behaviour that has been seen rather than
    announced. Its per-page verified-against stamp is part of the edit.

### Verification

14. Re-run row one of *Measured* against a locally built binary to see the split
    class (`make build`, strict config against `https://localhost:9000`; the demo
    certificate carries SAN `localhost`, finding L). `make test-unit` green,
    `make test-conformance` green (item 3), and the demo stack up with the two
    switched examples (item 4).

## Split out of this ticket

- **[042](042-a-certificate-failure-is-not-retried.md)** — a certificate that
  cannot be verified is retried to the attempt ceiling, three TLS handshakes per
  client request, and no retry can succeed until an operator acts.
- **[043](043-the-backend-is-checked-before-the-first-client-request.md)** — a
  backend the proxy cannot reach produces a pod that goes Ready and fails every
  request. ADR 0034 D6 and D9 already bound the answer.
- **`reportStreamFault` reports a backend fault as a client disconnect**
  (finding J). Still true
  ([helpers.go:122-137](../../internal/proxy/handlers/object/helpers.go#L122)),
  and no longer urgent: the observer logs the same failure with its class and
  host, so an operator is not blind. It is a wrong subject in one line, filed in
  043 together with the reachability question it belongs to.

## What the tree looks like today

**Stale as of 2026-09-15 for everything about error reporting** — see *What
changed on 2026-09-18*. The transport facts below were verified on 2026-09-14
against release 5.0.0 and still hold.

- **The bundle.** `/etc/ssl/certs/ca-certificates.crt` in the image — Debian's
  `ca-certificates` as `gcr.io/distroless/static-debian12:nonroot` ships it,
  224,449 bytes, 150 certificates, mode `r-xr-xr-x`, and the only entry under
  `/etc/ssl` (verified with `docker export | tar -tv` on the 5.0.0 image). No
  OpenSSL, no `update-ca-certificates`, no shell.
- **How roots are loaded** (Go 1.27.1 `crypto/x509/root.go`, `loadOnDiskRoots`):
  the first readable file of `certFiles` (`/etc/ssl/certs/ca-certificates.crt`
  first) **and** every file in `certDirectories` (`/etc/ssl/certs`,
  `/etc/pki/tls/certs`). `SSL_CERT_FILE` replaces the file list with that one
  file; `SSL_CERT_DIR` replaces the directory list. So with `SSL_CERT_FILE`
  pointing at a private CA the bundle is still read — through the directory
  scan, because it is a regular file in `/etc/ssl/certs`. Roots are loaded once
  per process (`sync.Once`), on the first TLS handshake.
- **The proxy touches none of this** unless `insecure_skip_verify` is set:
  [server.go:192-220](../../internal/proxy/server.go#L192) leaves the SDK
  transport alone, and only the insecure branch installs a `tls.Config`. System
  roots therefore apply, and `SSL_CERT_FILE` works without any proxy change.
  **`ca_file` changes exactly this sentence** — it is the second branch that
  touches `tls.Config`, and the reason item 1 must follow the same
  mutate-never-replace rule.
- **A backend TLS failure reaches `MapError` with no `APIError` and
  `StatusCode: 0`**, so it is internal by definition
  (`docs/developer/errors.md`, *How a backend error is classified*) and answers
  `500 InternalError`. Decision 1 leaves that alone.

## Measured

Four runs of the 5.0.0 release image (`--platform linux/amd64` on this Mac; the
image is amd64-only) against the demo stack's MinIO, whose certificate is issued
by `test/ssl-setup/ca.crt` (SAN `minio`, valid to 2036), with the minimal
configuration and **no** `insecure_skip_verify`, `aws s3 ls` through the proxy:

| Run | Result |
|---|---|
| No private CA | `InternalError` after the SDK's retries; log at `info` shows only `S3 operation failed` |
| `-v ca.crt:/etc/ssl/custom/ca.crt:ro -e SSL_CERT_FILE=/etc/ssl/custom/ca.crt` | round trip succeeds; bundle untouched |
| image bundle + private CA concatenated, mounted over `/etc/ssl/certs/ca-certificates.crt` | succeeds |
| private CA alone mounted over `/etc/ssl/certs/ca-certificates.crt` | succeeds — the proxy has one outbound TLS peer |

Row one's log observation is the part that went stale on 2026-09-15: the
observer's warn line now names `class=tls` and carries the x509 text. That the
public roots stay trusted beside `SSL_CERT_FILE` is from the Go source only; the
proxy has no second TLS peer to prove it against.

## Findings from the 2026-09-14 second pass that still stand

- **A.** `test/e2e/velero/values-proxy.yaml` mounts the test CA as a Secret at
  `/app/ca`, sets `SSL_CERT_FILE=/app/ca/ca.crt` and keeps
  `insecure_skip_verify: false`, so the Velero suite validates the MinIO chain
  for real inside kind. Cite it rather than inventing an example. The chart keys
  are `volumes`, `volumeMounts` and `env`, not `extraVolumes`/`extraEnv`
  ([values.yaml:166-172](../../deploy/helm/s3-encryption-proxy/values.yaml#L166),
  [:263](../../deploy/helm/s3-encryption-proxy/values.yaml#L263), consumed by
  [templates/deployment.yaml:114-140](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L114)).
- **B.** `templates/deployment.yaml` carries `checksum/config` (line 24) and
  `checksum/secret` (line 29), both over the **chart's own** ConfigMap and
  Secret. A CA the operator brings through `volumes` is in neither, so a rotated
  CA needs a manual `kubectl rollout restart` and nothing says the pod is running
  on the old roots. `ca_file` makes this **more** relevant, not less: the pool is
  now built by the proxy at startup. Document it; do not fix it here.
- **I.** `README.md` and `docs/developer/configuration.md` both state that the
  only environment mechanism is a `${VAR}` reference in a named list of fields,
  with `S3EP_LICENSE_TOKEN` as the single exception.
  `SSL_CERT_FILE`/`SSL_CERT_DIR` are read by the **Go runtime**, not the loader,
  so they are not a counterexample — but an operator who has read that sentence
  will stop looking. Work list item 11.
- **L.** `test/ssl-setup/gen-certs.sh` builds one leaf certificate and copies it
  to `minio.crt`; its SAN block (lines 56-76) carries `localhost` and `127.0.0.1`
  alongside the container and Kubernetes names. So a locally built binary pointed
  at `https://localhost:9000` with verification on reproduces row one of
  *Measured*.

Findings C, D, F and J moved: C and J into 043, D into 042, F is settled by
deletion (decision 2). Finding E is moot — the observer sits below the SDK.
Finding H is settled by decision 5. Finding K is settled by decision 11.

## Open questions

- **May two backends carry certificates from different private CAs in one
  deployment?** `ca_file` is per entry, so the configuration permits it and
  nothing in this design assumes otherwise. It belongs to
  [037](037-multiple-backends.md) to confirm, not here.
- **Does `docs/operations/` want a page of its own for the backend trust story,
  or is the developer section plus the README sentence enough?** The rule says
  what an operator meets lives under `docs/operations/`, and a CA mount is
  squarely an operator's job. Against a new page: the settings themselves are the
  README's key block, and the *why* is the developer page. Decide before writing
  item 7, because the cross-links differ.

## Done when

- A backend entry accepts `ca_file`, verification uses only that file when it is
  set, and each of the three refusals names the key and the entry.
- The demo stack runs with `ca_file` instead of `insecure_skip_verify: true`, and
  both proxies come up.
- A certificate failure is `class=tls_certificate` at error level in the log and
  in `s3ep_backend_transport_failures_total`, distinguishable from a
  protocol-level `tls` failure without reading the error text.
- The four documentation homes carry their part, the README's key block has the
  new key, and the website page has been updated directly.
- `make test-unit`, `make test-conformance` and the integration suites green, and
  this file is in `archive/`.
