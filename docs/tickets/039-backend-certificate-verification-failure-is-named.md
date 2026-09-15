# 039 — A backend certificate the proxy does not trust is named, in the log and in the developer docs

Raised 2026-09-14 by the owner, out of the website documentation work: an
enterprise backend usually presents a certificate from a private CA, and today
neither the docs nor the log say where the CA bundle is or what a missing CA
looks like. **Two work items, both small, to be done in a session of their own.**
Everything under *What the tree looks like today* was verified on 2026-09-14
against release 5.0.0; the four runs under *Measured* were executed, not
reasoned about.

**Investigated a second time on 2026-09-14** — see *Investigated 2026-09-14*
below. The two items hold, but they touch three documents rather than two, they
carry a decision that has to be taken before any code is written (finding F), and
the pass turned up five further open questions. The work list is now nine items,
still small ones. Read the findings before starting; they are what the review
session is for.

## What it is

1. **`docs/developer/configuration.md` gains a section on the CA bundle**: where
   it is in the image, how Go's `crypto/x509` picks roots, and the two ways an
   operator adds a private CA. The website already carries the operator-facing
   version (`/documentation/configuration#backend-ca`); the developer page is
   where the *why* and the file paths belong.
2. **A backend certificate that fails verification is logged at error level and
   is distinguishable from every other backend error.** Today it is a
   `500 InternalError` whose only error-level line reads
   `S3 operation failed … error_code=InternalError status_code=500`, identical to
   any other internal failure; the x509 reason surfaces only at `debug`. An
   operator on `info` has no way to tell a CA problem from anything else.

## What the tree looks like today

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
  `internal/proxy/server.go:192-220` leaves the SDK transport alone, and only
  the insecure branch installs a `tls.Config` (with `InsecureSkipVerify` and the
  `Warn` at line 204). System roots therefore apply, and `SSL_CERT_FILE` works
  without any proxy change.
- **Where the log lines come from.** `ErrorWriter.WriteS3Error`
  (`internal/proxy/response/errors.go:38-70`): the raw error is logged at debug
  as `S3 operation error detail` (line 59), then `S3 operation failed` at error
  for a 5xx (line 62) or warn for a 4xx (line 64), with `bucket`, `key`,
  `error_code`, `status_code`. A backend TLS failure reaches `MapError` with no
  `APIError` and `StatusCode: 0`, so it is internal by definition
  (`docs/developer/errors.md`, *How a backend error is classified*) and answers
  `500 InternalError`.
- **The error chain**, as the debug line prints it for `ListBuckets` against a
  MinIO under a private CA with verification on:
  `operation error S3: ListBuckets, exceeded maximum number of attempts, 3,
  https response error StatusCode: 0, RequestID: , HostID: , request send
  failed, Get "https://minio:9000/?x-id=ListBuckets": tls: failed to verify
  certificate: x509: certificate signed by unknown authority`.
  Every link in it unwraps: `*smithy.OperationError` → `*retry.MaxAttemptsError`
  → `*awshttp.ResponseError` → `*smithyhttp.RequestSendError` → `*url.Error` →
  `*tls.CertificateVerificationError` (Go ≥ 1.20, field `Err`) → the x509 error
  (`x509.UnknownAuthorityError`; `x509.HostnameError` and
  `x509.CertificateInvalidError` sit in the same place for a name mismatch and
  an expired certificate). `errors.As(err, &certErr)` on
  `*tls.CertificateVerificationError` should reach it; **verify with a test
  before relying on it** — see the work list.

## Measured

Four runs of the 5.0.0 release image (`--platform linux/amd64` on this Mac; the
image is amd64-only) against the demo stack's MinIO, whose certificate is issued
by `test/ssl-setup/ca.crt` (SAN `minio`, valid to 2036), with the minimal
configuration and **no** `insecure_skip_verify`, `aws s3 ls` through the proxy:

| Run | Result |
|---|---|
| No private CA | `InternalError` after the SDK's retries; log at `info` shows only `S3 operation failed`; at `debug` the x509 line above |
| `-v ca.crt:/etc/ssl/custom/ca.crt:ro -e SSL_CERT_FILE=/etc/ssl/custom/ca.crt` | round trip succeeds; bundle untouched |
| image bundle + private CA concatenated, mounted over `/etc/ssl/certs/ca-certificates.crt` | succeeds |
| private CA alone mounted over `/etc/ssl/certs/ca-certificates.crt` | succeeds — the proxy has one outbound TLS peer |

That "the public roots stay trusted beside `SSL_CERT_FILE`" is from the Go source
only; the proxy has no second TLS peer to prove it against.

## Investigated 2026-09-14 — consequences, and what the work list was missing

A second pass over the tree, verified in the code and in the module cache on
2026-09-14 against this branch. Each item says what it changes about the work
list above. Nothing here was measured in a container; where a claim is read out
of source rather than run, it says so.

### A. The operator pattern item 1 wants to document already runs in CI

`test/e2e/velero/values-proxy.yaml` mounts the test CA as a Secret at `/app/ca`,
sets `SSL_CERT_FILE=/app/ca/ca.crt` and keeps `insecure_skip_verify: false`, so
the Velero suite validates the MinIO chain for real inside kind. That is
*exactly* pattern one, in the chart, on a release gate — the developer page
should cite it as the worked example rather than inventing one, and the e2e
values file is the thing to keep in step if the wording changes.

The chart keys are **`volumes`, `volumeMounts` and `env`**, not
`extraVolumes`/`extraEnv`: `deploy/helm/s3-encryption-proxy/values.yaml:166-172`
and `:263`, consumed by `templates/deployment.yaml:114-140`. Any snippet in the
docs has to use those names.

No shipped `config/*.yaml` example runs with verification on — all four set
`insecure_skip_verify: true` — and `scripts/conformance-run.sh:200` templates it
as `${INSECURE}`. So the one configuration in the repository that verifies a
backend certificate is a Helm values file, not a config example. That is worth a
sentence in the docs and it is also why item 6 has to hand-write its config.

### B. A rotated CA does not roll the pod — confirmed, and sharper than stated

`templates/deployment.yaml` carries `checksum/config` (line 24) and
`checksum/secret` (line 29), both computed over the **chart's own** ConfigMap and
Secret templates. A CA the operator brings through `volumes` is in neither.
Together with Go's `sync.Once` root load that means a rotated CA needs a manual
`kubectl rollout restart`, and nothing in the chart or the log will say the pod
is running on the old roots. Document it as the consequence it is; do not fix it
here.

### C. Nothing tells the operator before the first client request

Verified: there is **no backend probe at startup and none behind `/health`**.
`internal/proxy/router.go:41-72` wires the health handler to shutdown state and
the request tracker only, and `ListBuckets`/`HeadBucket` are reached from
handlers alone. So a backend the proxy cannot verify produces a pod that goes
Ready, passes its probes, and answers `500 InternalError` to every client
request. Item 2 makes that state legible in the log; it does not make it visible
before traffic arrives. See the open question below — it is a decision, it wants
an ADR, and it is not this ticket.

### D. The failure costs three TLS handshakes per request, and no retry can work

`retry.RetryableConnectionError.IsErrorRetryable`
(`aws-sdk-go-v2@v1.47.0/aws/retry/retryable_error.go:94`) matches
`interface{ ConnectionError() bool }`, and `*smithyhttp.RequestSendError`
implements it returning **`true` unconditionally**
(`smithy-go@v1.28.1/transport/http/client.go:137`). A certificate that cannot be
verified is therefore retried to the attempt ceiling — which is where the
`exceeded maximum number of attempts, 3` in the recorded chain comes from —
although no retry can succeed until an operator acts. Three handshakes per client
request, and the client's own SDK then retries the 500 on top. Raised here
because the project's rule is to report an underperforming path rather than pass
it: it is small in absolute terms and it is pure waste. Whether to fix it is an
open question below.

`ConnectionError()` is also the ready-made hook for the *neighbouring classes*
question: refused connection, timeout and handshake failure all carry it, and the
certificate case is the subset that additionally carries a
`*tls.CertificateVerificationError`. Any classification helper should be shaped
so the second can be added without rewriting the first.

### E. The unwrap chain is real, checked in the module cache — and the test is still required

Every link verified in source, not inferred from the printed text
(`aws-sdk-go-v2 v1.47.0`, `smithy-go v1.28.1`, both pinned in `go.mod`):

| Link | Where | How it unwraps |
|---|---|---|
| `*smithy.OperationError` | `smithy-go/errors.go:57` | `Unwrap` |
| `*retry.MaxAttemptsError` | `aws-sdk-go-v2/aws/retry/errors.go:18` | `Unwrap` |
| `*awshttp.ResponseError` | `aws/transport/http/response_error.go:31-33` | **no `Unwrap`** — an `As(target)` hook forwarding into the embedded value |
| `*smithyhttp.ResponseError` | `smithy-go/transport/http/response.go:28` | `Unwrap` |
| `*smithyhttp.RequestSendError` | `smithy-go/transport/http/client.go:142` | `Unwrap` |
| `*url.Error` → `*tls.CertificateVerificationError` → the x509 error | stdlib | `Unwrap` |

So `errors.As` should reach. **Item 3 stays mandatory, and the reason is now
named**: the third row is an `As` hook rather than an `Unwrap`, it is the one
link in the chain that a dependency bump can change without a compile error, and
Renovate moves these two modules regularly. A test that drives the real SDK is
the only thing that would notice.

### F. `ErrorWriter` cannot say `backend_endpoint` today — decide which way before starting

It holds a `*logrus.Entry` and nothing else (`internal/proxy/response/errors.go:24-33`),
and it is constructed at eight non-test sites (`middleware_setup.go`, `router.go`,
`errors.go`, and the `bucket`, `object`, `multipart`, `multipart/copy` and `root`
handlers). Three ways out, cheapest last:

1. the base logger the handlers are built on already carries the endpoint — **not
   verified**, it is `s.logger`; check it first, because if it does the field is free;
2. `NewErrorWriter(logger, backendEndpoint)` — eight call sites plus every test
   that builds one;
3. leave the field out. `target_endpoint` is already in the startup log, 5.0.0
   reads exactly one backend entry, and the line's job is to name the *cause*, not
   the peer.

Option 3 is the minimum while there is one backend; the field stops being
optional the day more than one entry is read (ticket 037). Whichever is chosen,
the rule the ticket already states holds: never the request URL, which carries the
query.

### G. `request_id` needs no plumbing — resolved

The ticket marked this unverified. `writeErrorDocument` already reads the id back
off the response header the request-id middleware set
(`internal/proxy/response/errors.go:81`, ADR 0008 D12). `WriteS3Error` has the
same `http.ResponseWriter` in hand, so `w.Header().Get(middleware.RequestIDHeader)`
is available at the point the new line is written. Empty only where that
middleware did not run, and then omitted rather than invented — same rule as the
document.

### H. Three documents, not two: `SECURITY_ARCHITECTURE.md` is missing from the work list

§6.6 *Transport* already carries the `Proxy to backend` row and the paragraph
about `insecure_skip_verify` being "a smaller loss than it looks … do not use it
outside development". That paragraph is where an operator deciding between
mounting a CA and switching verification off actually reads, and today it names
no alternative. One sentence pointing at the developer page belongs there, in the
same change — otherwise the threat model keeps recommending against a knob
without saying what to do instead.

Open: does this close or create a hardening item? The gap is documentation, not
behaviour, so probably neither — but the H-list is where a "no documented trust
path, so operators reach for the insecure knob" finding would have lived, and
that should be a conscious call rather than an omission.

### I. The docs' environment-variable story will contradict itself unless handled

`README.md` and `docs/developer/configuration.md` both state that the only
environment mechanism is a `${VAR}` reference inside a named list of fields, with
`S3EP_LICENSE_TOKEN` as the single exception — and configuration.md's *What was
removed in 5.0.0* section is an argument that env-var configuration was harmful.
`SSL_CERT_FILE`/`SSL_CERT_DIR` are read by the **Go runtime**, not by the loader,
so they are not a counterexample. But an operator who has read that sentence will
conclude environment variables do nothing, and stop looking. Both places need one
line drawing that boundary: the proxy reads no key from the environment; the TLS
stack underneath it reads these two.

### J. A backend fault after the status is out is logged as a client disconnect

`reportStreamFault` (`internal/proxy/handlers/object/helpers.go:122-137`) splits
on the integrity sentinels; **everything else** becomes
`Warn("The response body stopped before the object ended")` and increments
nothing. A whole-object GET makes two backend requests, so a backend fault can
land there.

For the *certificate* case this is not reachable in practice: roots load once per
process, so if the first request verified, the second does too. It is reachable
for the neighbouring classes in D — a reset, a timeout, a backend that goes away
mid-object — and there they are currently reported as a client that went away,
which is the wrong subject. Shape the classification as a helper both
`MapError`/`WriteS3Error` and `reportStreamFault` can call, so that case is a
later two-line change instead of a rewrite.

### K. The website is a different repository — rule 8 applies

Item 1 says the website already carries `/documentation/configuration#backend-ca`.
Not verified from here. If the developer page lands a fact the website
contradicts — `SSL_CERT_DIR`, the rotation-needs-a-restart note, the chart's real
key names from A — that is a change in `s3ep-website`, which is a sibling repo:
write `local_<name>.md` in **this** project describing the edit, or ask for
"mach es direkt". Do not edit it as part of this ticket.

### L. Item 6's plan works — verified

`test/ssl-setup/gen-certs.sh` builds one leaf certificate and copies it to
`minio.crt`; its SAN block (lines 56-76) carries `localhost` and `127.0.0.1`
alongside the container and Kubernetes names. So a locally built binary pointed
at `https://localhost:9000` with verification on does reproduce row one of
*Measured*. The config for it has to be written by hand — see A.

## Work list

1. **`docs/developer/configuration.md`** — new section, suggested title *The CA
   bundle, and a backend under a private CA*, placed after *3. `${VAR}`
   references*. Content: the bundle's path and provenance; the Go loading rule
   above and what `SSL_CERT_FILE` / `SSL_CERT_DIR` each replace; that the proxy
   sets no `RootCAs` and only the insecure branch touches `tls.Config`; the two
   operator patterns (name the CA in `SSL_CERT_FILE`, or replace the bundle —
   with the note that a bundle holding only the private CA is legitimate because
   the backend is the one TLS peer and the license check phones nowhere); roots
   are loaded once per process, so a rotated CA is a restart, and the chart does
   not roll a pod for a volume the operator added; `insecure_skip_verify` is not
   the answer. Cross-link `README.md` (*Complete configuration file structure*,
   the `insecure_skip_verify` line) and the errors page once item 2 lands.
   Mark shown values `# default` / `# example` per the documentation standard.
   Findings A and B supply the content: cite `test/e2e/velero/values-proxy.yaml`
   as the worked example instead of inventing one, use the chart's real key names
   (`volumes` / `volumeMounts` / `env`), and state that no shipped `config/*.yaml`
   example verifies a backend certificate.
2. **Classify the failure in `WriteS3Error`** (or in `MapError`, which is the
   one place that already walks the chain with `errors.As`): when the chain
   carries a `*tls.CertificateVerificationError`, log **one error-level line
   with its own message** — e.g. `backend certificate verification failed` —
   carrying `backend_endpoint` (the configured `target_endpoint`, never the
   request URL with its query), the x509 `reason` (the wrapped error's text,
   which names unknown authority / hostname / expiry), plus `bucket` and `key` as
   today — and `request_id`, which finding G resolves: it is not on the writer's
   entry, but `WriteS3Error` holds the same `http.ResponseWriter` the document
   reads it back off, so no plumbing is needed (ADR 0008 D12a). Findings D, F and
   J shape this item — read them before starting. Keep the response as it is unless the open
   question below is decided: the *client-facing* wording per code is fixed
   (`docs/developer/errors.md`, *What never reaches a client*), and this ticket
   is about the log. Consider a field that other tooling can key on
   (`cause=backend_certificate`) rather than relying on message text alone.
3. **A unit test that produces the real chain**: `httptest.NewTLSServer` (its
   certificate is self-signed, so the system pool refuses it), an
   `aws-sdk-go-v2` S3 client pointed at it with retries off, one call, then the
   classification asserted on the returned error. That pins that `errors.As`
   reaches through the SDK wrappers — the assumption the whole item rests on.
   `internal/proxy/response/errors_coverage_test.go` is where the neighbouring
   assertions live. Finding E says why this is not optional: one link in the
   chain is an `As` hook rather than an `Unwrap`, so a Renovate bump of
   `aws-sdk-go-v2` or `smithy-go` could break it without a compile error.
4. **`docs/developer/errors.md`**: add the new line to *When the status is
   already out*'s sibling section on classification — what is logged at error
   level for a backend TLS failure, why the response stays what it is, and that
   the x509 text is a `reason` field and never a response body.
5. **`README.md`**: one sentence beside `insecure_skip_verify` pointing at the
   developer page, so an operator who finds the key finds the right answer.
6. Re-run the first row of *Measured* against a locally built binary to see the
   new line (`make build`, then the strict config against
   `https://localhost:9000`; the demo certificate carries SAN `localhost`,
   confirmed in finding L). The config has to be hand-written — finding A.
   `make test-unit` green; no integration suite is affected.
7. **`SECURITY_ARCHITECTURE.md` §6.6 *Transport*** — finding H. The paragraph
   that tells an operator not to use `insecure_skip_verify` outside development
   names no alternative. One sentence pointing at the new developer section, in
   the same change.
8. **The environment-variable boundary** — finding I. One line each in
   `README.md` (*Environment Variable References* / *The container's own
   configuration*) and `docs/developer/configuration.md`: the proxy reads no
   configuration key from the environment, and `SSL_CERT_FILE` / `SSL_CERT_DIR`
   are read by the Go TLS stack underneath it, not by the loader. Without it the
   new section reads as a contradiction of the 5.0.0 removal argument.
9. **Decide finding F before writing code**: whether the new line carries
   `backend_endpoint` at all, and if so how the writer learns it. Cheapest
   answer today is to leave it out; the field becomes necessary when more than
   one `s3_backends` entry is read (ticket 037).

## Open questions

- **Is `500 InternalError` the right class for a backend the proxy cannot
  verify?** It is not transient in the SDK's sense — a retry cannot succeed
  until an operator acts — but it is not a state of the object either, so the
  4xx rule in `docs/developer/errors.md` does not apply. S3 has no code for "the
  storage behind this endpoint is unreachable"; `503 ServiceUnavailable` would
  be retried like the 500 is. Leaving the response alone and fixing the log is
  the minimal answer; changing the class is a decision and would want an ADR.
- **Neighbouring classes.** A backend that refuses the connection, times out or
  fails the TLS handshake for a protocol reason lands on the same generic line.
  Whether they get their own message (`backend unreachable`) in the same change
  or later is open; the certificate case is the one an enterprise rollout hits
  first. Finding D names the mechanism that would make this cheap:
  `interface{ ConnectionError() bool }` is what every one of them carries, and
  the certificate case is the subset that also carries a
  `*tls.CertificateVerificationError`. Shape the helper so the wider case is a
  later addition, not a rewrite.
- **Should a certificate verification failure be retried at all?** Finding D:
  it is retried to the attempt ceiling — three TLS handshakes per client
  request — because `*smithyhttp.RequestSendError` reports `ConnectionError()`
  as true unconditionally, and no retry can succeed until an operator acts. A
  retryer that stops on `*tls.CertificateVerificationError` would fix it. Small
  in absolute terms and pure waste; raised because the project's rule is to
  report an underperforming path rather than pass it. Open whether it belongs in
  this ticket at all, since it changes behaviour rather than a log line.
- **Should the proxy check the backend before it reports Ready?** Finding C:
  there is no backend probe at startup and none behind `/health`, so an
  untrusted CA produces a pod that passes every probe and fails every client
  request. Naming it at deploy time instead of at first traffic is the
  difference between an operator finding it and a user finding it. It is a
  decision — a startup probe that fails closed changes what "the proxy starts"
  means, and a readiness probe that talks to the backend couples the pod's
  readiness to the backend's availability. It wants an ADR and probably its own
  ticket; it is named here because this ticket is where it surfaced.
- **Does this close or create a hardening item?** Finding H. The gap is
  documentation rather than behaviour, so probably neither — but the H-list is
  where "no documented trust path, so operators reach for the insecure knob"
  would have lived. Make it a conscious call.
- **Is a config example with verification on worth shipping?** Finding A: no
  `config/*.yaml` example sets `insecure_skip_verify: false`, so the docs will
  describe a configuration the repository does not contain. A fifth example or a
  documented snippet — and a fifth example is also a new file
  `TestCfgShippedExamplesCarryNoUnknownKeys` globs.
- **Does the website need a matching change, and by which route?** Finding K.
  `s3ep-website` is a sibling repository, so under rule 8 this is either a
  `local_<name>.md` ticket in this project or an explicit "mach es direkt" — not
  an edit made in passing.

## Done when

- Both developer pages carry the sections above, `README.md` points at them, and
  `SECURITY_ARCHITECTURE.md` §6.6 names the alternative to `insecure_skip_verify`.
- The environment-variable boundary is stated wherever the docs claim the proxy
  reads nothing from the environment.
- A backend under an unknown CA produces exactly one error-level line per
  failed request whose message and fields identify the cause without `debug`,
  pinned by a unit test that drives the real SDK error chain.
- `make test-unit` is green and this file is in `archive/`.
