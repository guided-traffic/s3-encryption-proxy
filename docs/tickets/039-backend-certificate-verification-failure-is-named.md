# 039 — A backend certificate the proxy does not trust is named, in the log and in the developer docs

Raised 2026-09-14 by the owner, out of the website documentation work: an
enterprise backend usually presents a certificate from a private CA, and today
neither the docs nor the log say where the CA bundle is or what a missing CA
looks like. **Two work items, both small, to be done in a session of their own.**
Everything under *What the tree looks like today* was verified on 2026-09-14
against release 5.0.0; the four runs under *Measured* were executed, not
reasoned about.

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
2. **Classify the failure in `WriteS3Error`** (or in `MapError`, which is the
   one place that already walks the chain with `errors.As`): when the chain
   carries a `*tls.CertificateVerificationError`, log **one error-level line
   with its own message** — e.g. `backend certificate verification failed` —
   carrying `backend_endpoint` (the configured `target_endpoint`, never the
   request URL with its query), the x509 `reason` (the wrapped error's text,
   which names unknown authority / hostname / expiry), plus `bucket` and `key` as
   today — and `request_id`, if the entry the writer is built on carries it
   (not verified; the access log line does, ADR 0008 D12a). Keep the response as it is unless the open
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
   assertions live.
4. **`docs/developer/errors.md`**: add the new line to *When the status is
   already out*'s sibling section on classification — what is logged at error
   level for a backend TLS failure, why the response stays what it is, and that
   the x509 text is a `reason` field and never a response body.
5. **`README.md`**: one sentence beside `insecure_skip_verify` pointing at the
   developer page, so an operator who finds the key finds the right answer.
6. Re-run the first row of *Measured* against a locally built binary to see the
   new line (`make build`, then the strict config against
   `https://localhost:9000`; the demo certificate carries SAN `localhost`).
   `make test-unit` green; no integration suite is affected.

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
  first.

## Done when

- Both developer pages carry the sections above and `README.md` points at them.
- A backend under an unknown CA produces exactly one error-level line per
  failed request whose message and fields identify the cause without `debug`,
  pinned by a unit test that drives the real SDK error chain.
- `make test-unit` is green and this file is in `archive/`.
