# 042 — A backend failure that cannot resolve itself is not retried

Split out of the backend-trust refining session on 2026-09-18, where it was
raised and deliberately left out of that ticket's scope: it changes behaviour
rather than reporting, and it wants a decision of its own.

## What it is

A backend certificate that does not verify is retried to the SDK's attempt
ceiling — three TLS handshakes per client request — although no retry can
succeed until a person changes something. The client's own SDK then retries the
`500` on top, so one client operation can cost nine handshakes against a peer
that will refuse every one of them.

## Why it happens, verified 2026-09-18

`retry.RetryableConnectionError.IsErrorRetryable`
(`aws-sdk-go-v2@v1.47.0/aws/retry/retryable_error.go:94`) matches
`interface{ ConnectionError() bool }`, and `*smithyhttp.RequestSendError`
(`smithy-go@v1.28.1/transport/http/client.go:137`) implements it returning
**`true` unconditionally**. Every send-side failure is therefore retryable by
construction, and nothing distinguishes a peer that is briefly unreachable from
a peer this proxy will never be allowed to talk to.

The `exceeded maximum number of attempts, 3` in the recorded error chain of the
backend-trust work is this, observed.

## What it would take

A retryer that is asked once more before it retries: if the error carries a
`*tls.CertificateVerificationError`, stop. Everything else keeps today's
behaviour. The backend observer already resolves that exact condition for its
failure class, so the predicate exists and has tests — what is missing is a seam
where the SDK's retry decision can consult it.

## What has to be decided

- **Is the certificate case the only one that stops?** A DNS name that does not
  resolve and a connection refused are equally hopeless within one request, but
  unlike a certificate they can become true a second later without anybody
  acting. The certificate case is the only one where the product can be sure.
- **Does stopping the retry change what a client sees?** It should not — the
  answer is `500 InternalError` either way (ADR 0037 D8) — but it arrives sooner,
  and a client that measured the old latency will notice the difference before
  it notices the saving.
- **Is it worth it at all?** Three handshakes on a path that needs a human is
  pure waste, and it is small. Raised because this project reports an
  underperforming path rather than passing it; what to do about it is not
  therefore automatic.
- **Where does the seam go** so that it is one decision consulted by the SDK,
  and not a second copy of the classification that can drift from the first.

## Done when

The behaviour is decided, and either built with a test that proves one handshake
where there were three, or recorded as deliberately not built with the reason.
