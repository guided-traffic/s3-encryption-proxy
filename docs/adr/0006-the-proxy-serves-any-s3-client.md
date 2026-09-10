# ADR 0006: The proxy serves any S3 client

## Status

**Accepted.** Date: 2026-09-07.

This ADR decides how compatibility questions are argued and how the product
describes itself; it is a rule, not a feature. **Implemented today:** the
user-facing reference and the security architecture state the scope as written
here, and every general finding in them names the general condition first and a
client only as an example.

**One of the five gaps is closed:** the stored format's ranged reads are verified by the
proxy itself (ADR 0003). **Four remain, and they are the release's outstanding work**, since
everything ships as one bundle: a real listing document with plaintext sizes (ADR 0010),
conditional request headers beyond `If-Match`/`If-None-Match` on `GET`, verification of
client checksums (ADR 0012), and forwarding of the storage headers a `PUT` still drops
(ADR 0007 D3). To them add `ListParts`, which answers a fabricated empty document for any
upload id — a generic client that verifies its own upload is told it has no parts, which is
the shape D2 and D3 exist to forbid.

**Proof today is narrow:** exactly one client — Velero, whose node agent uploads
through kopia — has an end-to-end suite (`make e2e-up`, `make test-e2e-velero`).
CloudNativePG Barman is a named client with no suite of its own.

## Context

The product is a transparent S3 encryption proxy. It terminates the S3 API,
encrypts on the way in, decrypts on the way out, and a client talks to it exactly
as it would talk to S3. Nothing in that description names a client, and nothing
in the deployment prevents one: an operator points an endpoint at the proxy and
whatever speaks S3 arrives.

The work of September 2026 was nevertheless driven by building an end-to-end
suite for one client, and that suite paid for itself — it found four defects that
each blocked that client outright. It also crept into the reasoning. Documents
began to describe the proxy as built for that client. Compatibility questions
were settled by asking what that client sends.

The concrete failure, on 2026-09-07: a decision brief on the storage headers a
`PUT` silently discards proposed refusing six of them — server-side encryption
and SSE-KMS, customer-provided keys, `x-amz-tagging`, `x-amz-acl` and the grant
headers, `x-amz-website-redirect-location`, and the `PUT ?acl` / `PUT ?cors`
request bodies — and argued it per header with "no known caller", "no known
consumer" and "the deployment the end-to-end suite installs sets none of these".
The owner rejected the framing outright. The defect was the silent drop answered
with `200`; refusing is right only where forwarding creates a trap the client
cannot see; and the confidentiality of the object content, which is the proxy's
job, is touched by none of those headers. Re-checked against S3 semantics instead
of against one client, exactly one refusal survived: customer-provided keys
(`x-amz-server-side-encryption-customer-*`), because no read path carries the key
back, so such an object could never be read again. Everything else is forwarded,
and the discarded `?acl` / `?cors` bodies are parsed and forwarded instead. An
argument from the observed client set had produced five wrong answers out of
six.

A second instance the same day: per-IP failure counting was argued away with "a
backup node agent bursts from one pod IP". The conclusion was right and the
argument was not — any S3 client bursts from one address, and clients behind NAT
or an ingress share one.

The same shape shows up wherever a finding was written down under the name of the
client it was found with. A ranged read that the proxy does not verify is the read
path of every client that reads ranges, not "the kopia path". A 30-second write
deadline on the listener kills any transfer slower than that, not just one
tool's archive download. A discarded `Content-MD5` discards the integrity intent
of every client that sends one. Each of those was found through one client and
applies to all of them.

Scoping the product at one tool also mis-sets the security bar. "Supported for
one backup tool" says nothing about a client with a different access pattern,
and the gaps that matter — an unverified partial read, an object whose encryption
metadata was stripped — are properties of the stored format, not of the client.

## Decision

**D1.** The proxy serves **any** S3 client. Velero with kopia and CloudNativePG
Barman are named example clients; the `aws` CLI, rclone and the AWS SDKs are
ordinary clients. No client, named or exercised, defines the scope.

**D2.** A compatibility question is answered against **S3 semantics** — what AWS
S3 does with that request — and not against what any one client sends. Where the
proxy deliberately differs, the difference is documented as a limit in the
user-facing reference.

**D3.** "No client in scope does X" is not an argument. It is admissible only
when X is impossible in S3. "No client we have observed does X today" may set
priority; it never decides what the answer is.

**D4.** A defect found through one client is stated, and fixed, for every client
it applies to. Its write-up names the general condition first and the client as
the example that surfaced it.

**D5.** The end-to-end suite proves **one client end to end**. It is evidence
about that client and never evidence about the scope; a change exercised only by
that suite is not thereby shown to be safe for anyone else. Behaviour that every
client sees is proven by the integration suites over both the plain and the TLS
endpoint, or by a new suite.

**D6.** Client-observable behaviour is documented in the general reference, not
in a per-client section. A per-client section carries only that client's
configuration and the notes specific to it.

**D7.** Support is claimed only as far as it is exercised, and the claim says
which kind of proof it rests on: an end-to-end suite, an integration suite, or a
documented configuration that nothing here runs.

## Consequences

- **More surface has to be right.** A backup tool exercises a narrow slice of
  S3. A generic client does not: listings with their parameters and their sizes,
  conditional requests, versioning, storage and lock headers, upload checksums,
  ranged reads, error documents. Several of those are known-incomplete today,
  and each is now a defect rather than an out-of-scope gap.

- **A green end-to-end run is not sufficient evidence.** The heavier weight moves
  to the integration suites, and any gap in them is a gap in the evidence — which
  is a real cost, because a suite that covers one SDK is not a suite that covers
  every client.

- **Cheap refusals are gone.** "No known caller" no longer closes a question, so
  interfaces get implemented or refused on S3 grounds, sometimes for a header no
  measured client sends. That is deliberate work spent on latent demand, and the
  code paths it creates are the least exercised in the product.

- **Documentation costs more.** Every finding is written for all clients, with
  the observed one as an example. Rewriting the reference and the security
  architecture on 2026-09-07 was that cost paid once; keeping them that way is
  the recurring part.

- **No leaning on the client's own crypto.** A client that encrypts or checksums
  its own repository protects that client's data only, and only when it is
  configured to. It is never a substitute for the proxy's own guarantees and
  never an argument for weakening them.

- **Narrower support claims.** "One client has end-to-end proof, the rest are
  ordinary S3 clients" reads as less than "built for X". It is what is true.

## Alternatives Considered

- **Scope the product at one client — an encryption sidecar for one backup
  tool.** Lost: the code is a generic S3 proxy, ordinary clients already work
  through it, and narrowing the claim narrows nothing real — an operator points
  any client at the endpoint regardless. It would also not shrink the work: the
  gaps that block a generic client (ranged reads, listings, checksums) are the
  same ones that reach that single client through its uploader.

- **Tiered support: one supported client, everything else best effort.** Lost:
  it makes "best effort" the standing answer to any defect the supported tool
  does not happen to hit, which is exactly how a `PUT` that discards storage
  headers and answers `200` survived. The quality bar becomes what one tool
  notices.

- **Define the scope as the set of clients that have an end-to-end suite.** Lost:
  a suite means a cluster, a bring-up and tens of minutes per run, so that set
  would never grow past one or two. Every other client would keep using the
  endpoint with no stated support at all — the honest version of the same gap,
  not a fix for it.

- **Keep the general scope, but let the observed client set decide contested
  compatibility calls.** Lost: that is precisely the reasoning the storage-header
  brief was rejected for, and it had produced the wrong answer on six of seven
  headers.

## Residual risks

- **One client has end-to-end proof; the other named client has none.** Nothing
  in this repository exercises a database backup path, so the CloudNativePG
  Barman claim rests on configuration and reasoning, not on a run. Unverified.

- **Broad scope, narrow test matrix.** The integration suites are written against
  one SDK. Behavioural differences of other clients — rclone, older SDKs,
  infrastructure tools that drive S3 reflexively — are not exercised. Not
  verified, and the most likely source of the next compatibility defect.

- **Interfaces specified without a measured caller.** The decided upload
  checksum surface covers algorithms because the header exists, not because any
  observed client sends them. Whether a real client sends them is unverified; if
  none does, that is untested cost once it is built.

- **Customer-provided encryption keys are still open.** They are silently
  dropped today; the decided rule refuses them with `501 NotImplemented`, because
  carrying them on writes alone would produce objects the proxy can never read
  back. Whether to carry them on every verb — the only known reason being a
  backend policy that requires them, and none has shown up — is decided against
  for now and not settled for good.

- **Filename encryption is open, and its value can only be measured for one
  client's key layout.** What a key leaks depends on the client's naming scheme,
  and the measurement available is for one of them. See ADR 0023.

- **"Any S3 client" is not "isolated clients".** Every authenticated client can
  read and write everything the backend credential reaches, under one active key.
  Two clients sharing one proxy share a trust domain; separation is a separate
  deployment. Accepted, and stated in the security architecture.

- **Scope is a compatibility statement, not a security claim.** Until the stored
  format is one the proxy verifies on every read, the backend must be treated as
  trusted infrastructure — for every client, the named ones included. See
  ADR 0001 and ADR 0003.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0007 — Forward it or refuse it, never silently drop it
- ADR 0010 — Sizes and listings describe the plaintext
- ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt
- ADR 0012 — Client-supplied checksums are verified against the plaintext and never forwarded
- ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
- ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
- ADR 0023 — Filename encryption, if it ships, encrypts directory segments only
- [README.md](../../README.md) — user-facing reference, client usage and the documented limits
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model, trust boundaries, residual risks
