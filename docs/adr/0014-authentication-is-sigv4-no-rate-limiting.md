# ADR 0014: Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: both SigV4 forms, static client credentials with their length minimums,
constant-time signature comparison, a fixed failure message per error code, unauthenticated
`/health` and `/version`, an unauthenticated monitoring listener, and profiling endpoints on
their own loopback listener that refuses a non-loopback address at startup.

**Amended 2026-09-10: the deletions have landed, the two additions have not.** `s3_security`
carries `max_clock_skew_seconds` and nothing else — the six keys no code read are gone from the
configuration, from every shipped example and from the production chart values. The per-address
failure map went with them, and with it the unbounded key space, the hardcoded threshold and the
log line about a potential brute-force attack; nothing in the proxy counts, keys on, or decides
anything from a client address any more. A security event logs `remote_addr` and
`x_forwarded_for` as two raw fields and interprets neither, which is D8 in full, and no shipped
configuration key suggests a limiter that does not exist, which is D7 in full. Both
understatements this block used to carry are closed.

**Implemented 2026-09-11:** `s3_security.max_presign_expiry_seconds` with its 3600-second
default and the S3 seven-day maximum as a hard cap (D5), and `s3_security.max_clock_skew_seconds`
governing the `Authorization`-header form as well as the pre-signed one (D4). D9's "exactly two
keys" is now true in the tree: every key that read nothing is removed, and both remaining keys
are enforced wherever they can apply — `max_clock_skew_seconds` on both authentication forms,
`max_presign_expiry_seconds` on the pre-signed form, which is the only one that declares a
lifetime.

**Implemented 2026-09-13: D13 and D14.** The blanket `403 InvalidRequest` every authentication
failure used to answer is replaced by the status and code each failure actually warrants, and the
probe pair is matched as a probe rather than as a path. Both were open questions this ADR left to
the owner; both are now decided below and true in the tree.

**Added while implementing D4, and it is a refusal this ADR did not specify:** a configured
`max_clock_skew_seconds` of `0` is refused at startup. It used to be read silently as the
900-second default on both paths — so the value an operator picks to mean "no tolerance" quietly
widened the window to the maximum. There is no value that switches the check off, and ADR 0017 D8
forbids the silent fixup that hid it.

## Context

The proxy sits between an S3 client and a backend it does not trust (ADR 0001). The client leg
is the operator's own; the adversary is on the other side. So the front door has exactly one
job — establish which configured client is calling and that the request was not altered on the
way — and no job at all in defending the client leg against itself.

The proxy serves any S3 client (ADR 0006), and real clients use both SigV4 forms: header
signing on the data path, pre-signed URLs for log and download retrieval. Supporting only one
form is not an option; a backup tool that signs its uploads and then hands out pre-signed URLs
for its own downloads breaks on the missing half.

What forced this decision was the other end of the front door — machinery that sounded like
security and was not. Four `s3_security` keys (`enable_rate_limiting`,
`max_requests_per_minute`, `max_failed_attempts`, `unblock_ip_seconds`) were parsed, validated,
defaulted, documented in the README, and set in every shipped example config and in the
production chart values, and no code read any of them. The one construct that looked like an
implementation was a per-address failed-attempt map:

- keyed on the first `X-Forwarded-For` value when the header was present, which on any
  internet-facing deployment is a string the caller chooses;
- never evicted and unbounded, so unauthenticated failing requests with a varying forged header
  grew proxy memory without limit;
- compared against a hardcoded threshold rather than the configured one, and consumed by
  nothing but a log line — nothing was ever blocked;
- written without synchronisation from the request goroutine. Concurrent map writes are not a
  lost update in Go: the runtime terminates the process, and it is not a panic, so the HTTP
  server's per-connection recovery cannot catch it. The path that did it was the authentication
  **failure** path, so two parallel requests with a bad signature and no credentials at all
  were a remote kill switch.

The crash was fixed by serialising the counters. The structure around it could not be fixed the
same way: the question was whether to complete it or delete it, and it was answered twice. On
2026-09-06 the call was to delete the knobs and the map. On 2026-09-07 that was briefly reversed
— keep the map, add a trusted-proxy CIDR allowlist and eviction — and reverted the same day,
because keeping the map only earns that machinery if something reads it, and the only reading
that would justify it is live per-address blocking. Per-address blocking is the wrong instrument
for the clients this proxy serves: one legitimate client is one authenticated identity that
bursts thousands of requests from one address, and any client behind a NAT or an ingress looks
the same. A signing secret of the required minimum length is not guessable, so brute-force
protection at this door is a fiction. Denial-of-service defence belongs in the ingress, which
can actually do it.

Two smaller instances of the same class sat in the same struct. `strict_signature_validation`
and `enable_security_logging` were read by nothing — both fail safe, so nothing was exposed,
but a knob that silently does nothing is the same lie in a smaller font. And the one key that
did work, `max_clock_skew_seconds`, worked on only one of the two authentication forms: the
pre-signed path read it, the header path — which is what every AWS SDK client sends — compared
against a compile-time 900 seconds. An operator tightening the window to narrow replay exposure
tightened nothing on the path that carries the traffic.

The opposite problem existed as well: a control an operator would want did not exist. The
maximum lifetime a pre-signed URL may claim was hardcoded to the S3 maximum of seven days. Seven
days of bearer capability is the wrong default for a proxy whose purpose is to limit exposure;
known clients get by with minutes.

## Decision

**D1** Client authentication is AWS Signature Version 4, in both forms: the `Authorization`
header form and the pre-signed query form (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
`X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`). Both are first-class on every
authenticated route; neither is a degraded mode.

**D2** Clients are static credentials from configuration. At least one `s3_clients` entry is
required or the proxy does not start. The only supported entry type is `static`. An
`access_key_id` is at least 8 characters, a `secret_key` at least 16, and duplicate access key
ids are a startup error.

**D3** Every request authenticated by the `Authorization` header form is checked for: a bounded
header; a credential scope with the right shape, an 8-digit date, service `s3` and terminator
`aws4_request`; an access key id that exists in `s3_clients`; a request timestamp inside the
clock-skew window in both directions; a credential date matching the request date; and the full
SigV4 signature, compared in constant time. A pre-signed request is checked for the same credential
scope, the same access key id, the same credential-date match and the same constant-time signature;
its timestamp rules are D5's — the signing time may not be ahead of now by more than the clock
skew, and the URL is refused once its own declared lifetime plus that skew has passed.

**D4** `s3_security.max_clock_skew_seconds` (default 900) governs both authentication forms. One
key, one configured tolerance, enforced on every path it names; D3 states how each form applies
it.

**D5** `s3_security.max_presign_expiry_seconds` bounds the lifetime a pre-signed URL may claim.
Default 3600 seconds; hard cap 604800 seconds, the S3 maximum, enforced both at configuration
validation and at the point of use. `X-Amz-Expires` is mandatory and positive, and the signing
time is bounded by the clock skew, so a URL cannot extend its own lifetime.

**D6** Per-chunk signatures inside an `aws-chunked` upload are not verified; the seed signature in
the `Authorization` header is. Those chunk signatures protect the client leg, which is
operator-controlled and not the adversary here. The mitigation on that leg is TLS, which is also
what makes an AWS SDK choose the unsigned-trailer framing in the first place.

**D7** The proxy performs no request rate limiting and no per-address blocking, and ships no
configuration key that suggests otherwise. Rate limiting, connection limiting and
denial-of-service defence are the ingress's job.

**D8** The client address is a log field, never an identity. Security events log `remote_addr` and
`x_forwarded_for` as two raw fields and interpret neither. No forwarded header selects a client,
keys a counter, or decides anything in the proxy, so there is no trusted-proxy list to configure.

**D9** `s3_security` carries exactly two keys — `max_clock_skew_seconds` and
`max_presign_expiry_seconds` — and both are enforced. Every other key in that block is removed
rather than documented as unimplemented (ADR 0013).

**D10** An authentication failure answers a fixed message per S3 error code. The attempted access
key id, the signed header names and the clock offset are logged and never echoed into the
response (ADR 0008).

**D11** `/health` and `/version` are unauthenticated by design and are served ahead of the
authentication middleware; D14 says which requests to those two paths are the probe and which
are S3 requests. The monitoring listener carries no authentication at all and is to be
fenced by the network, not by the proxy. Profiling endpoints run on their own listener bound to
loopback; a non-loopback address for them is a startup error, because a heap profile of this
process contains key material and plaintext.

**D12** If throttling is ever wanted in the proxy itself, it arrives as a new configuration key
that lands in the same change as the code reading it and a test that proves it throttles. That
test is the whole point, and it is what the deleted keys never had.

**D13** The status of an authentication refusal follows its S3 error code, and the code names what
actually failed. A request carrying no `Authorization` header at all is anonymous and answers
`403 AccessDenied`. A header carrying a scheme this proxy does not implement answers
`400 InvalidRequest`; a header it cannot parse answers `400 AuthorizationHeaderMalformed`. An
unknown access key id (`403 InvalidAccessKeyId`), a signature that does not match
(`403 SignatureDoesNotMatch`) and a timestamp outside the window (`403 RequestTimeTooSkewed`) keep
the status S3 gives them. The rule is that 400 means the request itself is unusable and 403 means
it was understood and refused; a blanket status for every failure tells a client to fix the wrong
thing, and D10's fixed message per code is only useful if the code is right. Verified against
MinIO on the two cases that differ: anonymous is `403 AccessDenied` there too, and a `Basic`
header is `400 InvalidRequest`. Where MinIO and AWS disagree — MinIO answers an unparseable AWS4
header with status 400 and code `AccessDenied` — this proxy follows AWS, because clients branch on
the code (ADR 0006 D2).

**D14** A request to `/health` or `/version` is the probe only when it is unsigned and carries no
query string at all. Anything else addressed to those two paths is an S3 request for a bucket of
that name — which S3 allows and this proxy does not forbid — and is routed, authenticated and
answered as one. Reserving the two names for the probe would make two legal bucket names
unreachable through the proxy without saying so anywhere; the probe keeps its exemption, the name
does not get one. Both paths keep answering the probe while the proxy drains (ADR 0029 D1).

## Consequences

- An unauthenticated caller can fail signature checks as fast as the network allows, and an
  attempt naming a configured access key id costs a signature computation (one naming an unknown
  key is refused before that). Nothing in the proxy slows either down. A deployment exposed to an
  untrusted network needs a limiter in front of it; a deployment without one has no brute-force or
  flood defence, and that is the accepted position, not an oversight.
- A flood of failing requests carrying a varying forged `X-Forwarded-For` no longer grows proxy
  memory, because there is no map left to grow. It costs CPU and one warning line per attempt,
  which is what the log pipeline has to absorb instead.
- Deployments that set the removed keys do not start. **Updated 2026-09-12:** an unknown key
  refuses the start and the error names it (ADR 0013), so a configuration carrying
  `enable_rate_limiting` or any of the other five has to be edited before the proxy runs. The
  removal is a breaking configuration change with no compatibility shim, and the release carrying
  it is declared major by its label (ADR 0018).
- There is no per-client visibility into failed authentications beyond the log stream: no counter,
  no metric. A Prometheus counter was considered and rejected below, so an operator who wants that
  view builds it from logs.
- An attacker-chosen `X-Forwarded-For` string still reaches the log line. Accepted: being a field
  is now its only role — it is not a key and not a decision input — and the log encoder quotes it.
  It must not be read as the client's identity.
- Lowering the pre-signed ceiling from seven days to one hour breaks any client that relies on
  multi-day URLs until the operator raises the knob. **Landed 2026-09-11:** the break has
  happened. The default is 3600 seconds, the S3 maximum of seven days is only the hard cap a
  configured value may not exceed, and a URL declaring more than the configured ceiling is
  refused.
- Making `max_clock_skew_seconds` apply to the header form tightens behaviour for anyone who
  configured a value below 900. A client whose clock is off by more than the configured window
  stops authenticating, with a clear timestamp error. It is the one change in this family that can
  break a working deployment, and **as of 2026-09-11 it is behind rather than ahead**: a value
  below 900 now applies to the path that carries the traffic.
- A client that signs chunks over plain HTTP and expects the proxy to detect a man in the middle
  gets nothing. The answer is TLS on the client leg.

## Alternatives Considered

- **Implement the two blocking knobs for real: live per-address blocking, a trusted-proxy CIDR
  allowlist, and eviction.** Held for one day and rejected. It puts new security behaviour on the
  authentication hot path, needs its own tests, and is the wrong instrument regardless: legitimate
  S3 clients burst from a single address, and a publicly exposed proxy still needs the ingress to
  limit properly. The kept map would have been infrastructure justified by a control nobody needs
  from this component.
- **Keep the failure map as a counter and only bound it (eviction plus a size cap).** Rejected: it
  is a trusted-proxy question, an eviction policy and a memory bound in service of one log line,
  and it leaves the two knobs dead.
- **Keep the keys and document them as accepted-but-unimplemented.** Rejected. A control that
  exists only in configuration or documentation is worse than no control, because it gets relied
  upon — an operator configures around a limiter that is not there (ADR 0013).
- **A Prometheus counter for failed authentications, labelled by client address.** Rejected: the
  per-address label has exactly the unbounded-cardinality problem the map had, and nothing asked
  for the visibility. If it is wanted, it comes with the dashboard panel that uses it.
- **Verify the per-chunk signature chain.** Rejected: real implementation and real CPU cost on
  every upload, to protect the leg that is not the adversary. Verifying the client's own upload
  checksums against the plaintext buys more of the same benefit for less (ADR 0012).
- **Leave the pre-signed ceiling at the S3 maximum of seven days.** Rejected: it is a bearer
  capability, and the proxy's job is to bound exposure. Known clients mint URLs that live minutes.
- **Make the pre-signed ceiling unbounded so an operator can set anything.** Rejected: the hard cap
  stays at the S3 maximum so that a configured value cannot put the proxy outside what an S3 client
  expects.

## Residual risks

- **Replay inside the signature validity window is undefended.** There is no nonce store, so a
  captured signed request — or a pre-signed URL that leaked — can be replayed as often as the
  attacker likes until its timestamp ages out. The clock-skew window is a freshness bound, not a
  replay defence. Shrinking `max_clock_skew_seconds` shrinks the window on the `Authorization`
  header form; a leaked pre-signed URL lives for its own declared lifetime plus that skew, so the
  knob that shrinks that one is `max_presign_expiry_seconds` (D5). Whether a nonce store is ever
  built is open, and nothing depends on it today.
- **The signature does not cover the request body.** A missing `X-Amz-Content-Sha256` on a
  non-empty body is treated as `UNSIGNED-PAYLOAD`, and the pre-signed form defaults to it, so the
  signature authenticates the request line and headers only. Verifying what the client sent about
  its own bytes is ADR 0012's subject.
- **Whether any deployment outside this repository sets the removed keys is not verified.**
  **Updated 2026-09-12:** such a configuration no longer keeps loading — an unknown key refuses the
  start and the error names it (ADR 0013). The deployment stops until the keys are removed,
  instead of loading while its operator believes a control was lost that never existed.
- **No mechanism prevents the next dead key.** The guard is the rule in D12, not a check; a field
  that is defined and never read passes every decoder.
- **The client address in the logs remains attacker-chosen** wherever the proxy is reachable
  without a sanitising hop. It is not an identity and must not be used as one in any downstream
  alerting.
- **Closed 2026-09-11: the deletions and the two additions they were scoped with are all in the
  tree.** `max_clock_skew_seconds` is now read on both paths. This is the one behaviour
  change in this family that can break a working deployment: a client whose clock is
  between the configured window and 900 seconds off used to authenticate on the header path and
  now does not. Every shipped example configuration and the production deployment values set 300,
  so the window narrows from 900 to 300 for anyone who took one of those as their starting point.
- **A probe that starts signing its requests stops being a probe.** D14 tells the two apart by the
  absence of a signature and of a query string, so a readiness check that is given credentials, or
  a health URL that acquires a cache-busting parameter, is routed to the bucket of that name and
  answers an S3 error instead of the probe document. That is the intended answer, and it is a
  failure mode worth knowing before it is diagnosed as an outage.
- **What "no rate limiting" means operationally is untested.** No measurement exists of how many
  failing authentications per second one instance absorbs before it degrades, so the ingress
  requirement is stated from design, not from a number.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0006 — The proxy serves any S3 client
- ADR 0008 — Every response describes the proxy, never the backend
- ADR 0012 — Client-supplied checksums are verified against the plaintext and never forwarded
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start
- ADR 0015 — A transfer is bounded by the client and by shutdown, not by a server wall clock
- ADR 0016 — The license is a startup gate with an explicit expiry
- ADR 0018 — A major release is declared by a label, never discovered at merge
- [README.md](../../README.md) — the `s3_clients` and `s3_security` configuration reference, and
  the pre-signed URL section
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — trust boundaries, what is verified
  on every request, what is not verified, and the hardening checklist
