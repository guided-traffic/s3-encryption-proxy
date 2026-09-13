# ADR 0013: A configuration key exists only if code reads it, and an unworkable configuration refuses to start

## Status

**Accepted.** Date: 2026-09-07.

**Amended 2026-09-13: D12, D13 and D14 added — the configuration file itself, the license file
the operator names, and the command line. All three were decided on 2026-09-12 and all three
landed 2026-09-13.** They carry this record's theme outwards from the keys to the inputs that
deliver them. What each one ended: a configuration file that could not be opened, or whose YAML
did not parse, was read as no file at all, so the start failed on the missing
`s3_backend.target_endpoint` and told the operator the wrong thing (D12); a written
`license_file` that did not resolve fell through to a fixed list of well-known locations, so a
mistyped path could start the proxy on a token nobody chose (D13); and `--monitoring` and
`--monitoring-port` overruled `monitoring.enabled` and `monitoring.bind_address`, the second of
them unable to express its own default as an override (D14). The binary now declares one flag,
`--config`. D1 through D11 are unaffected and stay as described below.

**Not built as of 2026-09-13: four of D7's zero cases.**
`optimizations.streaming_segment_size` at zero or below falls back to 12 MB for the part size
only, while the single-request ceiling reads the written value, so every PUT of a non-empty body
goes through the multipart producer; `optimizations.multipart_upload_concurrency` at zero falls
back to 4 and `optimizations.multipart_short_part_buffer_size` to 64 MB; and
`optimizations.multipart_session_cleanup_interval` at zero switches the periodic session sweeper
off. Each is a gap rather than a design.

**D1 through D11 are implemented on the 5.0.0 branch, except those four zero cases; the last key
this decision named as dead went 2026-09-11.** Every one of them is gone —
from the loader, from every shipped example configuration and from the production deployment
values — and the log line D2 attached to that deletion landed with it.

Deleted: the six `s3_security` keys (`strict_signature_validation`, `enable_rate_limiting`,
`max_requests_per_minute`, `enable_security_logging`, `max_failed_attempts`,
`unblock_ip_seconds`) together with the per-address failure accounting behind them, which left
`s3_security` with one key, `max_clock_skew_seconds` (the second key D2 names,
`max_presign_expiry_seconds`, arrived with D6 on 2026-09-11); `s3_backend.use_tls` (D4); the
legacy top-level backend block (`target_endpoint`, `region`, `access_key_id`, `secret_key`,
`use_tls`, `skip_ssl_verification`) and the migration that folded it into `s3_backend` (D9);
`optimizations.streaming_buffer_size` and
`optimizations.enable_adaptive_buffering` (D9, amended 2026-09-09); and
`optimizations.streaming_threshold` and `encryption.integrity_verification` (amended
2026-09-10). With `integrity_verification` go the modes `off`, `lax`, `strict` and `hybrid`:
integrity is no longer a setting, it is a property of the stored format (ADR 0003). Two
never-read defaults this ADR had not named, `encryption.algorithm` and
`encryption.key_rotation_days`, went with them.

The authentication-failure log line is what D2 specified: the peer address and the forwarding
header as two raw fields, interpreted as nothing. The fields that invited interpretation,
`client_ip` and `failed_count`, are gone, and so is the branch that compared a hardcoded
threshold and announced a brute-force attempt. The one key added in the same wave,
`optimizations.multipart_short_part_buffer_size`, arrived with the code that reads it and a
startup range check (ADR 0011) — D1 applied rather than repaired afterwards.

**Implemented 2026-09-11, the rest of it.**

- **D11.** The loader decodes in its exact mode: a key the proxy does not define refuses the
  start and the error names it, with a line telling the operator that a key removed by a release
  is listed in its notes. A provider block keeps swallowing its own parameters, which is
  asserted rather than assumed, and every shipped example configuration is decoded in a test so
  that a file this repository hands out cannot be one that refuses to start.
- **D3.** `s3_security.max_clock_skew_seconds` governs both authentication forms. The
  header-signed path used to compare against a package constant, so a deployment that tightened
  the window — every shipped example sets 300 — kept a window three times wider on the path most
  requests take. The second, unreachable comparison beside it is gone: it tested the same
  quantity without the absolute value. **`0` is now refused** rather than read silently as the
  default: at second granularity it can only be a misunderstanding of "switch it off", and a
  silent fixup is what ADR 0017 D8 forbids.
- **D4, second half.** A `target_endpoint` without a scheme, or with one the SDK does not speak,
  is a startup error naming the key. The string used to reach the SDK verbatim.
- **D5** (amended 2026-09-12). A plain-HTTP backend refuses the start under every provider, and
  the message says what a listener learns and why an upload would fail rather than only that the
  endpoint is wrong. The `exit` provider was exempt until the exemption was measured: it started
  and then answered `500` to every single-request upload. The warning that named the endpoint is
  gone with it.
- **D6.** `s3_security.max_presign_expiry_seconds` exists, defaults to 3600 and is bounded by
  the S3 maximum of seven days. The ceiling is enforced at the point of use as well as in
  validation, because a configuration assembled in code never passes through validation.
- **D9a, 2026-09-11.** `optimizations.clean_aws_signature_v4_chunked` is gone from the loader,
  the defaults, the two shipped examples and the Velero values; aws-chunked decoding is
  unconditional. A configuration still carrying the key is refused by name at startup (D11).
- **D9, the last key, 2026-09-11.** `optimizations.clean_http_transfer_chunked` is gone with the
  decoder it gated and with that decoder's base type — three shipped examples and the Velero
  values carried it, not the one this ADR used to name. The premise was re-proved before the
  deletion: the Go HTTP server deletes the `Transfer-Encoding` header from the request
  unconditionally before dispatch, answers an unsupported value itself, and refuses the header
  outright on the HTTP/2 listener, so the branch could not fire on any transport this proxy
  serves. Body decoding now carries no configuration at all.

**D5 is complete, 2026-09-12.** The refusal half refuses a plain-HTTP backend under every
provider, the `exit` one included. One warning survives beside it: a start under the `exit`
provider logs what that provider costs — new objects are stored unencrypted, while objects an
encrypting provider wrote earlier are still decrypted on read as long as it stays configured. It
is the exit provider's alone; an encrypting provider cannot reach it. The second line that named
an `http://` endpoint went with the exemption it described: that configuration no longer starts.

**Amended 2026-09-10: a reader is not an effect.** D1 tests a key by asking whether code reads
it. The dead-code sweep found a pair that passes that test and did nothing:
`optimizations.multipart_session_cleanup_interval` and `optimizations.multipart_session_max_age`
drove a background sweeper aimed at the session map of the storage format that had just been
replaced — permanently empty — while the live session map had a sweeper nothing called. A
client-driven multipart upload that was neither completed nor aborted therefore held its
buffered short part and its data key for the life of the process. Both keys expired the live
sessions from then on, and the sweeper stops when the proxy shuts down. **Corrected 2026-09-12:**
`optimizations.multipart_session_max_age` no longer exists. Expiry counts from the last part an
upload received rather than from when it was created, under
`optimizations.multipart_session_idle_timeout` (ADR 0028); the same number means something else
under the two keys, so a configuration still carrying the old one is refused at startup by name
rather than by D11's generic message, and a value below 1 second is refused too. D1 is read from
here on as: **a key exists only if code reads it and that read changes what the product does.**
A reader aimed at the wrong object is the same defect as no reader, and it is harder to see,
because searching for the key finds a hit.

**Closed 2026-09-11: an unknown key is no longer accepted in silence.** The loader now decodes
in its exact mode. What made this urgent is that the permissive mode made a misspelled live key
indistinguishable from a deleted one — see the Consequences — and this release deletes
twenty-two.

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
it an unseekable reader on every write path — the sealing one and the exit provider's, which
passes the client's own stream through — so a single-request upload fails with
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

**A second review, on 2026-09-12, found the same shape one level further out (D12–D14).** It
read every claim in this repository's documentation against the code, and three of its findings
were not documentation defects at all: the inputs that carry the configuration treat themselves
as advisory. A configuration file that cannot be read is discarded and the process continues on
defaults, so the operator is told their backend endpoint is missing when the truth is that
their file was never read. A `license_file` the operator wrote is only the first candidate in a
fixed list of well-known locations, so a mistyped path yields a different token and no message.
And two command-line flags overrule the monitoring keys, one of them unable to say what its own
default says. A key is worth no more than the file it arrives in, the path it names and the
command line that can quietly replace it.

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

**D5** (amended 2026-09-12). The proxy refuses to start when `s3_backend.target_endpoint` is
plain `http://`, under **every** provider. The error names the endpoint, the provider, what a
listener on that leg learns, and the upload failure the operator would otherwise spend an
afternoon on.

The exit provider used to be exempt, on the grounds that it writes no ciphertext and so had
no unseekable stream to fail on. Both halves were wrong. The exit write path hands the SDK an
unseekable *plaintext* stream, and the SDK does not ask what the bytes mean: it asks whether
it can seek them to compute a payload hash without TLS. Measured on the exemption before it
was removed, the proxy started and then answered `500` to every single-request upload with
*failed to seek body to start, request stream is not seekable*, while an upload above
`optimizations.streaming_segment_size` went through the multipart producer and stored fine —
a configuration that breaks as a function of object size, discovered in production rather
than at startup.

The security half points the same way, and harder. Plain HTTP is refused under an encrypting
provider because the backend credential travels in a SigV4 header over plaintext and a
listener learns every bucket name, object key and object size. Under the exit provider the
object bytes travel in the clear as well, so the exemption admitted strictly more exposure
than the rule it was an exception to. The startup warning that named the endpoint is gone
with the configuration it described.

Rejected: **keep the exemption and only correct its reasoning.** It would document a
configuration whose small uploads cannot work. Rejected: **keep it for a bucket that was
never encrypted**, the pure pass-through case — [ADR 0025](0025-leaving-is-a-supported-mode.md)
calls that a consequence of the exit provider rather than a purpose of it, and a proxy whose
purpose is encryption is not the tool for an unencrypted bucket over an unencrypted link.
Leaving stays possible: an operator reaching for the exit provider was writing through this
proxy under an encrypting provider, which already required `https://` on that same backend.

**D6.** `s3_security.max_presign_expiry_seconds` exists because an operator needs to bound the
lifetime a pre-signed URL may claim, and it lands with the code that enforces it. A value
outside the permitted range is a startup error, and the enforcing code clamps independently of
startup validation, so a configuration assembled in code cannot exceed the cap either. Its
default, its cap and what it is enforced against are ADR 0014.

**D7** (amended 2026-09-11). A configuration that cannot work, or that silently disables a
protection, refuses to start. The proxy does not start degraded and does not repair the value.
Refused at startup: a backend endpoint with no scheme, with a scheme the client cannot use, or
with plain HTTP under any provider (D5); an `encryption.metadata_key_prefix` that does
not satisfy **the shape rule of ADR 0009 D2**, which owns it — this rule used to restate the
pattern here and the two records drifted apart, so it names the owner instead; a positive
`optimizations.streaming_segment_size` outside its documented range or not a whole number of
segments; a `monitoring.pprof_bind_address` that is not a loopback address while profiling is
enabled; a client secret shorter than 16 characters; a clock-skew window or a pre-signed
ceiling of zero, and a pre-signed ceiling above the S3 maximum; a header or idle listener
budget of zero (ADR 0015 D8). Every such error names the field and the rule it broke, and no
value it checks is quietly corrected — one that would have turned the proxy into a shredder fails
loudly rather than being repaired. Where a zero is *not* checked the rule does not hold; the
Status section names those cases. The deliberate zeros are owned elsewhere: `shutdown_timeout` at zero means 30 seconds
(ADR 0015 D4), and the two body budgets mean "no deadline" and are the shipped default
(ADR 0015 D8).

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
request.

**D9a** (added 2026-09-11). `optimizations.clean_aws_signature_v4_chunked` is deleted too, and
for the opposite reason: its decoder does run, and the only thing the key's other setting can do
is damage. With it false the proxy never strips aws-chunked framing, so the framing is stored as
object content, and the client upload checksum of ADR 0012 cannot be verified at all — what the
proxy would hash is the framing rather than the payload. D1 asks whether code reads a key; this
adds the question D1 does not: **whether any value an operator may set is one the product would
accept.** Here one of the two is data corruption, so the key has no defensible setting and no
reason to exist. aws-chunked decoding is unconditional. The legacy top-level backend keys (`target_endpoint`, `region`, `access_key_id`,
`secret_key`, `use_tls`, `skip_ssl_verification`) and the migration that folds them into
`s3_backend` are deleted with them: they are backward-compatibility scaffolding, and no
backward compatibility is owed. `optimizations.streaming_buffer_size` and
`optimizations.enable_adaptive_buffering` are deleted as well (added 2026-09-09): the first
is read only by its own range check and by an accessor no production code calls; the second
only by the validation branch that guards `optimizations.streaming_threshold`, a key the
segment chain removes (ADR 0003), after which nothing reads it at all.

**D10.** Removing a key is a breaking change. It is announced in the release notes of the
major release that carries it, never absorbed by a compatibility shim or a deprecation
period. ~~The configuration loader ignores unknown keys silently, so a configuration written
for an older release keeps loading and merely loses documentation for a feature that never
existed; the release notes are the only channel that tells the operator so.~~ (Superseded by
D11 below: an unknown key refuses the start.)

**D11, decided 2026-09-10.** An unknown configuration key refuses the start, and the refusal
names the key. **This supersedes the last sentence of D10**, which made the release notes the
only channel: a channel that reaches only the operator who reads them is not a control, and
this release deletes twenty-two keys at once. Without D11 every one of them becomes a setting the
operator believes is in force — the same silence this ADR was written against, arriving from
the other direction. A misspelled key is refused for the same reason and by the same rule.

Two boundaries. A provider's own configuration block keeps its catch-all, because those
parameters belong to the provider and the provider validates them; D11 governs the keys the
proxy itself defines. And environment variables are not keys: they are not enumerable, so
nothing can decide whether one was meant for this process.

Measured before the decision was taken: of the four shipped example configurations three pass
unchanged, and the fourth was refused — it carried a top-level `streaming.segment_size` block
that no code has ever read, while the key the proxy reads is
`optimizations.streaming_segment_size`. An operator who copied that example and raised the
value got no effect and no warning. The check found it on its first run, which is the argument
for D11 in one line.

**D12, decided 2026-09-12.** A configuration file that cannot be read refuses the start, and the
error names the file. A path that does not exist, a file that cannot be opened and a file whose
YAML does not parse are one answer: the process stops, and the message is about the file rather
than about whatever the defaults go on to fail. Today the read error is discarded, so such a run
continues on defaults and dies on the missing `s3_backend.target_endpoint` — a true failure with a false reason,
which sends the operator to edit authentication while the actual mistake is one character in a
path. Finding no configuration file at all is a different thing and stays what it is: nothing was
named, so nothing was misread, and the start still fails on the keys that have no default. Which
route found the file does not enter into it — *found it and it does not parse* is never a
legitimate outcome, with or without `--config`. Verified before the decision: every invocation
this project ships that starts the proxy passes `--config`, and a run without it locates no file
today and fails on `s3_backend.target_endpoint` regardless, so D12 changes which error is printed
rather than whether anything that works today keeps working. It also compounds with D13 — once a
written `license_file` binds, a configuration file that was never read means that key never
arrives either, and the message points in the wrong direction a second time.

**D13, decided 2026-09-12.** A configured `license_file` is binding. Where the key is written,
the file it names is the only file: if that file cannot be read the proxy refuses to start, and
the error names the path. Discovery of the well-known locations applies only where the key is
**not** written — the key's own default is not a statement by the operator, so a deployment that
says nothing about the license keeps the discovery it has today, the container paths included.
A gate that silently substitutes a different token for the one the operator named is not a gate
(ADR 0016 D1), and the substitution is not hypothetical: an image carrying a token from some
build step starts happily when the mounted secret is missing or misnamed, and a running proxy is
no evidence that the intended token was found. The bite lands exactly where it should — the
operator made a statement and it was overruled. The token's environment routes are untouched by
this rule (ADR 0016 D6).

**D14, decided 2026-09-12.** A command-line flag does not override a configuration key.
`--monitoring` and `--monitoring-port` are removed: what monitoring does is expressed in the
configuration — `monitoring.enabled`, `monitoring.bind_address`, `monitoring.metrics_path` and
the profiling keys beside them — and where the configuration says nothing, the default applies.
This is the rule the project already applies to the environment, where no variable overrides a
key and the one mechanism is a `${VAR}` reference written into a value; a flag is the same idea
wearing different clothes. `--config` is not an exception to it: it names which configuration is
read and overrules nothing inside one.

`--monitoring-port` could not do the job it advertised in any case. It is compared against its
own default rather than against whether it was given, so a configuration setting
`monitoring.bind_address: ":7000"` together with an explicit `--monitoring-port=:9090` yields
`:7000` — the one value the flag cannot express is the value it defaults to. The two go together:
the argument was about the port, and keeping `--monitoring` alone would leave half a mechanism
standing for a deployment that passes the pair. Removing a flag is a breaking change of the same
kind as removing a key (D10): it is announced in the release notes of the major release that
carries it (ADR 0018), never softened by a shim or a deprecation period.

## Consequences

- **An upgrade rejects configurations that "worked" before.** **Updated 2026-09-12:** all four
  refusals fire. A non-loopback profiling address and an `encryption.metadata_key_prefix` that is
  empty or not lowercase landed first; the scheme-less endpoint and the plain-HTTP endpoint under
  any provider, the `exit` one included (D4, D5), refuse the start too, so an endpoint that cannot
  carry a streaming upload no longer starts and then fails at the first large PUT. In Kubernetes
  each is a crash loop with a readable reason instead of a pod that reports Ready and fails every
  streaming upload — deliberately the louder failure.
- **A configuration written against the legacy top-level block no longer starts.** **Updated
  2026-09-12:** it used to announce itself by accident — the keys were dropped in silence, which
  left `s3_backend` empty, and the required-field check caught it with
  `s3_backend.target_endpoint is required`. Under D11 it announces itself on purpose and earlier:
  the unknown-key refusal names `target_endpoint`, `region`, `access_key_id`, `secret_key`,
  `use_tls` and `skip_ssl_verification`, and the required-field check is never reached.
- **Operators who set the other deleted keys get a startup error naming the key.** **Updated
  2026-09-12:** D11 reversed the two consequences that stood here. An unknown key is no longer
  ignored, so a deleted key is not silence plus release notes, and a misspelling of a live key is
  not silence plus the default: an operator who writes `s3_security.max_clock_seconds` instead of
  `s3_security.max_clock_skew_seconds` is refused by name rather than left with the 900-second
  default in place of the 300 seconds intended. What it costs instead is that every configuration
  in the field carrying a stale key stops the process until it is edited — the breaking change
  D11 took deliberately.
- **Honouring the configured clock skew on both paths breaks working clients.** **Landed
  2026-09-11:** a client whose clock is off by more than the configured window used to
  authenticate on the header-signed path, because that path compared against a compile-time 900
  seconds, and does not any more. That is the configured intent, and the failure message is
  explicit, but it is the one change here that can break a healthy deployment.
- **A pre-signed URL claims at most one hour unless the operator raises it.** **Landed
  2026-09-11:** D6's key exists, its default is 3600 seconds, and the S3 maximum of seven days is
  the hard cap. A deployment that relies on longer-lived URLs has to raise the key; that is what
  replacing a seven-day default costs.
- **Remote profiling is gone.** A heap profile now requires loopback access to the pod — a
  port-forward, or a container sharing the network namespace. Nobody enjoys that on an
  incident call; it is the price of not exposing keys and plaintext on an unauthenticated
  port.
- **Deleting the failure accounting removes a per-address failure signal.** There is no
  counter of failed authentications per client and no metric to build one from — the exported
  metric set was checked in this tree and carries nothing about authentication. The log line
  is what remains.
- **The rule is a discipline, not a mechanism, and the amendment above is the proof.**
  Nothing automated proves that a declared key has a reader, and rejecting unknown keys would
  not help with that: a field that is declared and never read passes such a check, and so does
  a field whose reader sweeps the wrong map. The guard is review.
- **Deleting a key is one-way but cheap in this direction.** If security-event logging should
  ever become suppressible, it comes back as a key with a reader and a test.
- **A deployment that switched monitoring on with a flag says so in its configuration**
  (D14, added 2026-09-13). **Built 2026-09-13:** a chart that passed the flags
  renders the setting into the configuration it already writes, and anyone scripting the binary
  edits their invocation. That is what removing a flag costs, and it is why it belongs inside a
  major release.
- **What D14 bought back: a chart value that reached only half the deployment can no longer
  drift.** The chart's `monitoring.metricsPath` value used to reach the scrape configuration
  alone and never the proxy, because the flags carried the bind address and nothing else — so
  setting it to anything but `/metrics` made every scrape a 404 against a path the proxy does
  not serve. The chart now renders the whole `monitoring` block, so `metrics_path` travels with
  `enabled` and `bind_address` and two statements of the same fact cannot disagree. Rendering it
  also found the drift already in the tree: `values-production.yaml` and `values-monitoring.yaml`
  each carried a `monitoring:` block inside `config` **and** the chart's own `monitoring` values,
  and the chart now refuses to render with both rather than letting one of them win silently.
- **Nothing this project ships stops working under D12, and that is the whole of its cost.**
  **Decided 2026-09-12, not built:** every invocation it ships that starts the proxy names a
  configuration file that parses; what changes is that a file which was quietly ignored stops the
  process and says which file it was, instead of surfacing a few checks later as missing client
  credentials.
- **A mistyped `license_file` becomes a refusal to start** (D13). **Decided 2026-09-12, not
  built:** a deployment that named a path which does not resolve — and was, knowingly or not,
  running on whatever discovery found instead — stops starting until the path is corrected. That
  is the intent: the alternative is a license gate honoured against a token nobody chose.

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
- **Warn instead of refusing on a plain-HTTP backend.** Rejected: the process would be healthy
  and every streaming upload would fail. The warning was kept for the pass-through provider until
  2026-09-12 and then dropped with the exemption itself (D5): there the object bytes travel in the
  clear as well, so it is refused for the same reason, harder.
- **Leave profiling on the metrics listener and document restricting access.** Rejected for
  the same reason the dead keys are deleted; the exposure is plaintext and key material.
- **Normalise a bad metadata prefix** (lowercase it, or substitute the default). Rejected: a
  prefix that disagrees with what is stored turns the proxy into a pass-through that serves
  ciphertext with a 200. That must fail loudly.
- **A deprecation period or compatibility shim for the removed keys.** Rejected: no
  backward compatibility is owed (ADR 0017), and a shim is more configuration code that must
  itself be read and tested.
- **Refuse an unreadable configuration file only when `--config` was passed** (D12). The
  cautious reading, and weaker: *found it and it does not parse* is never a legitimate outcome
  with or without the flag, so the distinction does not earn the branch it costs.
- **Keep discarding the read error and extend the required-field message with a hint**
  (D12). Rejected: it decorates the wrong error instead of removing it, and every hint of that
  kind is a sentence that has to stay true as the checks around it move.
- **Keep the license fallback list and log at warn level which path was used** (D13). Rejected:
  it relies on somebody reading a start-up warning, and for a gate whose effect only shows at
  expiry that is far too late.
- **Drop the license fallback list entirely** (D13). Rejected: stricter than the problem and it
  breaks a legitimate case — `license_file` has a default that the image lives on, and the
  well-known container paths are a real convenience for anyone running the image without a
  configuration of their own. Discovery for *said nothing*, binding for the explicit statement.
- **Make the monitoring flags honest — branch on whether the flag was given rather than on its
  value** (D14). Rejected: it fixes `--monitoring-port` and keeps a second way to say the same
  thing, which is the part that was wrong.
- **Keep the monitoring flags and document the quirk** (D14). Rejected: it writes a defect down
  as a feature. The flag stands in the command line, silently loses to the configuration, and
  nothing anywhere says why.

## Residual risks

- **Closed 2026-09-11: the loader no longer accepts an unknown key in silence.** A misspelled
  key, a key from a newer release and a key indented under the wrong section are all refused at
  startup, and the error names the key. The trade this entry left open was taken: the breaking
  change is accepted, and every configuration in the field carrying a stale key stops the process
  until it is edited. A provider's own block is the documented exception and still swallows its
  own parameters.
- **Nothing prevents the next dead key.** The rule is enforced by review only, and the
  2026-09-10 amendment shows the sharper version of the failure: a key whose reader exists and
  points at the wrong thing.
- **`s3_backend.insecure_skip_verify` survived the cleanup unexamined.** It is live, it is
  read, and it disables certificate verification on the leg that faces the adversary — so it
  passes the rule this ADR states while being the one backend-transport setting most worth a
  second look. No decision has been taken about it. **Narrowed 2026-09-12:** the second half of
  this risk is closed — the connection path it selects is the SDK's own client with nothing
  overridden but the certificate check, so it carries the same dial, handshake and pool budgets
  as the verifying path instead of a bare transport's.
- **The metrics listener stays unauthenticated on every interface by default.** Only profiling
  moved to loopback. What that listener exports was checked in this tree and is now narrow:
  request counts and durations labelled by HTTP method, route template and status code — the
  route template, not the requested path, so no bucket or object name reaches a label — a
  connection gauge, and build and license information. **Narrowed 2026-09-12:** the licensee's
  name and company are no longer labels; what the license metrics still disclose is the expiry
  date, as a label and as a timestamp gauge, so whoever reaches the port learns when the
  deployment's license runs out but not whose it is.
- **Closed 2026-09-12: there is no pass-through exception left to measure.** D5's split — refuse
  under an encrypting provider, warn under the `exit` one — was measured before it was removed:
  under `exit` against a plain-HTTP backend the proxy started and answered `500` to every
  single-request upload, while an upload above `optimizations.streaming_segment_size` went through
  the multipart producer and stored fine. A configuration that breaks as a function of object size
  is not one to warn about, so plain HTTP is refused under every provider and the warning is
  gone.
- **The metadata prefix rule sets no maximum length.** ~~It requires no trailing separator, so
  a short prefix silently swallows client metadata that happens to begin with it~~ — closed by
  [ADR 0009](0009-the-metadata-prefix-is-the-proxys-namespace.md) D2, which requires the
  trailing `-` and a minimum of four characters, and by D7 above, which no longer names the
  weaker rule. What stands is the upper bound: there is none, so an over-long prefix fails at
  the backend with an opaque error rather than at startup. Changing one valid prefix to
  another still passes startup and still
  makes every already stored object unreadable — but no longer quietly: an object whose
  metadata does not carry the configured prefix is refused with `InvalidObjectState` on every
  read verb under an encrypting provider (ADR 0003, ADR 0009) instead of being served as
  ciphertext with a 200; under the `exit` provider it is still served (ADR 0025). The outage
  is fleet-wide and loud, which is the right shape for a mistake no startup check can see.
- **Settled 2026-09-10: `encryption.integrity_verification` can no longer be defaulted into a
  permissive state, because it no longer exists.** The question of what its safe default
  should be disappeared with the key and the modes it selected. What a read does and does not
  still owe the client is the stored format's business now (ADR 0003), not a configuration
  key's.
- **The pre-signed ceiling is enforced, and the number behind it is still unmeasured.** D6's
  one-hour default (ADR 0014) was derived from one backup client's ten-minute URLs, and no other
  client's URL lifetime was measured. **Updated 2026-09-12:** the key exists and every pre-signed
  URL is bounded by it, so an unmeasured number is now in force rather than merely proposed. The
  measurement is still owed.
- **Built 2026-09-13: D12, D13 and D14.** A configuration file that cannot be read now refuses
  the start and the error names it, a written `license_file` that does not resolve refuses the
  start instead of falling through to discovery, and the monitoring flags are gone.
- **D13 binds one route to the token and leaves the others as they are.** Three environment
  variable names are accepted, and the discovery list still applies wherever the key is not
  written, so *which token is this proxy running on* remains unanswerable from the configuration
  alone. ADR 0016 carries that risk; D13 narrows it to the case where the operator said nothing.
- **Unverified: whether anything outside this repository passes the monitoring flags.** Inside
  it the chart and the project's own local run targets passed them, and all of those moved to
  configuration under D14; no survey was made of deployments or scripts elsewhere, and for them
  the removal is a breaking change with no deprecation step in front of it. A flag that no longer
  exists is refused by name, so such an invocation stops rather than starting without it.
- **Unverified: whether any deployment outside this repository sets the removed keys.**
  **Updated 2026-09-12:** under D11 none of them keeps loading — every removed key is refused at
  startup and the message names it, the legacy top-level backend block included. Every such
  deployment has to be rewritten before it starts.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0006 — The proxy serves any S3 client
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt
- ADR 0012 — Client checksums are verified against the plaintext, never forwarded and never stored
- ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
- ADR 0015 — A transfer is bounded by the client and by shutdown, not by a server wall clock
- ADR 0016 — The license is a startup gate with an explicit expiry; D13 makes the path the
  operator writes binding on that gate
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0018 — A major release is declared by a label, never discovered at merge
- ADR 0025 — Leaving is a supported mode: the exit provider writes plaintext and still decrypts
  what an encrypting provider wrote
- ADR 0028 — An abandoned upload expires on inactivity, not on age
- [README.md](../../README.md) — the configuration reference an operator works from
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the threat model rule this decision applies, and the hardening checklist entry for the dead keys
