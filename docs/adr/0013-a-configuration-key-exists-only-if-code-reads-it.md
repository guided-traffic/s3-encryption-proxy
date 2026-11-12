# ADR 0013: A configuration key exists only if code reads it, and an unworkable configuration refuses to start

## Status

**Accepted.** Date: 2026-09-14.

**D1 through D14 are implemented, except three of D7's zero cases.**
`optimizations.multipart_part_size` at zero or below falls back to 12 MB for the part size
only, while the single-request ceiling reads the written value, so every PUT of a non-empty body
goes through the multipart producer; `optimizations.multipart_upload_concurrency` at zero falls
back to 4; and `optimizations.multipart_short_part_buffer_size` at zero falls back to 64 MB. Each
is a gap rather than a design. A written `optimizations.multipart_session_cleanup_interval` or
`optimizations.multipart_session_idle_timeout` below one second refuses the start.

Every key this decision names as dead is gone — from the loader, from every shipped example
configuration and from the production deployment values: the six `s3_security` keys
(`strict_signature_validation`, `enable_rate_limiting`, `max_requests_per_minute`,
`enable_security_logging`, `max_failed_attempts`, `unblock_ip_seconds`) together with the
per-address failure accounting behind them; the backend's `use_tls` (D4); the legacy top-level
backend block (`target_endpoint`, `region`, `access_key_id`, `secret_key`, `use_tls`,
`skip_ssl_verification`) and the migration that folded it into the backend block (D9);
`optimizations.streaming_buffer_size` and `optimizations.enable_adaptive_buffering` (D9);
`optimizations.clean_aws_signature_v4_chunked` (D9a) and `optimizations.clean_http_transfer_chunked`
(D9) with the decoder it gated; and `optimizations.streaming_threshold` and
`encryption.integrity_verification`. With `integrity_verification` go the modes `off`, `lax`,
`strict` and `hybrid`: integrity is not a setting, it is a property of the stored format
(ADR 0003). Two never-read defaults this ADR had not named, `encryption.algorithm` and
`encryption.key_rotation_days`, went with them. aws-chunked decoding is unconditional, and body
decoding carries no configuration at all.

The authentication-failure log line is what D2 specifies: the peer address and the forwarding
header as two raw fields, interpreted as nothing. There are no `client_ip` or `failed_count`
fields and no branch that compares a hardcoded threshold and announces a brute-force attempt.
`optimizations.multipart_short_part_buffer_size` arrived with the code that reads it and a
startup range check (ADR 0011) — D1 applied rather than repaired afterwards.

What else is built:

- **D11.** The loader decodes in its exact mode: a key the proxy does not define refuses the
  start and the error names it, with a line telling the operator that a key removed by a release
  is listed in its notes. The provider block is held to the same rule: each provider type
  declares what it reads — `aes` reads `aes_key`, `exit` reads nothing at all — and any other key
  refuses the start naming it and its provider. Every shipped example configuration is decoded in
  a test so that a file this repository hands out cannot be one that refuses to start.
  `optimizations.multipart_session_max_age`, `optimizations.streaming_segment_size` and the
  singular `s3_backend` mapping are each refused by a message of their own.
- **D3.** `s3_security.max_clock_skew_seconds` governs both authentication forms, and there is one
  comparison per path. `0` is refused rather than read silently as the default: at second
  granularity it can only be a misunderstanding of "switch it off", and a silent fixup is what
  ADR 0017 D8 forbids.
- **D4.** A `target_endpoint` without a scheme, or with one the SDK does not speak, is a startup
  error naming the key.
- **D5.** A plain-HTTP backend refuses the start under every provider, the `exit` one included,
  and the message says what a listener learns and why an upload would fail. One warning stands
  beside it: a start under the `exit` provider logs what that provider costs — new objects are
  stored unencrypted, while objects an encrypting provider wrote earlier are still decrypted on
  read as long as it stays configured. It is the exit provider's alone; an encrypting provider
  cannot reach it.
- **D6.** `s3_security.max_presign_expiry_seconds` exists, defaults to 3600 and is bounded by the
  S3 maximum of seven days. The ceiling is enforced at the point of use as well as in validation.
- **D12 and D14.** A configuration file that cannot be read refuses the start and the error names
  it. The binary declares one flag, `--config`.
- **The backend block** is the list `s3_backends`, read with exactly one entry.

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

**A key describing a configuration that cannot work.** The backend's `use_tls` was read only to
copy itself onwards. The backend transport is decided by the scheme of `target_endpoint` alone.
Worse, a plain-HTTP backend endpoint cannot carry a streaming upload at all: the AWS SDK the
proxy uses signs a payload by hashing the body, which needs a seekable stream, and only accepts
`UNSIGNED-PAYLOAD` over TLS. The proxy hands it an unseekable reader on every write path — the
sealing one and the exit provider's, which passes the client's own stream through — so a
single-request upload fails with `failed to seek body to start`. Nothing in the product said so;
every shipped example uses TLS, which is why it was never hit. A validation on `use_tls` would
have refused the working configurations and passed the broken one.

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

The same review found configurations that were accepted and destroyed data or silently disabled
protection: an empty or non-lowercase `encryption.metadata_key_prefix` made stored objects read
back as pass-through, serving ciphertext to the client with a 200.

**A reader is not an effect.** A dead-code sweep found a pair of keys that passed a test asking
only whether code reads them and did nothing: `optimizations.multipart_session_cleanup_interval`
and `optimizations.multipart_session_max_age` drove a background sweeper aimed at the session map
of the storage format that had just been replaced — permanently empty — while the live session
map had a sweeper nothing called. A client-driven multipart upload that was neither completed nor
aborted therefore held its buffered short part and its data key for the life of the process. A
reader aimed at the wrong object is the same defect as no reader, and it is harder to see,
because searching for the key finds a hit.

**A second review found the same shape one level further out (D12, D14).** It read every claim
in this repository's documentation against the code, and two of its findings were not
documentation defects at all: the inputs that carry the configuration treated themselves as
advisory. A configuration file that could not be read was discarded and the process continued on
defaults, so the operator was told their backend endpoint was missing when the truth was that
their file was never read. And two command-line flags overruled the monitoring keys, one of them
unable to say what its own default says. A key is worth no more than the file it arrives in and
the command line that can quietly replace it.

## Decision

**D1.** A configuration key exists only if code reads it **and that read changes what the
product does.** A new key lands in the same change as the code that reads it and as a test that
proves the effect. A key with no reader, or with a reader aimed at the wrong object, is deleted,
never documented as aspirational.

**D2.** The six `s3_security` keys named above are deleted, together with the per-address
failure accounting behind them. `s3_security` keeps exactly two keys —
`max_clock_skew_seconds` and `max_presign_expiry_seconds` — and both are enforced on every
path they name. The authentication-failure log line stays and records the peer address and
the forwarding header as two raw fields, interpreting neither.

**D3.** `s3_security.max_clock_skew_seconds` governs both authentication forms, header-signed
and pre-signed. A configured value that is honoured on one path only is the same defect as a
key with no reader at all.

**D4.** The backend's `use_tls` is deleted. The backend transport is the scheme of
`s3_backends[].target_endpoint`. A `target_endpoint` without a scheme is a startup error.

**D5.** The proxy refuses to start when `s3_backends[].target_endpoint` is plain `http://`,
under **every** provider. The error names the endpoint, the provider, what a listener on that
leg learns, and the upload failure the operator would otherwise spend an afternoon on.

The rule includes the exit provider, although it writes no ciphertext. The exit write path hands
the SDK an unseekable *plaintext* stream, and the SDK does not ask what the bytes mean: it asks
whether it can seek them to compute a payload hash without TLS. Measured under the exit provider
against a plain-HTTP backend, the proxy started and then answered `500` to every single-request
upload with *failed to seek body to start, request stream is not seekable*, while an upload
above `optimizations.multipart_part_size` went through the multipart producer and stored fine —
a configuration that breaks as a function of object size, discovered in production rather than
at startup.

The security half points the same way, and harder. Plain HTTP is refused under an encrypting
provider because the backend credential travels in a SigV4 header over plaintext and a
listener learns every bucket name, object key and object size. Under the exit provider the
object bytes travel in the clear as well, so an exemption for it would admit strictly more
exposure than the rule it excepted. No startup warning names a plain-HTTP endpoint: that
configuration does not start.

Rejected: **an exemption for the exit provider with corrected reasoning.** It would document a
configuration whose small uploads cannot work. Rejected: **an exemption for a bucket that was
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

**D7.** A configuration that cannot work, or that silently disables a protection, refuses to
start. The proxy does not start degraded and does not repair the value. Refused at startup: a
backend endpoint with no scheme, with a scheme the client cannot use, or with plain HTTP under
any provider (D5); an `encryption.metadata_key_prefix` that does not satisfy **the shape rule of
ADR 0009 D2**, which owns it; a positive `optimizations.multipart_part_size` outside its
documented range or not a whole number of segments; a `monitoring.pprof_bind_address` that is
not a loopback address while profiling is enabled; a client secret shorter than 16 characters; a
clock-skew window or a pre-signed ceiling of zero, and a pre-signed ceiling above the S3
maximum; a header or idle listener budget of zero (ADR 0015 D8). Every such error names the
field and the rule it broke, and no value it checks is quietly corrected — one that would have
turned the proxy into a shredder fails loudly rather than being repaired. Where a zero is *not*
checked the rule does not hold; the Status section names those cases. The deliberate zeros are
owned elsewhere: `shutdown_timeout` at zero means 30 seconds (ADR 0015 D4), and the two body
budgets mean "no deadline" and are the shipped default (ADR 0015 D8).

**D8.** Profiling is served on its own listener bound to loopback
(`monitoring.pprof_bind_address`, default `127.0.0.1:6060`) and is never registered on the
metrics listener. `/metrics` stays on `monitoring.bind_address` so it can be scraped
cluster-wide. Only a loopback IP literal or the literal `localhost` is accepted: a name is
refused rather than resolved, because resolving at startup makes the proxy unbootable without
a resolver and a name that points at loopback today can point elsewhere tomorrow.
`monitoring.pprof_enabled` stands on its own and does not silently require
`monitoring.enabled`.

**D9.** The same deletion applies outside the security section.
`optimizations.clean_http_transfer_chunked` is deleted with the decoder it gated: the Go HTTP
server deletes the `Transfer-Encoding` header from the request unconditionally before dispatch,
answers an unsupported value itself, and refuses the header outright on the HTTP/2 listener, so
that decoder cannot run on any transport this proxy serves. The legacy top-level backend keys
(`target_endpoint`, `region`, `access_key_id`, `secret_key`, `use_tls`, `skip_ssl_verification`)
and the migration that folds them into the backend block are deleted with it: they are
backward-compatibility scaffolding, and no backward compatibility is owed.
`optimizations.streaming_buffer_size` and `optimizations.enable_adaptive_buffering` are deleted
as well: the first is read only by its own range check and by an accessor no production code
calls; the second only by the validation branch that guards `optimizations.streaming_threshold`,
a key the segment chain removes (ADR 0003), after which nothing reads it at all.

**D9a.** `optimizations.clean_aws_signature_v4_chunked` is deleted too, and for the opposite
reason: its decoder does run, and the only thing the key's other setting can do is damage. With
it false the proxy never strips aws-chunked framing, so the framing is stored as object content,
and the client upload checksum of ADR 0012 cannot be verified at all — what the proxy would hash
is the framing rather than the payload. D1 asks whether a read changes what the product does;
this adds the question D1 does not: **whether any value an operator may set is one the product
would accept.** Here one of the two is data corruption, so the key has no defensible setting and
no reason to exist. aws-chunked decoding is unconditional.

**D10.** Removing a key is a breaking change. It is announced in the release notes of the
major release that carries it, never absorbed by a compatibility shim or a deprecation
period.

**D11.** An unknown configuration key refuses the start, and the refusal names the key. The
release notes of D10 are therefore not the only channel: a channel that reaches only the
operator who reads them is not a control, and 5.0.0 deletes twenty-two keys at once. Without
D11 every one of them would become a setting the operator believes is in force — the same
silence this ADR was written against, arriving from the other direction. A misspelled key is
refused for the same reason and by the same rule.

The provider block is held to the same rule. Each provider type declares the keys it reads —
`aes` reads `aes_key`, `exit` reads nothing at all — and a key it does not declare refuses the
start, naming it and its provider. A provider that reads the one key it wants and drops the rest
validates nothing, so "the provider validates its own parameters" is no ground for an exception.

Two removed keys are refused by a message of their own rather than by the generic one, for
opposite reasons. `optimizations.multipart_session_max_age` measured a session from its
creation; expiry counts from the last part an upload received, under
`optimizations.multipart_session_idle_timeout` (ADR 0028), and the same number means something
else under the two keys, so the operator is told the meaning changed. Nothing about the value or
its checks changed when `optimizations.streaming_segment_size` became
`optimizations.multipart_part_size`, so that refusal exists to tell the operator that the two
names are one setting.

One boundary: environment variables are not keys. They are not enumerable, so nothing can
decide whether one was meant for this process.

Measured when this rule was taken: of the four shipped example configurations three passed
unchanged, and the fourth was refused — it carried a top-level `streaming.segment_size` block
that no code has ever read, while the key the proxy reads is
`optimizations.multipart_part_size`. An operator who copied that example and raised the
value got no effect and no warning. The check found it on its first run, which is the argument
for D11 in one line.

**D12.** A configuration file that cannot be read refuses the start, and the error names the
file. A path that does not exist, a file that cannot be opened and a file whose YAML does not
parse are one answer: the process stops, and the message is about the file rather than about
whatever the defaults go on to fail. Discarding the read error would let such a run continue on
defaults and die on the missing backend — a true failure with a false reason, which sends the
operator to edit authentication while the actual mistake is one character in a path. Finding no
configuration file at all is a different thing and stays what it is: nothing was named, so
nothing was misread, and the start still fails on the keys that have no default. Which route
found the file does not enter into it — *found it and it does not parse* is never a legitimate
outcome, with or without `--config`. Every invocation this project ships that starts the proxy
passes `--config`, and a run without it that locates no file fails on the missing backend
regardless, so D12 changes which error is printed rather than whether anything that works keeps
working.

**D13.** `license_file` is accepted and read by nothing. The proxy checks no license
(ADR 0016), so the key binds nothing: it has no default, the file it names is never opened, and a
configuration that writes it starts with a warning that names the key as ignored. It stays
decodable so that a configuration written for a release that checked a license still starts. The
next major release removes it, and from then on D11 refuses it like any other unknown key. It is
the one key that exists without code reading it for its purpose, and the one compatibility shim
of the kind the alternatives below reject for removed keys.

**D14.** A command-line flag does not override a configuration key. `--monitoring` and
`--monitoring-port` are removed: what monitoring does is expressed in the configuration —
`monitoring.enabled`, `monitoring.bind_address`, `monitoring.metrics_path` and the profiling keys
beside them — and where the configuration says nothing, the default applies. This is the rule the
project already applies to the environment, where no variable overrides a key and the one
mechanism is a `${VAR}` reference written into a value; a flag is the same idea wearing different
clothes. `--config` is not an exception to it: it names which configuration is read and
overrules nothing inside one.

`--monitoring-port` could not do the job it advertised in any case. It was compared against its
own default rather than against whether it was given, so a configuration setting
`monitoring.bind_address: ":7000"` together with an explicit `--monitoring-port=:9090` yielded
`:7000` — the one value the flag could not express was the value it defaulted to. The two go
together: the argument was about the port, and keeping `--monitoring` alone would leave half a
mechanism standing for a deployment that passes the pair. Removing a flag is a breaking change of
the same kind as removing a key (D10): it is announced in the release notes of the major release
that carries it (ADR 0018), never softened by a shim or a deprecation period.

**The backend block is a list.** The backend is configured under `s3_backends`, a list, and the
entry's fields are `target_endpoint`, `region`, `access_key_id`, `secret_key` and
`insecure_skip_verify`. The singular `s3_backend` mapping is refused by a message of its own
rather than by D11's generic one: the shape changed and the meaning did not, so the generic
refusal would read as *this setting is gone* to every deployment in the field, and every
deployment writes this key. The message says to move the block under a single `- ` entry. A
second entry is refused too, naming how many were written — reading the first and discarding the
rest is the silent drop ADR 0007 refuses, and here it would leave an operator who listed two
backends believing both were written to with one of them silently empty.

Two points, because D1 does not obviously cover either. **A list the proxy serves one entry from
is not a key with no reader:** the length is read and a second entry stops the start, which is a
behaviour an operator can observe, and D1 asks for a read that changes what the product does
rather than for a read of every value. **The shape lands before the feature that needs it, and
deliberately so.** Keeping several backends in sync is a later release; turning a mapping into a
list then would refuse every configuration in the field under D11 — so the shape is the only part
of that feature that breaks anything, and a major release is where a break is paid for (ADR 0018).

## Consequences

- **An upgrade rejects configurations that "worked" before.** All four refusals fire: a
  non-loopback profiling address, an `encryption.metadata_key_prefix` that breaks the shape rule
  of ADR 0009 D2, a scheme-less endpoint, and a plain-HTTP endpoint under any provider, the `exit`
  one included (D4, D5). An endpoint that cannot carry a streaming upload does not start and then
  fail at the first large PUT. In Kubernetes each is a crash loop with a readable reason instead
  of a pod that reports Ready and fails every streaming upload — deliberately the louder failure.
- **A configuration written against the legacy top-level block does not start.** The unknown-key
  refusal of D11 names `target_endpoint`, `region`, `access_key_id`, `secret_key`, `use_tls` and
  `skip_ssl_verification`, and the required-field check is never reached.
- **Operators who set the other deleted keys get a startup error naming the key.** A deleted key
  is not silence plus release notes, and a misspelling of a live key is not silence plus the
  default: an operator who writes `s3_security.max_clock_seconds` instead of
  `s3_security.max_clock_skew_seconds` is refused by name rather than left with the 900-second
  default in place of the 300 seconds intended. What it costs is that every configuration in the
  field carrying a stale key stops the process until it is edited — the breaking change D11 takes
  deliberately.
- **Honouring the configured clock skew on both paths breaks working clients.** A client whose
  clock is off by more than the configured window is refused on the header-signed path too, where
  releases before 5.0.0 compared against a compile-time 900 seconds. That is the configured
  intent, and the failure message is explicit, but it is the one change here that can break a
  healthy deployment.
- **A pre-signed URL claims at most one hour unless the operator raises it.** D6's key defaults
  to 3600 seconds, and the S3 maximum of seven days is the hard cap. A deployment that relies on
  longer-lived URLs has to raise the key; that is what replacing a seven-day default costs.
- **Remote profiling is gone.** A heap profile requires loopback access to the pod — a
  port-forward, or a container sharing the network namespace. Nobody enjoys that on an
  incident call; it is the price of not exposing keys and plaintext on an unauthenticated
  port.
- **Deleting the failure accounting removes a per-address failure signal.** There is no
  counter of failed authentications per client and no metric to build one from — the exported
  metric set was checked in this tree and carries nothing about authentication. The log line
  is what remains.
- **The rule is a discipline, not a mechanism, and the session sweeper in the Context is the
  proof.** Nothing automated proves that a declared key has a reader, and refusing unknown keys
  (D11) does not help with that: a field that is declared and never read passes such a check, and
  so does a field whose reader sweeps the wrong map. The guard is review.
- **Deleting a key is one-way but cheap in this direction.** If security-event logging should
  ever become suppressible, it comes back as a key with a reader and a test.
- **A deployment that switched monitoring on with a flag says so in its configuration** (D14).
  The chart renders the setting into the configuration it writes, and anyone scripting the binary
  edits their invocation. That is what removing a flag costs, and it is why it belongs inside a
  major release.
- **What D14 buys back: a chart value cannot reach only half the deployment.** With the flags
  carrying the bind address and nothing else, the chart's `monitoring.metricsPath` value reached
  the scrape configuration alone and never the proxy, so setting it to anything but `/metrics`
  made every scrape a 404 against a path the proxy does not serve. The chart renders the whole
  `monitoring` block, so `metrics_path` travels with `enabled` and `bind_address` and two
  statements of the same fact cannot disagree. A values file that carries a `monitoring:` block
  inside `config` **and** the chart's own `monitoring` values is refused at render time rather
  than letting one of them win silently; two of the shipped values files carried both when the
  chart began rendering the block.
- **Nothing this project ships stops working under D12, and that is the whole of its cost.**
  Every invocation it ships that starts the proxy names a configuration file that parses; what
  changes is that a file which would be quietly ignored stops the process and says which file it
  is, instead of surfacing a few checks later as missing client credentials.
- **A configuration carrying `license_file` starts with a warning** (D13) until the next major
  release, which refuses it under D11. The warning is the only notice an operator gets before
  then.

## Alternatives Considered

- **Implement what the keys promised** — a rate limiter, per-address blocking driven by the
  failed-attempt threshold and the unblock timer, plus a trusted-proxy list and eviction to
  make the forwarding header safe to key on. Per-address limiting is the wrong tool for this
  product: a legitimate S3 client is one authenticated identity bursting thousands of requests
  from one address, and clients behind a NAT or an ingress share an address. A signed request
  needs a client secret of at least 16 characters, which is not guessable, and denial-of-service
  defence belongs in the ingress. See ADR 0014.
- **Keep the keys and document them as unimplemented.** Rejected by the threat model rule
  this ADR exists to apply: the documentation is exactly where the reliance comes from.
- **Keep a bounded failure counter with eviction, feeding only the log line.** Rejected: a
  trusted-proxy allowlist is a lot of infrastructure for one log field.
- **Wire `use_tls` up so it forces the scheme.** Rejected: it duplicates information the
  endpoint already carries, and making it authoritative means rewriting the endpoint — a larger
  change for no gain.
- **Warn instead of refusing on a plain-HTTP backend.** Rejected: the process would be healthy
  and every streaming upload would fail. Under the exit provider the object bytes travel in the
  clear as well, so a warning there is rejected for the same reason, harder (D5).
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
- **Make the monitoring flags honest — branch on whether the flag was given rather than on its
  value** (D14). Rejected: it fixes `--monitoring-port` and keeps a second way to say the same
  thing, which is the part that was wrong.
- **Keep the monitoring flags and document the quirk** (D14). Rejected: it writes a defect down
  as a feature. The flag stands in the command line, silently loses to the configuration, and
  nothing anywhere says why.

## Residual risks

- **Nothing prevents the next dead key.** The rule is enforced by review only, and the session
  sweeper in the Context shows the sharper version of the failure: a key whose reader exists and
  points at the wrong thing.
- **`s3_backends[].insecure_skip_verify` has not been examined.** It is live, it is read, and it
  disables certificate verification on the leg that faces the adversary — so it passes the rule
  this ADR states while being the one backend-transport setting most worth a second look. No
  decision has been taken about it. The connection path it selects is the SDK's own client with
  nothing overridden but the certificate check, so it carries the same dial, handshake and pool
  budgets as the verifying path.
- **The metrics listener stays unauthenticated on every interface by default.** Only profiling
  is on loopback. What that listener exports was checked in this tree and is narrow: request
  counts and durations labelled by HTTP method, route template and status code — the route
  template, not the requested path, so no bucket or object name reaches a label — a connection
  gauge, and build information.
- **The metadata prefix rule sets no maximum length.** [ADR 0009](0009-the-metadata-prefix-is-the-proxys-namespace.md)
  D2 requires the trailing `-` and a minimum of four characters, and D7 names that rule, but there
  is no upper bound, so an over-long prefix fails at the backend with an opaque error rather than
  at startup. Changing one valid prefix to another passes startup and makes every already stored
  object unreadable — loudly: an object whose metadata does not carry the configured prefix is
  refused with `InvalidObjectState` on every read verb under an encrypting provider (ADR 0003,
  ADR 0009) instead of being served as ciphertext with a 200; under the `exit` provider it is
  served (ADR 0025). The outage is fleet-wide and loud, which is the right shape for a mistake no
  startup check can see.
- **The pre-signed ceiling is enforced, and the number behind it is unmeasured.** D6's one-hour
  default (ADR 0014) was derived from one backup client's ten-minute URLs, and no other client's
  URL lifetime was measured. Every pre-signed URL is bounded by it, so an unmeasured number is in
  force. The measurement is still owed.
- **Unverified: whether anything outside this repository passes the monitoring flags.** Inside
  it the chart and the project's own local run targets passed them, and all of those moved to
  configuration under D14; no survey was made of deployments or scripts elsewhere, and for them
  the removal is a breaking change with no deprecation step in front of it. A flag that does not
  exist is refused by name, so such an invocation stops rather than starting without it.
- **Unverified: whether any deployment outside this repository sets the removed keys.** Under
  D11 none of them keeps loading — every removed key is refused at startup and the message names
  it, the legacy top-level backend block included. Every such deployment has to be rewritten
  before it starts.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0006 — The proxy serves any S3 client
- ADR 0007 — Forward it or refuse it, never silently drop it
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt
- ADR 0012 — Client checksums are verified against the plaintext, never forwarded and never stored
- ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
- ADR 0015 — A transfer is bounded by the client and by shutdown, not by a server wall clock
- ADR 0016 — The proxy is licensed under Apache 2.0 and checks no license; D13 is the one key
  it leaves behind
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0018 — A major release is declared by a label, never discovered at merge
- ADR 0025 — Leaving is a supported mode: the exit provider writes plaintext and still decrypts
  what an encrypting provider wrote
- ADR 0028 — An abandoned upload expires on inactivity, not on age
- [README.md](../../README.md) — the configuration reference an operator works from
- [docs/security/threat-model.md](../security/threat-model.md) — the threat model rule this decision applies, and where rule 2 came from
