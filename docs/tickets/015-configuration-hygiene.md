# Ticket 015: Configuration hygiene: dead knobs out, real controls in

## Status (2026-09-06)

**Open.** Item 4 in the order of work of the Velero path review
(the [label index](README.md#label-index) defines them); carries the
decisions **N-5**, **D-5**, **D-6** (with **P-11**) and **D-7**, all taken on
2026-09-06. It depends on nothing: it touches `s3_security.*`,
`s3_backend.use_tls` and the pre-signed URL validator, none of which the storage
format v2 ticket or the upload checksums ticket rewrite. It is sequenced after
them only because all three tickets edit the same five `config/*.yaml` example
files and v2 deletes two more keys there (`encryption.integrity_verification`,
`optimizations.streaming_threshold`); landing this one first means rewriting
those blocks twice. If v2 slips, this ticket can go first at the cost of that
churn. Every line number below was read in the tree at commit `bc6a37a`.

---

## Context

The threat model recorded on 2026-09-06 has three rules; the second one is what
this ticket is about:

> A control that exists only in configuration or documentation is worse than no
> control, because it gets relied upon.

Three instances of that, found while building the Velero e2e suite:

1. **N-5.** Four `s3_security` keys are parsed, validated, documented in the
   README, set in every shipped example config and in the production Helm values
   — and read by nothing. The one piece of machinery that looks like an
   implementation, the failed-attempt map in
   [s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go), is keyed by
   an attacker-chosen string, compares against a hardcoded 5 rather than the
   configured value, only logs, is written without a lock, and never expires. It
   is not a weak control; it is a liability with a security-sounding name.
2. **D-6 / P-11.** `s3_backend.use_tls: false` describes a configuration that
   cannot work: aws-sdk-go-v2 signs a payload by hashing the body, which needs a
   seekable stream, and only accepts `UNSIGNED-PAYLOAD` over TLS. The proxy
   streams an unseekable ciphertext reader, so every streaming PutObject fails
   with `failed to seek body to start`. Nothing in the repository says so. All
   shipped configs use TLS, which is why it has never been hit.
3. **D-7.** The opposite problem: a control an operator would want does not
   exist. The pre-signed URL lifetime ceiling is hardcoded to the AWS maximum of
   seven days. Seven days of bearer capability is the wrong default for a proxy
   whose job is to limit exposure to a hostile backend, and Velero's own URLs
   live 600 s.

Two more instances turned up while verifying the above and are folded in below
as **E-1** and **E-2**; they are the same defect class in the same two files, so
splitting them into their own ticket would mean touching `s3_security` twice.

After this ticket, `s3_security` has exactly two keys and both are enforced on
every code path.

---

## Scope

**In**

- **N-5** (and **D-5**, which it makes moot): delete `enable_rate_limiting`,
  `max_requests_per_minute`, `max_failed_attempts`, `unblock_ip_seconds`, their
  defaults and their validation; delete the `SecurityMetrics` struct and the
  failed-attempt map; keep the security log line.
- **D-6** / **P-11**: refuse to start on a plain-HTTP backend when the active
  provider encrypts; warn and continue for `none`. Delete the dead
  `s3_backend.use_tls` knob that the decision is nominally phrased against (see
  [Part 2](#part-2--d-6-refuse-a-plain-http-backend-when-the-provider-encrypts)
  for why the check keys on the endpoint scheme instead).
- **D-7**: add `s3_security.max_presign_expiry_seconds`, default 3600, hard cap
  604800, clamping the currently hardcoded ceiling.
- **E-3** (found 2026-09-06 while correcting the README reference, needs a
  decision before it is implemented): `viper.SetDefault("encryption.integrity_verification", "off")`
  in [config.go:357](../../internal/config/config.go#L357). A deployment that omits
  the key runs with **no HMAC verification at all**, while `CLAUDE.md`, the
  README and `SECURITY_ARCHITECTURE.md` all present `strict` as the recommended
  mode. Under the threat model this is the wrong default: the safe value has to
  be the one you get by saying nothing. The reason it is a decision and not a
  fix is the blast radius. Flipping the default to `strict` makes an existing
  deployment that never set the key start rejecting every object stored without
  an `s3ep-hmac`, which is exactly what `hybrid` exists for. Options: flip to
  `strict` and document the break; flip to `hybrid` as a safe-but-permissive
  middle; or refuse to start when the key is absent under an encrypting
  provider, which forces the operator to choose. Note that ticket
  [013](013-storage-format-v2.md) deletes the key entirely, because v2 makes
  integrity inseparable from decryption, so whichever option is picked here is
  an interim measure whose lifetime is the distance to v2.
- **E-1**: make the `Authorization`-header path honour
  `s3_security.max_clock_skew_seconds`, which today only the pre-signed path
  reads.
- **E-2**: delete `strict_signature_validation` and `enable_security_logging`,
  also read nowhere, and the unused `GetS3SecurityConfig()`.
- Every file carrying a deleted key: five `config/*.yaml`, the production Helm
  values, the e2e proxy values, `README.md`, `CLAUDE.md`. Enumerated in
  [Part 1.4](#14-every-file-that-carries-a-dead-key).

**Out**

- **Implementing a rate limiter.** Per-IP limiting is the wrong tool here:
  Velero and its node-agent each present one pod IP and burst far past any
  per-IP limit during a backup, and the real controls are authentication and
  container resource limits. If a limiter is wanted later it gets its own ticket
  with a test that proves it throttles — that test is the whole point, and it is
  what this code never had.
- **A Prometheus counter for failed authentications.** Tempting while deleting
  the map, but not asked for by any decision, and the per-IP label it would want
  has the same unbounded-cardinality problem as the map. If the visibility is
  wanted, it is a separate change with a dashboard panel that uses it.
- `encryption.verify_upload_digests` (D-9, the upload checksums ticket) and the
  config deletions v2 owns (`integrity_verification`, `streaming_threshold`).
- The rest of the legacy top-level S3 block (`target_endpoint`, `region`,
  `access_key_id`, `secret_key`, `skip_ssl_verification` at
  [config.go:158-171](../../internal/config/config.go#L158-L171) and
  `migrateLegacyConfig` at
  [config.go:265-310](../../internal/config/config.go#L265-L310)). It is
  backward-compatibility scaffolding the project rules say to delete, but it is
  a separate change with its own test fallout — `TestLoad_ValidNoneConfig`
  ([config_test.go:15](../../internal/config/config_test.go#L15)) reaches the
  backend through the legacy `target_endpoint`
  ([config_test.go:21](../../internal/config/config_test.go#L21)); its providers
  and clients already use the current keys. Only `use_tls` leaves here, because
  D-6 is about it.
- Chart items (P-10) and `SECURITY_ARCHITECTURE.md` (order of work, item 7).

---

## Part 1 — N-5: the four dead knobs and the map behind them

### 1.1 What is actually there

Verified by grep over the whole tree and by reading every hit.

| Key | Parsed | Validated | Read by |
|---|---|---|---|
| `s3_security.enable_rate_limiting` | [config.go:90](../../internal/config/config.go#L90) | [config.go:737](../../internal/config/config.go#L737) | nothing |
| `s3_security.max_requests_per_minute` | [config.go:93](../../internal/config/config.go#L93) | [config.go:738-743](../../internal/config/config.go#L738-L743) | nothing |
| `s3_security.max_failed_attempts` | [config.go:99](../../internal/config/config.go#L99) | [config.go:747-752](../../internal/config/config.go#L747-L752) | nothing |
| `s3_security.unblock_ip_seconds` | [config.go:103](../../internal/config/config.go#L103) | [config.go:755-760](../../internal/config/config.go#L755-L760) | nothing |

Defaults are set for all four at
[config.go:361-365](../../internal/config/config.go#L361-L365), and two of them get
a second, redundant default in `GetS3SecurityConfig()`
([config.go:843-848](../../internal/config/config.go#L843-L848)) — the same values
viper already sets (100 and 10), in a function with no caller anywhere in the
tree. There is no rate limiter, no IP block list and no unblock timer in the
repository; `grep -rni "rate.limit" internal/` returns six lines, all of them in
`config.go` (89, 90, 361, 736, 737, 739).

### 1.2 The failed-attempt map is worse than dead

[`logSecurityEvent`](../../internal/proxy/middleware/s3auth_robust.go#L418-L444) is
called on every authentication failure from both the header path and the
pre-signed path (14 call sites across
[s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go) and
[s3auth_presigned.go](../../internal/proxy/middleware/s3auth_presigned.go)). It
does this:

- increments `securityMetrics.FailedAttempts[clientIP]`
  ([s3auth_robust.go:424](../../internal/proxy/middleware/s3auth_robust.go#L424));
- `clientIP` comes from `getClientIP`
  ([s3auth_robust.go:447-462](../../internal/proxy/middleware/s3auth_robust.go#L447-L462)),
  which takes the **first `X-Forwarded-For` value** if the header is present.
  The proxy sits behind nothing that sanitises it, so on an internet-facing
  deployment that string is chosen by the caller;
- the map has no expiry and no size bound, so unauthenticated requests grow proxy
  RSS without limit — one map entry per distinct attacker-supplied string;
- the "brute force" branch
  ([s3auth_robust.go:438-443](../../internal/proxy/middleware/s3auth_robust.go#L438-L443))
  compares against a literal `5`, not against `max_failed_attempts`, and only
  writes a log line. Nothing is ever blocked;
- **there is no mutex.** `grep sync` in that file returns nothing. Concurrent
  requests write the same map from multiple handler goroutines, which is a
  `fatal error: concurrent map writes` — an unrecoverable crash, not a race the
  runtime tolerates. It has not been observed because two failures have to
  collide in the same instant, and the e2e authenticates successfully.

The three sibling counters (`InvalidSignatures`, `ClockSkewErrors`,
`ReplayAttempts`, incremented at
[:123](../../internal/proxy/middleware/s3auth_robust.go#L123),
[:137](../../internal/proxy/middleware/s3auth_robust.go#L137),
[:252](../../internal/proxy/middleware/s3auth_robust.go#L252) and
[s3auth_presigned.go:116](../../internal/proxy/middleware/s3auth_presigned.go#L116))
are unsynchronised `int`s that nothing reads: `GetSecurityMetrics`
([:465](../../internal/proxy/middleware/s3auth_robust.go#L465)) and
`ResetSecurityMetrics` ([:470](../../internal/proxy/middleware/s3auth_robust.go#L470))
have no callers in the tree, and the `SecurityMetrics` subtest in
[auth_test.go:430-451](../../test/integration/authentication/auth_test.go#L430-L451)
only curls `/metrics`, which is Prometheus and unrelated. So the whole struct
goes, not just the map.

The `ReplayAttempts` increment is additionally unreachable:
[:245-248](../../internal/proxy/middleware/s3auth_robust.go#L245-L248) already
returns when the **absolute** time difference exceeds the skew, so the
`now.Sub(requestTime) > skew` test at
[:251](../../internal/proxy/middleware/s3auth_robust.go#L251) can never be true.
That branch goes with E-1 below.

**Amended 2026-09-07 (D-24).** Two things changed after this section was written. First,
the mutex half is **fixed**: [024](024-coverage-round-findings.md) C-1 serialised every
counter access (`036301b`), because the concurrent-write crash turned out to be reachable
from the unauthenticated failure path by two parallel bad-signature requests. Second, the
owner decided the map is **kept, not deleted** — see Part 5 below, which reverses the
"whole struct goes" conclusion above and says what that implies for the two blocking knobs
in Part 1.1.

### 1.3 What stays

The `Warn`-level line at
[s3auth_robust.go:427-435](../../internal/proxy/middleware/s3auth_robust.go#L427-L435)
stays — event type, client IP, user agent, method, path, details. Only the
`failed_count` field leaves with the map. `getClientIP` stays: as a log field
an attacker-chosen `X-Forwarded-For` is fine, and it is the only way to see a
real client behind a real load balancer. As a **map key** it was the problem.

### 1.4 Every file that carries a dead key

Enumerated by
`grep -rn "enable_rate_limiting\|max_requests_per_minute\|max_failed_attempts\|unblock_ip_seconds"`
over the tree, excluding `.git`:

| File | Lines | Note |
|---|---|---|
| [internal/config/config.go](../../internal/config/config.go#L89-L103) | 89-103, 361-365, 736-760, 843-848 | struct, defaults, validation, second defaults |
| [config/aes-example.yaml](../../config/aes-example.yaml#L46-L60) | 46-60 | mounted by the demo HTTP proxy |
| [config/aes-tls-example.yaml](../../config/aes-tls-example.yaml#L55-L69) | 55-69 | mounted by the demo TLS proxy |
| [config/rsa-example.yaml](../../config/rsa-example.yaml#L41-L54) | 41-54 | |
| [config/none-example.yaml](../../config/none-example.yaml#L43-L57) | 43-57 | |
| [config/multi-example.yaml](../../config/multi-example.yaml#L41-L54) | 41-54 | |
| [deploy/helm/s3-encryption-proxy/values-production.yaml](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L160-L164) | 160-164 | the only chart values file with an `s3_security` block |
| [test/e2e/velero/values-proxy.yaml](../../test/e2e/velero/values-proxy.yaml#L131-L138) | 131-138 | including the four-line comment explaining the D-5 relaxation, which describes a limiter that does not exist |
| [README.md](../../README.md#L270-L274) | 20, 270-274, 604-606, 613 | |
| [CLAUDE.md](../../CLAUDE.md#L147-L151) | 147-151 | |

`CHANGELOG.md:1262` mentions `unblock_ip_seconds` in a released commit subject
and is left alone; the changelog is history, not configuration.

`deploy/helm/s3-encryption-proxy/values.yaml`, `values-development.yaml` and
`values-monitoring.yaml` have no `s3_security` block and need no change.
(`values-development.yaml:53` does carry a plain-HTTP endpoint, but as
`targetEndpoint` under a camelCase `config:` map that viper never maps to
`target_endpoint`; that file is ticket 016's, not this one's.)

README needs four edits, not one:

- the `s3_security` config reference block at
  [README.md:266-274](../../README.md#L266-L274);
- the `use_tls` line in the `s3_backend` block just above it,
  [README.md:256](../../README.md#L256) (Part 2 deletes that key);
- the Velero note at [README.md:604-606](../../README.md#L604-L606), which states
  the throttling behaviour as fact and is the clearest example of rule 2 — a
  reader would configure around a limiter that does not exist;
- two feature bullets that advertise "AWS Signature V4 validation with rate
  limiting", [README.md:20](../../README.md#L20) and
  [README.md:613](../../README.md#L613). Line 20 is currently three bullets run
  together on one line with one replacement character in it, where an emoji was
  lost; split it back into three while rewriting it.

`testRateLimiting` in
[auth_test.go:389-428](../../test/integration/authentication/auth_test.go#L389-L428)
sends ten `/health` requests 100 ms apart and asserts that at least one returns
200. It tests nothing about rate limiting and passes for the same reason it
would pass against an empty binary. Delete it and its call site at
[auth_test.go:139-141](../../test/integration/authentication/auth_test.go#L139-L141).
This is not a skipped integration test: it is a test of a feature that is being
removed because it does not exist.

---

## Part 2 — D-6: refuse a plain-HTTP backend when the provider encrypts

### 2.1 The knob the decision names does not do anything

D-6 is phrased as "refuse to start with `s3_backend.use_tls: false`". Verified
in this tree: `use_tls` reaches nothing. `S3BackendConfig.UseTLS`
([config.go:42](../../internal/config/config.go#L42)) and the legacy
`Config.UseTLS` ([config.go:170](../../internal/config/config.go#L170)) are read in
exactly two places, and both only copy the value onwards: the migration branch
([config.go:290-294](../../internal/config/config.go#L290-L294)), which moves the
legacy key into `s3_backend`, and
[server.go:107-109](../../internal/proxy/server.go#L107-L109), which copies the
legacy value into the new one and then never uses either.
`backendClientOptions`
([server.go:153-196](../../internal/proxy/server.go#L153-L196)) does not look at
it. The transport is decided solely by the scheme of `target_endpoint`, which
becomes `o.BaseEndpoint` at
[server.go:177](../../internal/proxy/server.go#L177). Ticket 012 item 6.1 already
recorded this and asked for a decision: *"Either remove dead `use_tls` from
config or wire it up — don't leave it lying."*

So a check on `use_tls` would refuse the wrong configurations and pass the
failing one: the shipped default is `use_tls: true`
([config.go:321](../../internal/config/config.go#L321)), and
`target_endpoint: "http://minio:9000"` with that default is exactly the setup
that dies on the first 5 MiB upload.

**Design decision.** The refusal keys on the scheme of
`s3_backend.target_endpoint`, and `use_tls` is deleted in the same change:
`s3_backend.use_tls` ([config.go:42](../../internal/config/config.go#L42)), the
legacy `use_tls` ([config.go:170](../../internal/config/config.go#L170)), both
defaults ([config.go:321](../../internal/config/config.go#L321),
[config.go:326](../../internal/config/config.go#L326)), the migration branch
([config.go:290-294](../../internal/config/config.go#L290-L294)), the fallback
([server.go:107-109](../../internal/proxy/server.go#L107-L109)), and the
`use_tls: true` line in all five `config/*.yaml`, in
[values-production.yaml:148](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L148)
and in
[values-proxy.yaml:117](../../test/e2e/velero/values-proxy.yaml#L117), and the same
line in the two documented `s3_backend` blocks
([README.md:256](../../README.md#L256), [CLAUDE.md:133](../../CLAUDE.md#L133)),
which the [success criteria](#success-criteria) grep also covers. This is
the same decision as N-5 applied to a key the findings doc did not list, and
enforcing a knob that controls nothing would be precisely the failure mode the
threat model's rule 2 names. The comment at
[server.go:167-170](../../internal/proxy/server.go#L167-L170) claims
"`s3_backend.use_tls` provides transport integrity" for the backend hop — wrong
twice over, and rewritten to name the endpoint scheme.

### 2.2 Where the check goes

Two halves, in two places, for two reasons.

**The refusal goes in config validation.** A new
`validateBackendTransport(cfg)` in
[internal/config/config.go](../../internal/config/config.go), called from
`validate()` ([config.go:370](../../internal/config/config.go#L370)) after
`validateLicenseAndEncryption` ([config.go:400-402](../../internal/config/config.go#L400-L402)) so
the active provider has already been validated and `GetActiveProvider()`
([config.go:764](../../internal/config/config.go#L764)) can be trusted. Reasons: it
is a configuration inconsistency and belongs with the other checks in
`validate()` ([config.go:370-415](../../internal/config/config.go#L370-L415)); it fires
before a listener or an S3 client exists; and every entry point that loads
config gets it, not only `main`. The failure surfaces through
[main.go:76-79](../../cmd/s3-encryption-proxy/main.go#L76-L79) as
`Failed to load configuration` with the message as the error, and the process
exits non-zero — which is what a Kubernetes operator sees as `CrashLoopBackOff`
with a readable reason, instead of a pod that is Ready and fails every backup.

Predicate, a small helper next to it:

```go
// backendUsesTLS reports whether the configured backend endpoint is reached
// over TLS. The transport comes from the endpoint scheme alone: it is what
// reaches the SDK as BaseEndpoint.
func backendUsesTLS(endpoint string) (bool, error)
```

`https` → true, `http` → false, anything else → an error. Rejecting a
scheme-less `target_endpoint` (`minio:9000`) is deliberate and new: today that
string is passed to `o.BaseEndpoint` verbatim and what the SDK does with it is
undefined. `target_endpoint` is already mandatory
([config.go:377-379](../../internal/config/config.go#L377-L379)), so this only
tightens its shape.

The error, one `fmt.Errorf`, naming the symptom the operator would otherwise
spend an afternoon on:

```
s3_backend.target_endpoint is plain HTTP (%q) while the active encryption
provider %q (type %q) encrypts: aws-sdk-go-v2 only sends an unseekable
streaming body with UNSIGNED-PAYLOAD over TLS, so every streaming upload fails
with "failed to seek body to start". Use an https:// endpoint, or the "none"
provider if a pass-through proxy is what you want.
```

When no provider is configured at all, `GetActiveProvider()` returns an error
and `validateBackendTransport` returns nil: the configuration has other problems
and this check has nothing to say about them. That keeps
`TestIntegrityVerificationWithDefaults`
([integrity_verification_test.go:169-196](../../internal/config/integrity_verification_test.go#L169-L196))
green, which loads `http://localhost:9000` with no providers.

**The warning goes in `main`.** Folded into the existing active-provider block
at [main.go:138-149](../../cmd/s3-encryption-proxy/main.go#L138-L149), which
already loops over the providers to warn about `none`. Replace that hand-rolled
loop with one `cfg.GetActiveProvider()` call and emit both warnings from it.
Reasons: it needs the logger, and the log level and format are configured
immediately above at
[main.go:118-136](../../cmd/s3-encryption-proxy/main.go#L118-L136); doing it in
`config.go` would mean `fmt.Fprintf(os.Stderr, ...)` like the legacy-migration
warning at [config.go:302-308](../../internal/config/config.go#L302-L308), which is
not in the log stream an operator watches.

```
⚠️  Plain-HTTP S3 backend with the 'none' provider: credentials, bucket names
and object keys travel in clear to the backend, and a streaming upload may
still fail, because aws-sdk-go-v2 needs TLS for an unseekable body.
```

"may still fail" is honest, not hedging: the `none` provider returns the
client's reader unchanged
([manager.go:139-146](../../internal/orchestration/manager.go#L139-L146),
[manager.go:225-234](../../internal/orchestration/manager.go#L225-L234)), so the
body handed to the SDK is just as unseekable as a ciphertext stream. D-6's
original recommendation assumed a pass-through body "may still be seekable";
that is unverified and the code reading suggests it is not. See
[Risks](#risks-and-open-questions) — one probe settles it, and if it fails the
warning becomes a second refusal, which is a one-line change.

---

## Part 3 — D-7: a configurable pre-signed URL ceiling

### 3.1 Current state

`maxPresignExpirySeconds` is a package constant of 7 days at
[s3auth_presigned.go:24-25](../../internal/proxy/middleware/s3auth_presigned.go#L24-L25),
enforced in `validatePresignExpiry` at
[s3auth_presigned.go:142-144](../../internal/proxy/middleware/s3auth_presigned.go#L142-L144).
`X-Amz-Expires` is already mandatory
([:135-137](../../internal/proxy/middleware/s3auth_presigned.go#L135-L137)) and the
signing time is already bounded by the configured clock skew
([:146-156](../../internal/proxy/middleware/s3auth_presigned.go#L146-L156)), so the
ceiling is the only piece an operator cannot influence.

### 3.2 The change

Add to `S3SecurityConfig`
([config.go:82-104](../../internal/config/config.go#L82-L104)):

```go
// Maximum lifetime a pre-signed URL may claim, in seconds (default: 3600).
// Hard-capped at 604800 (7 days), the AWS maximum.
MaxPresignExpirySeconds int `mapstructure:"max_presign_expiry_seconds"`
```

- default: `viper.SetDefault("s3_security.max_presign_expiry_seconds", 3600)`
  beside [config.go:360](../../internal/config/config.go#L360);
- validation in `validateS3Security`
  ([config.go:725](../../internal/config/config.go#L725)), in the space the four
  deleted blocks free up: reject `<= 0` and reject `> 604800` with
  `s3_security.max_presign_expiry_seconds cannot exceed 604800 seconds (7 days, the AWS maximum)`;
- in the middleware, replace the constant with two:
  `defaultPresignExpirySeconds = 3600` and
  `presignExpiryHardCapSeconds = 7 * 24 * 60 * 60`, plus a helper mirroring
  `maxClockSkewSeconds()`
  ([s3auth_presigned.go:160-167](../../internal/proxy/middleware/s3auth_presigned.go#L160-L167))
  exactly, including its `s.config != nil` guard:

```go
func (s *S3AuthenticationService) maxPresignExpirySeconds() int
```

  returning the configured value when positive, `defaultPresignExpirySeconds`
  otherwise, clamped to `presignExpiryHardCapSeconds` in both cases. The clamp
  is not redundant with the config validation: a `Config` built in code (as the
  middleware tests do) never passes through `validate()`.

- update the doc comment at
  [s3auth_presigned.go:47-48](../../internal/proxy/middleware/s3auth_presigned.go#L47-L48),
  which currently states the 7-day bound as the rule.

### 3.3 Why 3600, and why it does not break Velero

Velero mints its download URLs with `signedURLTTL`, 10 minutes by default
([download_request_controller.go](https://github.com/vmware-tanzu/velero/blob/main/pkg/controller/download_request_controller.go)),
for `velero backup logs`, `velero restore logs`, `velero backup download` and
the results fetch inside `velero backup describe --details`. 600 s fits inside
3600 s with room for an operator who raises the TTL. The deviation from the S3
7-day maximum is documented in the README under "Pre-signed URLs"
([README.md:567-573](../../README.md#L567-L573)) together with the knob and the
hard cap, so a client that legitimately needs longer URLs has one line to
change.

### 3.4 Tests that must change

[s3auth_presigned_test.go:192-203](../../internal/proxy/middleware/s3auth_presigned_test.go#L192-L203),
`oversized_expires_is_rejected`, sets `X-Amz-Expires` to
`maxPresignExpirySeconds+1`; that identifier is going away. The test service
([:28-37](../../internal/proxy/middleware/s3auth_presigned_test.go#L28-L37)) builds
a `config.Config` with only `MaxClockSkewSeconds`, so it will fall back to the
3600 default — set `defaultPresignExpirySeconds+1` there. Everything else in
that file signs for 10 minutes and stays valid under the new default.

---

## Part 4 — E-1 and E-2: found while verifying, same defect class

Neither is in the findings doc. Both are flagged rather than assumed: see
[Risks](#risks-and-open-questions) if either should be dropped.

**E-1 — `max_clock_skew_seconds` is honoured on one of two auth paths.**
`validateTimestamp` compares against the package constant
`MaxClockSkewSeconds = 900`
([s3auth_robust.go:40](../../internal/proxy/middleware/s3auth_robust.go#L40)) at
[:246](../../internal/proxy/middleware/s3auth_robust.go#L246) and
[:251](../../internal/proxy/middleware/s3auth_robust.go#L251), while the pre-signed
path reads the configured value through `maxClockSkewSeconds()`
([s3auth_presigned.go:162-167](../../internal/proxy/middleware/s3auth_presigned.go#L162-L167)).
Every shipped config and the e2e set `max_clock_skew_seconds: 300`, so header
authentication today tolerates a replay window three times wider than the
configuration says. Fix: call `s.maxClockSkewSeconds()` in `validateTimestamp`
and keep the constant as the fallback the helper already uses. Delete the
unreachable replay branch at
[:250-254](../../internal/proxy/middleware/s3auth_robust.go#L250-L254) in the same
edit (see [1.2](#12-the-failed-attempt-map-is-worse-than-dead)). This tightens
behaviour, so it needs one unit test per direction: a request 400 s old is
rejected with `max_clock_skew_seconds: 300` and accepted with 900.

**E-2 — two more `s3_security` keys nothing reads.**
`strict_signature_validation`
([config.go:84](../../internal/config/config.go#L84)) and
`enable_security_logging` ([config.go:96](../../internal/config/config.go#L96)) have
no reader in the tree either. Both fail safe today — signature validation is
always strict, security events are always logged — so nothing is exposed, but
`strict_signature_validation: false` silently does nothing, which is the same
lie in a smaller font. Delete both, delete the unused `GetS3SecurityConfig()`
([config.go:835-851](../../internal/config/config.go#L835-L851)), and drop the keys
from the same eleven files as Part 1.4. What remains in `s3_security` is
`max_clock_skew_seconds` (enforced on both paths after E-1) and
`max_presign_expiry_seconds` (new, enforced).

---

## Part 5 — Decisions from the coverage round (D-22, D-24, D-30)

Three items assigned here on 2026-09-07 from [024](024-coverage-round-findings.md). Each
is a configuration or listener change with a fail-closed answer, which is this ticket's
subject.

### 5.1 D-22 — pprof on its own loopback listener (024 S-3)

`/debug/pprof` is registered on the monitoring mux, which has no authentication and binds
`:9090` on every interface by default ([server.go](../../internal/monitoring/server.go),
[config.go](../../internal/config/config.go)). On an encryption proxy a heap profile
contains DEKs and plaintext buffers. Dormant in a stock install — `monitoring.enabled`,
`pprof_enabled` and the chart's monitoring Service all default to off — but the demo
config enables pprof, and the log line telling the operator to restrict access is a
control that exists only in documentation.

Decided: **`/debug/pprof` moves to its own listener bound to `127.0.0.1`**, port
configurable (`monitoring.pprof_bind_address`, default `127.0.0.1:6060` — verify the port
is free in the compose and e2e stacks). `/metrics` stays on the monitoring port so it can
be scraped cluster-wide. `kubectl port-forward` reaches loopback, so an administrator loses
nothing. A `pprof_bind_address` that is not a loopback address is a startup error, not a
warning — the demo config is corrected in the same change.

### 5.2 D-24 — keep the failure map; trusted proxies and eviction (024 S-4)

Part 1.2 concluded the whole `SecurityMetrics` struct should go. The owner decided the
other way: **keep `FailedAttempts`, add a trusted-proxy allowlist, and bound the map.**

- `s3_security.trusted_proxies`: a list of CIDRs. `X-Forwarded-For` and `X-Real-IP` are
  honoured only when `RemoteAddr` is inside one of them, and then the *last* untrusted hop
  is taken, not the first value in the header (the first value is the one an attacker
  writes). Empty list means the headers are ignored and `RemoteAddr` is the client.
- Eviction: a TTL per entry (`unblock_ip_seconds` is the natural source) and a hard cap on
  entries, oldest evicted first. The map can then no longer be grown without bound by
  varying a forged header on failing requests.

**The consequence this decision carries, flagged for the owner rather than assumed.**
Keeping the map only earns its trusted-proxy machinery if something *reads* it. Today its
only consumer is a log line comparing against a literal `5`. So either
`max_failed_attempts` and `unblock_ip_seconds` are **implemented** — which reverses Part 1
for those two knobs and turns them from dead into live security controls that need tests
of their own — or the map stays a counter feeding a log line, in which case a CIDR list is
infrastructure for a log line. This ticket assumes the first reading, because it is the
only one under which D-24 makes sense, and it needs a yes before item 5.2 is built.

### 5.3 D-30 — validate `metadata_key_prefix` at startup (024 H-5)

The prefix is read from config and never checked ([config.go](../../internal/config/config.go)).
Two values are catastrophic and both are accepted today: **empty** makes
`isNoneProviderData` treat every object as unencrypted, so every GET serves the ciphertext
as plaintext with a 200; **non-lowercase** never matches, because S3 lower-cases metadata
keys in transit while the comparison here does not, so decryption is silently disabled and
the encryption metadata leaks to the client.

Decided: **reject at startup.** The prefix must be non-empty and match `^[a-z0-9-]+$`;
anything else is a configuration error naming the field and the rule. No silent
normalisation — a config that would have turned the proxy into a shredder should fail
loudly, not be quietly repaired. One unit test per rejected shape, one for the default.

---

## Work breakdown

Ordered so each item compiles and tests green on its own.

- [ ] **1. Delete `SecurityMetrics`.** The struct
      ([s3auth_robust.go:52-58](../../internal/proxy/middleware/s3auth_robust.go#L52-L58)),
      the field ([:49](../../internal/proxy/middleware/s3auth_robust.go#L49)), its
      initialisation
      ([:82-84](../../internal/proxy/middleware/s3auth_robust.go#L82-L84)), the
      four increments
      ([:123](../../internal/proxy/middleware/s3auth_robust.go#L123),
      [:137](../../internal/proxy/middleware/s3auth_robust.go#L137),
      [:252](../../internal/proxy/middleware/s3auth_robust.go#L252),
      [s3auth_presigned.go:116](../../internal/proxy/middleware/s3auth_presigned.go#L116)),
      `GetSecurityMetrics`, `ResetSecurityMetrics`, and the `failed_count` field
      plus the brute-force branch in `logSecurityEvent`. Keep the `Warn` line and
      `getClientIP`.
- [ ] **2. E-1 in the same file:** `validateTimestamp` uses
      `s.maxClockSkewSeconds()`; the unreachable replay branch goes. Unit tests
      for 300 s and 900 s configurations.
- [ ] **3. Delete the six dead config keys** (`enable_rate_limiting`,
      `max_requests_per_minute`, `max_failed_attempts`, `unblock_ip_seconds`,
      `strict_signature_validation`, `enable_security_logging`) from the struct,
      the defaults, `validateS3Security` and `GetS3SecurityConfig` — the last of
      which goes entirely.
- [ ] **4. D-7:** add `max_presign_expiry_seconds` with its default, validation,
      middleware helper and clamp; update the doc comment; fix
      `oversized_expires_is_rejected`; add the three tests named in
      [Success criteria](#success-criteria).
- [ ] **5. D-6 refusal:** `backendUsesTLS` + `validateBackendTransport`, wired
      into `validate()`. Unit tests for http/https × encrypting/`none`/no
      provider, and for a scheme-less endpoint.
- [ ] **6. D-6 warning:** rewrite the provider block in
      [main.go:138-149](../../cmd/s3-encryption-proxy/main.go#L138-L149) around
      `GetActiveProvider()` and emit the plain-HTTP warning for `none`.
- [ ] **7. Delete `use_tls`** in both structs, both defaults, the migration
      branch and the `server.go` fallback; rewrite the misleading comment at
      [server.go:167-170](../../internal/proxy/server.go#L167-L170).
- [ ] **8. Config surface:** remove the dead keys and `use_tls` from the five
      `config/*.yaml`, `values-production.yaml` and `values-proxy.yaml`
      (including the four-line D-5 comment at
      [values-proxy.yaml:131-134](../../test/e2e/velero/values-proxy.yaml#L131-L134)).
      Add `max_presign_expiry_seconds` to the example configs with its default
      and a one-line comment.
- [ ] **9. Delete `testRateLimiting`** and its call site in
      [auth_test.go](../../test/integration/authentication/auth_test.go#L389-L428).
- [ ] **10. Docs:** README config block — both halves, the `s3_security` block
      at [README.md:266-274](../../README.md#L266-L274) and the `use_tls` line in
      the `s3_backend` block at [README.md:256](../../README.md#L256) — the Velero
      note, both feature bullets
      (splitting the mangled line 20), the "Pre-signed URLs" section with the new
      knob and the documented deviation from the S3 7-day maximum, and a line in
      the S3 backend section stating that an `https://` `target_endpoint` is
      required unless the provider is `none`. Mirror both config blocks into
      `CLAUDE.md` ([:133](../../CLAUDE.md#L133), [:147-151](../../CLAUDE.md#L147-L151)).
- [ ] **11. Full verification pass** per the next section.
- [ ] ~~**12. D-22: pprof on its own loopback listener.**~~ **Done 2026-09-07**,
      ahead of the rest of this ticket because it depends on nothing in it.
      `monitoring.pprof_bind_address` (`127.0.0.1:6060` # default) with
      `requireLoopbackAddress` in `validateMonitoring`
      ([config.go](../../internal/config/config.go)); a non-loopback value, `:6060`
      included, is a startup error naming the field. The listener is
      `monitoring.PprofServer` ([pprof.go](../../internal/monitoring/pprof.go)) and
      the monitoring mux no longer registers pprof at all, so it gets its
      unconditional 30 s `WriteTimeout` back — enabling pprof used to strip it
      from `/metrics` as well. Two consequences worth naming:
      - **pprof no longer depends on `monitoring.enabled`.** It used to, which
        made `pprof_enabled: true` on its own silently do nothing — the same
        class of lie as the dead knobs in Part 1. Coupling it back is also not
        possible as a validation rule: `--monitoring` overrides
        `cfg.Monitoring.Enabled` in
        [main.go:82](../../cmd/s3-encryption-proxy/main.go#L82) *after* `validate()`
        has run, so such a rule would reject a legitimate command line.
      - **A name is refused rather than resolved.** Only a loopback IP literal or
        the literal `localhost` is accepted. Resolving at startup would make the
        proxy fail to boot without a resolver, and a name that points at loopback
        today can point elsewhere tomorrow while the process keeps running.
      The demo profiling workflow in [012](012-performance-audit-round2.md) was
      updated in the same change: `localhost:9090/debug/pprof` now 404s and the
      image is distroless, so a profile is taken from a container sharing the
      proxy network namespace.
- [x] ~~**13. D-30: validate `metadata_key_prefix`.**~~ **Done 2026-09-07.**
      `metadataKeyPrefixPattern` = `^[a-z0-9-]+$`, checked as the **first** statement of
      `validateEncryption` ([config.go](../../internal/config/config.go)) — the provider
      branch below it returns early for every configuration that actually has providers,
      so a check appended at the end would never run in production. A nil pointer stays
      accepted: `setDefaults` supplies `s3ep-`, so nil only occurs in struct-built test
      configs. Corrections to item 5.3, both because the tree said otherwise:
      - **The empty-prefix mechanism is not what 5.3 and 024 H-5 say.**
        `isNoneProviderData` ([singlepart.go:330](../../internal/orchestration/singlepart.go#L330))
        explicitly *ignores* an empty configured prefix and falls back to the literal
        `s3ep-`. The shredder comes from the **disagreement**: every writer honours `""`
        and stores `encrypted-dek` unprefixed, that one reader still looks for `s3ep-`,
        finds nothing, and `DecryptData` hands the ciphertext back. Worth knowing because
        "fixing" `isNoneProviderData` to honour `""` literally makes it worse —
        `strings.HasPrefix(key, "")` is true for every key, so it would never pass
        anything through. Neither branch is right, which is why the value is refused at
        startup instead.
      - **"Never checked" is not quite true, and the exception is this ticket's own
        subject.** `MetadataManager.ValidateConfiguration`
        ([metadata.go:464](../../internal/orchestration/metadata.go#L464)) rejects
        whitespace in the prefix and comments *"Empty string is valid (means no prefix)"* —
        and **no production code calls it**. Dead validation that now also contradicts the
        live rule. Deleting it belongs with the rest of the dead-knob work in this ticket.
      No shipped YAML is rejected: the one uncommented `metadata_key_prefix` in the tree
      ([values.yaml:214](../../deploy/helm/s3-encryption-proxy/values.yaml#L214)) sits
      inside `providers[0].config`, where `mapstructure:",remain"` swallows it and nothing
      validates it at all — and its value `x-s3ep-` passes anyway. When
      [016](016-helm-chart-fixes.md) moves that key to the `encryption` block it starts
      being validated; that move stays a no-op for D-30, but the two must not land blind
      to each other.
      **What the rule deliberately leaves open**, reported rather than widened: no trailing
      separator is required, so a short prefix like `s3` silently swallows client metadata
      beginning with it (`isEncryptionMetadata` is a pure prefix test), and there is no
      maximum length, so a very long prefix fails at the backend with an opaque S3 error
      instead of at startup. And **changing** a valid prefix to another valid prefix still
      makes every stored object read back as pass-through, which the startup guard cannot
      see; failing closed on an object whose metadata carries a *different* known prefix
      belongs to [013](013-storage-format-v2.md).

---

## Success criteria

**The keys are gone, everywhere.** With `CHANGELOG.md` and the findings doc
excluded (history, not configuration), this returns nothing but the three
`SecurityMetrics` hits in
[auth_test.go](../../test/integration/authentication/auth_test.go#L143) (lines 143,
144 and 430), which name the Prometheus subtest that stays:

```bash
grep -rn "enable_rate_limiting\|max_requests_per_minute\|max_failed_attempts\|unblock_ip_seconds\|strict_signature_validation\|enable_security_logging\|use_tls\|UseTLS\|SecurityMetrics" . \
  --exclude-dir=.git --exclude=CHANGELOG.md --exclude-dir=tickets
```

**The chart still renders and carries no dead key:**

```bash
make helm-test
helm template t deploy/helm/s3-encryption-proxy -f deploy/helm/s3-encryption-proxy/values-production.yaml | grep -c "rate_limiting"   # 0
```

**Unit tests** — `make test-unit` green, with these added:

- `internal/config`: `http://` + `aes` provider fails with a message naming
  `target_endpoint`; `http://` + `none` provider loads; `https://` + `aes`
  loads; a scheme-less endpoint fails; no provider configured + `http://` loads
  (the check abstains).
- `internal/config`: `max_presign_expiry_seconds` of 0 and of 604801 are
  rejected; 3600 is the default when unset.
- `internal/proxy/middleware`: an SDK-signed URL with `X-Amz-Expires=600` is
  accepted under the default (this is the Velero case); the same URL is rejected
  by a service configured with `max_presign_expiry_seconds: 60`; a config above
  the hard cap is clamped rather than honoured.
- `internal/proxy/middleware`: a header-signed request 400 s old is rejected
  with `max_clock_skew_seconds: 300` and accepted with 900 (E-1).

**Lint** — `make lint` green. An import orphaned by the deletions is a compile
error, not a lint finding, so `go build ./...` is what catches it; `strings` in
`s3auth_robust.go` keeps other users
([:160](../../internal/proxy/middleware/s3auth_robust.go#L160),
[:178](../../internal/proxy/middleware/s3auth_robust.go#L178),
[:451](../../internal/proxy/middleware/s3auth_robust.go#L451)) and stays.

**Integration** — the demo comes up unchanged, because both compose proxies
already point at `https://minio:9000`: the HTTP proxy mounts
[config/aes-example.yaml:15](../../config/aes-example.yaml#L15)
([docker-compose.demo.yml:60](../../docker-compose.demo.yml#L60)) and the TLS proxy
[config/aes-tls-example.yaml:24](../../config/aes-tls-example.yaml#L24)
([:102](../../docker-compose.demo.yml#L102)):

```bash
./start-demo.sh
make test-integration        # plain-HTTP proxy listener
make test-integration-tls    # TLS proxy listener, the SDK's default framing
```

Both must be green with no test skipped or removed other than
`testRateLimiting`, which tested a feature that does not exist.

**Performance** — `make test-integration-performance` on an idle machine, three
runs, compared against the numbers currently in `docs/tickets/012-*`. Expected: no
change. The only hot-path edits are one fewer map write per **failed**
authentication and one function call replacing a constant in the clock-skew
check; a successful request loses nothing. Any movement beyond run-to-run noise
is a finding, not a rounding error, and gets reported before the ticket closes.

**Velero e2e** — `make e2e-up && make test-e2e-velero`, all 13 scenarios green
with the cleaned `values-proxy.yaml`. Two of them are the real assertions here:
V10 exercises `backup logs`, `restore logs` and `describe --details`, all of
which go through pre-signed URLs, so it proves the 3600 s default does not
break Velero's 600 s URLs; and the suite as a whole proves that removing the
"rate limiting off" line changes nothing, because there was never a limiter to
switch off.

**One manual probe** (D-6, `none` provider) — start the proxy with the `none`
provider against `http://minio:9000` and PUT an object above
`streaming_threshold`. Record the result in this ticket. If it fails with
`failed to seek body to start`, the warning becomes a refusal and D-6 loses its
exception.

---

## Risks and open questions

- **The `none`-provider exception may be worthless.** D-6 warns instead of
  refusing for `none` on the assumption that a pass-through body is seekable.
  Code reading says it is not:
  [manager.go:139-146](../../internal/orchestration/manager.go#L139-L146) and
  [manager.go:225-234](../../internal/orchestration/manager.go#L225-L234) return the
  caller's `io.Reader` unchanged, so the SDK sees the same unseekable stream. The
  manual probe above settles it. This does not block the ticket — the refusal for
  encrypting providers is the security-relevant half and is unaffected.
- **Deleting `use_tls` is a mechanism deviation from D-6's wording,** not from
  its decision. It is called out here rather than done quietly because it also
  closes ticket 012's item 6.1 question. If the key should instead be wired up
  to force the scheme, say so before item 7 — it is a different, larger change
  (endpoint rewriting) and it duplicates information the endpoint already
  carries. The refusal also settles the *rest* of 012's item 6.1: the
  plain-HTTP baseline run it asks for cannot be started with an encrypting
  provider once this lands, and its 1 GB streaming upload could not have
  completed before it either — that is the D-6 defect. 012 loses a measurement
  it never had; say so there rather than letting the next reader rediscover it.
- **E-1 and E-2 are additions.** Neither has a decision behind it. E-1 tightens
  a security window that configuration already claimed was tighter, so leaving
  it would leave the same class of lie this ticket exists to remove; E-2 is
  N-5's argument applied to two more keys in the same struct. Both are easy to
  drop from the branch if they should be their own ticket — E-1 is one call site
  plus two tests, E-2 is a field-and-grep deletion.
- **E-1 changes behaviour for a real client.** Any client whose clock is between
  300 s and 900 s off currently authenticates and afterwards will not. That is
  the configured intent, and the failure is a clear
  `request timestamp too far from current time`, but it is the one change here
  that can break a working deployment. The README should say it in the same
  change.
- **Nothing prevents the next dead knob.** There is no automated check that a
  `mapstructure` field has a reader, and a strict unknown-key decoder would not
  help: a field that is defined and never read passes it. The guard is a rule —
  a new configuration key lands in the same change as the code that reads it and
  a test that proves the effect — which is exactly what N-5's decision demands of
  a future rate limiter.
- **`X-Forwarded-For` stays in the logs.** After the map is gone, an
  attacker-chosen string still reaches the log line at
  [s3auth_robust.go:427-435](../../internal/proxy/middleware/s3auth_robust.go#L427-L435).
  Accepted: it is a log field, not a key or a decision input, and log injection
  is bounded by logrus's field quoting. Worth one sentence in
  `SECURITY_ARCHITECTURE.md` when that file is written, so the next reader does
  not mistake it for a trusted client identity.
- **`enable_security_logging` deletion is one-way.** If security-event logging
  should ever become suppressible, it comes back as a key with a reader. Deleting
  it now is the cheap direction.
- **Unverified:** whether any downstream deployment outside this repository sets
  the deleted keys. Viper ignores unknown keys silently, so such a config keeps
  loading and simply loses documentation it never had an implementation for.
  Worth a line in the release notes rather than a compatibility shim, per the
  project's no-backward-compatibility rule.
