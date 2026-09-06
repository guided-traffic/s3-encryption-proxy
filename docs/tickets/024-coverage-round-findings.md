# Ticket 024: The coverage round — what raising coverage found

## Status (2026-09-06)

**Open.** This is the record of the unit-coverage round run on
`feat/improve-test-coverage` on the night of 2026-09-06. It is a findings ticket, not a
work plan: the coverage itself is done and committed, and what is left here is the defect
list the exercise produced. Items that belong to an existing ticket are marked as such and
are **not** re-opened here — see [Ownership](#ownership-which-ticket-actually-fixes-what).

Every claim below carries its verification state:

- **Verified** — I read the code and confirmed it, or reproduced it with a test or a
  benchmark in this tree.
- **Reported** — a subagent reported it and I have not independently confirmed it. Treat
  these as leads, not as facts. One agent claim in this round was **wrong about severity**
  and is recorded in [Re-scoped](#re-scoped-claims-that-did-not-survive-checking) as a
  warning against taking the rest on trust.

---

## What the round did

Coverage of statements, unit tests only, `go test -short`:

| | Before | After wave 1 |
|---|---|---|
| Repository total | 63.1 % | **77.8 %** |

The measurement changed as well as the number, and the change is the more important half.
Two commits removed 1765 statements of test-shaped code from the *production* build before
a single test was written:

- `internal/proxy/mock_s3_backend.go`, 533 lines and 180 statements, a mock of the S3
  backend in package `proxy` with **no reference anywhere in the repository**, not even
  from a test. Deleted. `internal/proxy` 81.0 → 97.7 %.
- `handlers/{bucket,object,root}/test_helpers.go`, 1585 statements of testify mocks that
  were ordinary package members because the files lacked the `_test.go` suffix. Renamed.
  This also removed `github.com/stretchr/testify/mock` from the dependency graph of
  `cmd/s3-encryption-proxy`: `go list -deps` now finds no testify package in the binary.

`root` went 13.1 → 81.0 % purely from that rename, because 248 of its 290 statements were
the mock. `bucket` went **down**, 83.2 → 81.7 %, because its mock was better covered than
its handlers (921 of 1089 statements) and had been holding the package average up. 81.7 %
is the honest number for the handler code.

The lesson worth keeping: 628 uncovered statements, a quarter of every uncovered statement
in the repository, were mock code being measured as product code. A coverage percentage is
only as meaningful as its denominator.

### Why these packages and not the handlers

[Ticket 019](019-handler-unit-coverage.md) blocks handler-level unit coverage on
[ticket 013](013-storage-format-v2.md), per D-17: v2 deletes the GCM/CTR split, the
early-HMAC machinery, the ranged-read fork and the `integrity_verification` branches, so
handler tests written now would be rewritten line for line.

That constraint was respected, not ignored. Wave 1 covered only packages v2 does not
rewrite. Where later waves must touch v2-doomed code to reach a statement, the rule given
to every agent was: **test the client-visible contract, not the internal mechanism**, and
mark anything that pins v1 behaviour with

```go
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
```

so the churn v2 causes is localised and greppable instead of spread through the suite.

---

## Critical

### C-1 The security counters were a remote kill switch — **verified, fixed**

`logSecurityEvent` incremented `securityMetrics.FailedAttempts[clientIP]` with no
synchronisation, from the request goroutine
([s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go)).

Concurrent writes to a Go map are not a lost update. The runtime detects them and calls
`fatal("concurrent map writes")`, which terminates the process. It is not a panic, so
`net/http`'s per-connection recover cannot catch it.

The path that does it is the authentication **failure** path — bad signature, bad
timestamp, unknown access key — so it needs no credentials. Two parallel requests with a
forged signature were enough to end the process, and an attacker who wanted the proxy down
only had to keep sending them.

Fixed in `036301b`: every counter access goes through `metricsMu`, and
`GetSecurityMetrics` returns a deep copy rather than the live struct. `clientCache` was
checked and left alone — it is filled once in the constructor and only read afterwards,
and concurrent map reads are safe.

### C-2 A forged chunk header could allocate gigabytes, or panic — **verified, fixed**

`HTTPChunkedDecoder.ProcessChunkedData` sized its buffer from the client:
`make([]byte, chunkSize)` where `chunkSize` came from `ParseInt(line, 16, 64)`. The chunk
header is about twenty bytes and the value ranges to 2^63-1, so a tiny request body could
ask for a multi-gigabyte allocation before a byte of payload was read. `ParseInt` also
accepts a leading minus, and a negative length reaches `make()` in one decoder and
`p[:toRead]` in the other; both panic the request goroutine.

What makes this an oversight rather than a house style: `readAllSized` in
[parser.go](../../internal/proxy/request/parser.go) right next door already clamps its
length hint to `maxBodyPrealloc`.

Fixed in `4279275` with `io.CopyN` plus explicit negative guards in both decoders.

---

## Integrity

### I-1 A truncated aws-chunked upload was stored as a complete object — **verified, fixed**

`consumeCRLF` in
[streaming_aws_decoder.go](../../internal/proxy/request/streaming_aws_decoder.go) returned
a bare `io.EOF` when the stream ended where the chunk terminator belongs. `Read` passes
that out unchanged, and to `io.Copy` a bare `io.EOF` means *the stream ended cleanly*. A
client that hung up mid-upload therefore had its short body committed as a whole object —
and the HMAC verified, because the HMAC was computed over the bytes that actually arrived.

The body read immediately below it already converted this condition to
`io.ErrUnexpectedEOF`; only the terminator read was missing it. Fixed in `4279275`.

This is the same family as the truncated auto-multipart commit the pre-merge sweep found
(F-16 era), which is worth noting: it is the second instance of the same mistake, so the
class deserves a test rather than another point fix. The regression test is in
`internal/proxy/request/streaming_decoder_coverage_test.go`.

### I-2 The wrapped DEK aliased the buffer being zeroized — **verified, fixed, latent**

`EncryptDataStream` defers a loop that overwrites the plaintext DEK and returns whatever
`keyEncryptor.EncryptDEK` returned. `NoneProvider.EncryptDEK` returns its **input slice
unchanged**, so under the none provider the returned wrapped DEK aliased the buffer the
defer wipes.

Latent rather than live: both call sites in
[singlepart.go](../../internal/orchestration/singlepart.go) discard that return value, and
the base64 metadata string is built before the function returns, so the defer cannot reach
it. Fixed in `59ae8f0` with one `append` before it can become real.

---

## Security

### S-1 The AES KEK fingerprint is a crackable hash of a possibly human-chosen key — **verified, open**

Two facts that are each defensible alone and dangerous together.

`AESProvider.Fingerprint()` is `hex(SHA-256(kek))` over the **raw master KEK**, unsalted
([aes.go](../../pkg/encryption/keyencryption/aes.go)), and it is published in every
object's `s3ep-kek-fingerprint` metadata — which under this threat model the adversary
reads by definition.

`NewAESProvider` falls back to `kek = []byte(keyStr)` when the value does not base64-decode
to 32 bytes. So **any 32-character string is accepted as the AES-256 master key**:
`aes_key: "correct-horse-battery-staple-123"` starts the proxy.

Against a 32-byte random key, publishing SHA-256 of it is harmless. Against a 32-character
passphrase it is an offline dictionary attack with a free verification oracle, and
recovering the KEK unwraps every DEK and therefore every object.

[Ticket 013](013-storage-format-v2.md) already decided the fingerprint half — H-8, the
`aes` fingerprint becomes `HMAC-SHA256(KEK, "s3ep-kek-fingerprint")`. **The passphrase half
is not covered anywhere and is what turns H-8 from theoretical into practical.** The
options are to require base64 of 32 random bytes and reject the raw-string fallback, or to
run a passphrase through a KDF with a real work factor. That decision belongs to 013 with
the rest of the format change.

### S-2 The AES KEK wraps the DEK with unauthenticated AES-CTR — **verified, open**

`EncryptDEK` wraps with `cipher.NewCTR` and no MAC. A hostile backend can flip any bit of
`s3ep-encrypted-dek` and `DecryptDEK` returns a *different* DEK with no error — under CTR
the modification is bit-for-bit controlled.

Bounded today rather than exploitable: GCM objects fail their tag check, and for CTR
objects the HMAC key is HKDF-derived from the DEK, so a modified DEK produces a mismatching
HMAC. The exposure is the configurations where that check is absent — `integrity_verification`
`off` and `lax`, and `hybrid` against an object whose HMAC the backend simply removed,
which is N-2 exactly. Belongs to 013: an authenticated wrap (AES-GCM or AES-KW) is the fix,
and 013 is already rewriting the format.

### S-3 The monitoring port is unauthenticated, and pprof there exposes plaintext and keys — **reported, plausible, open**

The monitoring mux has no authentication and defaults to `:9090`, every interface. With
`PprofEnabled`, `/debug/pprof/heap` is registered on that same open port. On an encryption
proxy the heap holds DEKs, KEK-decrypted key material and plaintext object buffers, so
anyone who can reach the port can pull a heap profile and recover plaintext — defeating
encryption-at-rest from outside S3 entirely. The code logs a warning telling the operator
to restrict access; nothing enforces it, and rule 2 of the threat model says a control that
exists only in documentation is worse than none.

I have not reproduced the key recovery, hence *reported*. The exposure itself
(no auth, pprof on the metrics port, default bind `:9090`) is verifiable by reading
[server.go](../../internal/monitoring/server.go) and
[config.go](../../internal/config/config.go).

### S-4 Client IP is attacker-controlled and the failure map never shrinks — **verified, open**

`getClientIP` trusts `X-Forwarded-For`, then `X-Real-IP`, with no trusted-proxy allowlist,
and `securityMetrics.FailedAttempts` is never evicted. An unauthenticated client varying a
forged header on failing requests inserts an unbounded number of distinct map keys:
memory grows without bound. Independently, every security log line attributes the event to
an attacker-chosen address.

Related to N-5 / [ticket 015](015-configuration-hygiene.md): because `max_failed_attempts`
and `unblock_ip_seconds` are read by no code, there is no IP blocking to evade today. The
map growth and the log forgery are the live parts.

### S-5 AES-CTR silently discards the object key it is handed — **verified, open**

`AESGCMDataEncryptor.EncryptStream` takes `associatedData` and feeds it to GCM.
`AESCTRDataEncryptor.EncryptStream` and `DecryptStream` declare the same parameter as
`_ []byte` and **discard it**
([aes_ctr.go](../../pkg/encryption/dataencryption/aes_ctr.go)).

The caller passes the object key: `provider.EncryptDataStream(ctx, dataReader, []byte(objectKey))`
in [singlepart.go](../../internal/orchestration/singlepart.go). So the intent to bind an
object to its own key is in the code, and for GCM objects it holds. For CTR objects — which
is every object above `streaming_threshold` and every multipart upload — nothing binds the
ciphertext to the key it is stored under.

Under the hostile-backend model that is a live gap, not a theoretical one: the backend can
move a ciphertext object, its `s3ep-*` metadata included, from key A to key B and the proxy
serves it as B. The whole-object HMAC does not object, because the DEK travels with the
object and the HMAC key is derived from that DEK. For a backup store this means a restore
can return the wrong object with every integrity check passing.

[Ticket 013](013-storage-format-v2.md) already designs the fix and gives the reason
verbatim — `AAD = formatID ‖ clientObjectKey ‖ index`, *"it stops a hostile backend from
serving object A's ciphertext under B's name"*. What is **not** written down anywhere is
that the exposure exists today and that it is asymmetric: GCM objects are bound, CTR
objects are not. That asymmetry is what an operator needs to know before v2 ships, because
it says which of their objects are currently exposed. It belongs in
`SECURITY_ARCHITECTURE.md` next to H-1 as an interim statement.

### S-6 Replay defence and clock skew — **reported, open**

Two agent reports on the same area, not independently verified: that
`max_clock_skew_seconds` is ignored for header-signed requests (the constant
`MaxClockSkewSeconds` is used instead of the configured value), and that the replay branch
is unreachable so `ReplayAttempts` is always 0. If both hold, the configured skew window is
decorative for the main signing path. Sits with the 015 family of "knobs no code reads",
and should be checked before 015 is worked.

---

## Performance

Both of these are on a hot path, and MAIN GOAL 2 makes them worth their own section.

### P-1 The DEK is unwrapped twice on every GCM GET — **verified, measured, open**

[singlepart.go](../../internal/orchestration/singlepart.go) unwraps the DEK through the
ProviderManager (which caches, per [ticket 011](011-dek-cache-stale-on-reupload.md)), uses
it to derive the HMAC key, and then calls
`envelopeEncryptor.DecryptDataStream(ctx, reader, encryptedDEK, ...)`, which unwraps **the
same encrypted DEK a second time** inside
[envelope.go](../../pkg/encryption/envelope/envelope.go). The envelope layer does not go
through the ProviderManager, so the cache does not cover the second unwrap.

Measured in this tree, Apple M1 Ultra, `go test -bench`:

| KEK provider | one unwrap |
|---|---|
| `aes` | 392 ns |
| `rsa` (2048) | **936 613 ns ≈ 0.94 ms** |

So the redundant unwrap costs 0.4 µs under AES — noise — and **0.94 ms under RSA**, paid
serially before the first plaintext byte is delivered. One core does roughly 1067
RSA-2048 private-key operations per second, so the duplicate roughly **halves the ceiling
on GET throughput for the RSA provider**, from about 1067 to about 533 GETs per second per
core.

The fix is to pass the already-unwrapped DEK into the envelope layer instead of the wrapped
one, or to route the envelope layer through the ProviderManager cache. Ticket 013 rewrites
this path, so it should land there rather than as a separate change — but it must land,
and it should be measured after.

### P-2 The pooled read buffer is disabled unless monitoring is on — **verified, open**

`copyWithPooledBuffer` ([helpers.go](../../internal/proxy/handlers/object/helpers.go)) uses
`io.CopyBuffer` with a pooled 128 KiB buffer, which ticket 010 introduced deliberately.
`io.copyBuffer` checks `dst.(io.ReaderFrom)` **first** and, when it matches, calls
`dst.ReadFrom(src)` and ignores the supplied buffer entirely.

`monitoring.responseWriter` ([middleware.go](../../internal/monitoring/middleware.go))
embeds `http.ResponseWriter` and overrides only `WriteHeader`. It therefore *hides*
`ReadFrom`. And `router.Use(monitoring.HTTPMiddleware)` is applied to the whole router when
monitoring is enabled ([router.go](../../internal/proxy/router.go)).

The result is backwards:

| `monitoring.enabled` | `dst` | pooled 128 KiB buffer |
|---|---|---|
| false | `*http.response` (a `ReaderFrom`) | **ignored** |
| true | `*responseWriter` (hides it) | used |

A deliberate performance optimisation is switched on and off by a monitoring flag, and it
is *off* in the configuration that has one less wrapper. Worth re-checking which
configuration the ticket 010 measurements were taken under.

The same wrapper also drops `http.Flusher`, `http.Hijacker` and `Unwrap()`, so
`http.NewResponseController` does not work on a streaming proxy while monitoring is on.
Fix is small and local: add `Unwrap`, `Flush`, `Hijack` and `ReadFrom` passthroughs.

### P-3 The two headline HTTP metrics are never exported — **reported, open**

`RequestsTotal` and `RequestDuration` are registered into a private
`prometheus.NewRegistry()`, while `/metrics` serves `promhttp.Handler()`, which gathers
`prometheus.DefaultGatherer`. Nothing ever gathers the private registry, so request rate
and request latency — the two metrics the middleware exists to produce — are invisible to
Prometheus, and the Kubernetes and Helm labels attached through that same wrapper appear on
no exported metric. Not a runtime cost, but it means there is currently no production
latency signal to detect P-1 or P-2 with.

---

## S3 surface

These belong with [ticket 022](022-s3-surface-fidelity.md), which owns the "silent 200"
class. They are recorded here because they were found here; **022 is where they get
fixed**, and none of them duplicates an existing 022 item.

### X-1 Conditional read headers are dropped — **verified, open**

`handleGetObject` forwards only `If-Match` and `If-None-Match`
([operations.go](../../internal/proxy/handlers/object/operations.go)). It drops
`If-Modified-Since` and `If-Unmodified-Since`, so a conditional GET that AWS answers with
`304 Not Modified` returns `200` and the whole body — fetched from the backend, decrypted,
and transferred.

`handleHeadObject` forwards **no** conditional header at all, so even `If-None-Match` is
ignored on HEAD, where GET honours it. The two verbs disagree about the same request.

This is 022's defect class exactly, and it is distinct from 022 item 1, which is about
request headers dropped on **PUT**.

### X-2 An error can be answered behind HTTP 200 — **reported, open**

`MapError` is reported to be able to answer an error with a 2xx or 3xx status, so the
client receives an S3 `<Error>` document under a success status, and `WriteXML` commits the
200 before marshalling can fail, which can leave a truncated XML document behind a success
status. Also reported: bucket handlers marshal raw AWS SDK output structs through
`WriteXML`, producing XML no S3 client can parse. All three are in
[internal/proxy/response](../../internal/proxy/response) and all three are S3-conformance
issues rather than internal ones. Not independently verified.

---

## Correctness, smaller

**Verified:**

- `ComputeCiphertextSize` returns `-1` for the empty algorithm while `ComputePlaintextSize`
  accepts it. `putObjectDirect` sends `ComputeCiphertextSize` as `Content-Length` while the
  body comes from the encryptor, so a `-1` would reach the SDK as a negative length. The
  arithmetic itself is correct and is now pinned against the real encryptors for every
  algorithm and eleven payload sizes in
  [ciphertext_size_invariant_test.go](../../pkg/encryption/ciphertext_size_invariant_test.go).
- `GetSecurityMetrics` and `ResetSecurityMetrics` have no callers anywhere.

**Reported, not verified** — leads for whoever works the owning ticket:

- `internal/license`: `Stop()` is reported to deadlock when runtime monitoring was never
  started, hanging every unlicensed shutdown; and a license with no `exp` claim is reported
  to `os.Exit(1)` the proxy after 60 minutes. Both are startup and shutdown paths that a
  test can pin cheaply, and the second one would be a very unpleasant surprise in
  production.
- `internal/config`: legacy migration of `region`, `use_tls` and `skip_ssl_verification` is
  reported to be dead code that silently drops the values.
- `keyencryption`: `EncryptDEK`'s `keyID` return is discarded by every production caller,
  and `DecryptDataStream` passes the KEK its *own* fingerprint as the key id, which makes
  the identity check vacuous.

---

## Re-scoped: claims that did not survive checking

Recorded because it is the reason the rest of the *reported* items carry a caveat.

**"Tink `loadKEKHandle` ignores its KMS URI and mints a fresh random keyset on every call,
so data is unrecoverable after a restart."** The code does exactly that —
`loadKEKHandle(_ string, _ string)` discards both parameters and calls
`keyset.NewHandle(aead.AES256GCMKeyTemplate())`
([tink.go](../../pkg/encryption/keyencryption/tink.go)). But the severity is wrong, because
**the provider cannot be configured**: `validateProvider` refuses `type: "tink"` with
*"tink encryption is not yet implemented with the new architecture"*
([config.go](../../internal/config/config.go)), and there is no `config/tink-example.yaml`.
It is dead code, not a data-loss path.

It should still go: it is unreachable code that reads like a working KMS integration, and
`CLAUDE.md` still advertises Tink as *"Google Tink with KMS integration (production,
cloud-native)"*, which is the documentation describing a provider that refuses to start.
Deleting the provider and the doc line fits the repository rule about not keeping
unnecessary code. That is a decision for the owner, so it is listed and not done.

---

## Ownership: which ticket actually fixes what

Nothing here opens a competing ticket. The mapping:

| Finding | Owner |
|---|---|
| C-1, C-2, I-1, I-2 | **Closed on this branch**, no further work |
| S-1 (fingerprint half), S-2 | [013](013-storage-format-v2.md) — it is already changing the fingerprint (H-8) and the format |
| S-1 (passphrase half) | [013](013-storage-format-v2.md), **new**: no existing ticket covers the raw-string KEK fallback |
| S-4, S-6 | [015](015-configuration-hygiene.md), the "knobs no code reads" family |
| S-3 | **Needs a decision.** No ticket owns the monitoring port today |
| P-1 | [013](013-storage-format-v2.md), which rewrites that path — but it must be measured after |
| P-2, P-3 | [012](012-performance-audit-round2.md), the performance audit |
| X-1, X-2 | [022](022-s3-surface-fidelity.md), the silent-200 ticket |
| S-5 | [013](013-storage-format-v2.md) designs the fix; the interim exposure needs a line in `SECURITY_ARCHITECTURE.md` |
| Tink removal | **Needs a decision** from the repository owner |

## Success criteria

1. Repository statement coverage above 90 %, unit tests only, with the mock code out of the
   denominator. Wave 1 reached 77.8 %; the handler and orchestration waves carry the rest.
2. Every item above is either fixed, assigned to the ticket named in the table, or
   explicitly declined by the owner.
3. No test in this round depends on `config/license.jwt`, which expires 2026-10-05 per
   [ticket 020](020-dev-license-expiry.md). Held: the license tests mint their own keys.
4. `golangci-lint run` reports 0 issues and the suites pass under `-race`.
