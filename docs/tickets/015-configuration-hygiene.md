# Ticket 015: Configuration hygiene: dead knobs out, real controls in

## Status (2026-09-10, re-verified at `6eea6c3`)

**Open, unchanged in substance.** The dead-code round of 2026-09-10 closed the
deletion half (items 1, 3, 7, 8 deletion part, 12, 13). What is left is the half
that *adds* something — three decisions ADR 0013 records as specified-and-not-built,
one prefix-shape change, the unknown-key refusal, plus the test, doc and
verification work that hangs off them.

The two changes that landed since — the listing rewrite (ADR 0010, `d696763`) and
the exit provider (ADR 0025, `0ccface`, `6eea6c3`) — closed **nothing** here and
made **nothing** obsolete. The listing rewrite adds no configuration key at all
(the bucket handler reads exactly one, `h.config.S3Backend.Region`,
[operations.go:135](../../internal/proxy/handlers/bucket/operations.go#L135)). The
exit provider is a rename plus a semantic change this ticket has to follow through
its own text: `type: "none"` is now refused by name
([config.go:575-579](../../internal/config/config.go#L575-L579)), `type: "exit"` is
accepted ([config.go:572](../../internal/config/config.go#L572),
`isValidProviderType` [config.go:760-762](../../internal/config/config.go#L760-L762)),
and the license gate admits `exit` alone without a licence
([validator.go:152-165](../../internal/license/validator.go#L152-L165)). Items 5, 6
and the manual probe are rewritten below in that vocabulary; item 6's *premise*
also changed and is corrected there — under the exit provider two of the three
write paths now hand the SDK a seekable `bytes.Reader`.

Open: **2** (D3, clock skew on both auth forms), **4** (D6, pre-signed ceiling),
**5**/**6** (D5, plain-HTTP backend refusal and warning), **8b** (the one key
item 4 adds to the examples), **9** (`testRateLimiting`), **10** (docs for
2/4/5/6/14), **11** (verification), **14** (prefix shape), **15** (D11, unknown key
refuses the start), and the **manual probe**.

Item 15 was re-verified as *not built*: `Load()` still calls
`viper.Unmarshal(&cfg)` with no options
([config.go:177](../../internal/config/config.go#L177), the only `viper.Unmarshal`
in the tree) and `github.com/go-viper/mapstructure/v2` is still indirect
([go.mod:39](../../go.mod#L39)).

The decisions behind every item live in
[ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) and
[ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md); the standing
gap is `SECURITY_ARCHITECTURE.md` §8, H-10. This ticket is the work list, nothing
else. Every anchor below was read in the tree at `6eea6c3`.

---

## What closed, and what closed it

| Item | Closed by | Verified now |
|---|---|---|
| **1** — delete `SecurityMetrics`, the failed-attempt map, `getClientIP`, the brute-force branch | dead-code round 2026-09-10 | `grep -rn SecurityMetrics internal/ cmd/ pkg/` is empty. `logSecurityEvent` ([s3auth_robust.go:409-419](../../internal/proxy/middleware/s3auth_robust.go#L409-L419)) logs `remote_addr` and `x_forwarded_for` as two raw fields, exactly as ADR 0013 D2 specifies. The three remaining `SecurityMetrics` hits are the Prometheus subtest name in [auth_test.go:143-144, 430](../../test/integration/authentication/auth_test.go#L143), which is what the success criterion always allowed |
| **3** — delete the six dead `s3_security` keys, `GetS3SecurityConfig`, plus `streaming_buffer_size` and `enable_adaptive_buffering` | same | `S3SecurityConfig` ([config.go:64-68](../../internal/config/config.go#L64-L68)) carries `MaxClockSkewSeconds` and nothing else; `validateS3Security` ([config.go:717-729](../../internal/config/config.go#L717-L729)) checks only that one. `OptimizationsConfig` ([config.go:70-94](../../internal/config/config.go#L70-L94)) has no buffer or threshold field. `GetStreamingBufferSize`, `GetStreamingThreshold`, `GetS3SecurityConfig`, `GetProviderByAlias`, `GetProviderConfig`, `ValidateS3ClientCredentials`, `IsS3ClientAuthEnabled` all have zero hits |
| **7** — delete `use_tls` from both structs, both defaults, the migration and the `server.go` fallback; rewrite the misleading comment | same | `grep -rn "use_tls\|UseTLS" internal/ cmd/ pkg/ config/ deploy/ test/` is empty. `migrateLegacyConfig` is gone with the whole legacy block. `backendClientOptions` ([server.go:130-171](../../internal/proxy/server.go#L130-L171)) reads `TargetEndpoint` and `InsecureSkipVerify` only; the transport is `o.BaseEndpoint` at [server.go:153](../../internal/proxy/server.go#L153). `SECURITY_ARCHITECTURE.md` §6.6 states it |
| **8**, deletion half — strip the dead keys from every config surface | same | Nothing left in `config/*.yaml`, `deploy/helm/…/values-production.yaml` or `test/e2e/velero/values-proxy.yaml`, the four-line D-5 comment in the latter included. There are **four** example configs: `config/rsa-example.yaml` went with the `rsa` provider (`2fa4b9c`), and `config/none-example.yaml` is now `config/exit-example.yaml` (`0ccface`). `config/multi-example.yaml` also lost a top-level `streaming.segment_size` block no code ever read |
| **12** — pprof on its own loopback listener | 2026-09-07 | `monitoring.pprof_bind_address` with `requireLoopbackAddress` ([config.go:328-357](../../internal/config/config.go#L328-L357)); ADR 0013 D8 |
| **13** — validate `metadata_key_prefix` at startup | 2026-09-07 | `metadataKeyPrefixPattern` = `^[a-z0-9-]+$` ([config.go:490](../../internal/config/config.go#L490)), checked first in `validateEncryption` ([config.go:501-508](../../internal/config/config.go#L501-L508)). Item **14** below still changes the pattern |
| **13a** — delete the dead `MetadataManager.ValidateConfiguration` whose "empty is valid" comment contradicted the live rule | dead-code round 2026-09-10 | Zero hits for `ValidateConfiguration` outside a test *name* in [manager_test.go:183](../../internal/orchestration/manager_test.go#L183) |

Three premises later changes removed, so nobody re-derives them:

- **`isNoneProviderData` is gone** with `internal/orchestration/singlepart.go`. The
  empty-prefix shredder mechanism recorded under item 13 is history now; the reason
  the prefix is refused at startup stands (ADR 0013 D7, ADR 0009).
- **`TestIntegrityVerificationWithDefaults` is gone** with
  `internal/config/integrity_verification_test.go`. Item 5's abstention rule no
  longer has that test to keep green — the test it must keep green is
  `TestLoad_ValidExitConfig` ([config_test.go:11-51](../../internal/config/config_test.go#L11-L51)),
  which loads `s3_backend.target_endpoint: "http://localhost:9000"` with an `exit`
  provider, i.e. exactly item 6's warning case, not item 5's refusal case.
- **The pass-through provider is no longer called `none`.** Every occurrence of the
  word in this ticket used to mean the provider; where the work below says `exit` it
  means the type spelled `exit` in configuration, and a file that still says `none`
  no longer starts at all.

---

## Work breakdown

Ordered so each item compiles and tests green on its own.

- [x] ~~**1. Delete `SecurityMetrics`.**~~ Closed by the dead-code round, 2026-09-10.
- [x] ~~**2. ADR 0013 D3 — honour `max_clock_skew_seconds` on the header-signed path.**~~
      **Done 2026-09-11.** `validateTimestamp` calls `s.maxClockSkewSeconds()`, and
      the second comparison beside it is deleted: it tested the same quantity
      without the absolute value and could never be reached. Unit tests drive a
      request 400 s old through a 900 s window (accepted), a 300 s window
      (refused) and a Config with no value (falls back to 900).
      **Found and decided while doing it, not in the ticket:** `max_clock_skew_seconds: 0`
      used to be read silently as 900 on *both* paths — the value an operator
      picks to mean "no tolerance" quietly widened the window to the maximum. It
      is now refused at startup. ADR 0017 D8 forbids the silent fixup, and at
      second granularity there is no useful zero.
- [x] ~~**4. ADR 0013 D6 / ADR 0014 D5 — `s3_security.max_presign_expiry_seconds`.**~~
      **Done 2026-09-11**, default 3600, hard cap 604800, refused at 0. The
      middleware carries `defaultPresignExpirySeconds` and
      `presignExpiryHardCapSeconds` and clamps in `maxPresignExpirySeconds()`, so
      a Config built in code — every middleware test does that — is bounded too.
      Both test sites that used the disappearing identifier were repointed at the
      new default.
- [x] ~~**5. ADR 0013 D5 — refuse a plain-HTTP backend under an encrypting provider.**~~
      **Done 2026-09-11.** `backendUsesTLS` plus `validateBackendTransport`, called
      from `validate()` after the encryption block so `GetActiveProvider()` can be
      trusted, abstaining when no provider resolves. A scheme-less endpoint and an
      unknown scheme are refused with it (D4's second half). Seven unit cases:
      https x encrypting, http x encrypting, http x exit, https x exit,
      scheme-less, an unknown scheme, and no provider.
- [x] ~~**6. ADR 0013 D5, the warning half.**~~ **Done 2026-09-11.** The
      hand-rolled scan over the providers is one `cfg.GetActiveProvider()` call
      and emits both warnings. The plain-HTTP one says what actually travels in
      the clear under the exit provider — the object bytes as well as the
      credentials, bucket names and keys — and drops the sentence about an upload
      failing: an encrypting provider can no longer reach a plain-HTTP backend at
      all (item 5), so the seekability caveat has no case left to describe there.
      **The manual probe this item asked for is therefore moot** for the
      encrypting paths, and under `exit` no path seals anything, so there is no
      unseekable body on any of the three.
- [x] ~~**9. Delete `testRateLimiting`.**~~ **Done 2026-09-11**, with its call
      site. It sent ten `/health` requests and asserted that at least one returned
      200; it would have passed against an empty binary. `testSecurityMetrics`
      stays: it curls `/metrics`, which is Prometheus and unrelated.
- [x] ~~**10. Docs for items 2, 4, 5, 6 and 14.**~~ **Done 2026-09-11.**
      `README.md`: the `s3_security` block carries both keys with the rule that
      neither accepts 0; the `s3_backend` block states the scheme requirement and
      the plain-HTTP refusal instead of the inverse it used to carry; the
      pre-signed section leads with the one-hour default and names the seven-day
      maximum as the ceiling rather than the rule; and the upgrade notes carry the
      clock-skew change as the one item here that can break a healthy deployment.
      `SECURITY_ARCHITECTURE.md`: §6.3 rewritten around one window governing both
      forms, and H-10 closed with the three rows recording what each change does
      to an existing configuration. `CLAUDE.md`'s configuration reference carries
      the new keys and the note that it is now the authoritative list, because a
      key missing from it refuses the start.
- [ ] **11. Full verification pass** per [Success criteria](#success-criteria).
- [x] ~~**12. pprof on its own loopback listener.**~~ Done 2026-09-07 (ADR 0013 D8).
- [x] ~~**13. Validate `metadata_key_prefix` at startup.**~~ Done 2026-09-07; the dead
      `MetadataManager.ValidateConfiguration` that contradicted the live rule went
      with the dead-code round, 2026-09-10.
- [x] ~~**14. ADR 0009 D2 — prefix shape.**~~ **Done 2026-09-11.**
      `^[a-z0-9][a-z0-9-]{2,}-$`, with an error that states the three rules rather
      than only printing the pattern. Five new cases beside the existing ones:
      no trailing dash, below four characters, a leading dash, the shortest
      accepted form `abc-`, and a multi-segment `x-s3ep-dev-`. No shipped YAML
      changed. **ADR 0013 D7 restated the old pattern and had drifted from
      ADR 0009 D2** — that was the open question on this item; D7 now names
      ADR 0009 as the owner instead of repeating the rule, so the two cannot
      diverge again.
- [x] ~~**15. ADR 0013 D11 — an unknown configuration key refuses the start.**~~
      **Done 2026-09-11, and last on purpose**, so every key this release adds was
      in place before it. `viper.Unmarshal` takes a `DecoderConfigOption` setting
      `ErrorUnused`; the library's message names the offending keys and is not
      swallowed, with a line pointing at the release notes. `go mod tidy` promoted
      `github.com/go-viper/mapstructure/v2` to a direct dependency.
      Verified rather than assumed: a provider block still swallows its own
      parameters (the `,remain` boundary, asserted with the `exit` provider so the
      licence gate is not in the way), and **every shipped example configuration is
      decoded in a test**, so a file this repository hands out cannot be one that
      refuses to start. It caught two stale test fixtures carrying the pre-5.0.0
      top-level `encryption_type` and `aes_key`.
      Also checked by hand: all three chart values files that render today produce
      a config that decodes clean. `values-monitoring.yaml` and
      `values-development.yaml` do not render at all — that is
      [016](016-helm-chart-fixes.md) items 4 and 5, unchanged by this.
## Success criteria

**Unit tests** — `make test-unit` green, with these added:

- `internal/config`: `http://` + an encrypting provider fails with a message naming
  `target_endpoint`; `http://` + `exit` loads; `https://` + encrypting loads; a
  scheme-less endpoint fails; no provider configured + `http://` loads (item 5).
- `internal/config`: `max_presign_expiry_seconds` of 0 and of 604801 rejected; 3600
  the default when unset (item 4).
- `internal/config`: the unknown-key set from item 15, including the provider
  catch-all case and all four shipped examples.
- `internal/config`: the prefix shapes from item 14.
- `internal/proxy/middleware`: an SDK-signed URL with `X-Amz-Expires=600` accepted
  under the default (the Velero case); the same URL rejected under
  `max_presign_expiry_seconds: 60`; a config above the hard cap clamped, not
  honoured (item 4).
- `internal/proxy/middleware`: a header-signed request 400 s old rejected under
  `max_clock_skew_seconds: 300` and accepted under 900 (item 2).

**The chart still renders and its two live values files still load:**

```bash
make helm-test
helm template t deploy/helm/s3-encryption-proxy -f deploy/helm/s3-encryption-proxy/values-production.yaml
```

**Lint** — `make lint` green. An import orphaned by an edit is a compile error, not
a lint finding, so `go build ./...` is what catches it.

**Integration** — both demo proxies already point at `https://minio:9000`
([aes-example.yaml:15](../../config/aes-example.yaml#L15),
[aes-tls-example.yaml:24](../../config/aes-tls-example.yaml#L24)), so item 5 changes
nothing for them; item 2 does tighten the demo's header-auth window to the 300 s
those files configure.

```bash
./start-demo.sh
make test-integration        # plain-HTTP proxy listener
make test-integration-tls    # TLS proxy listener, the SDK's default framing
```

Both green with no test skipped or removed other than `testRateLimiting`.

**Performance** — `make test-integration-performance` on an idle machine, three
runs, against the numbers in [012](012-performance-audit-round2.md). Expected: no
change. The only hot-path edit is one function call replacing a constant in the
clock-skew check. Movement beyond run-to-run noise is a finding, reported before the
ticket closes.

**Velero e2e** — `make e2e-up && make test-e2e-velero`, all 13 scenarios green. V10
is the real assertion for item 4: it exercises `backup logs`, `restore logs` and
`describe --details`, all pre-signed, so it proves the 3600 s default does not break
Velero's 600 s URLs. The suite has not been run since the segment format landed, so
a failure there is not necessarily this ticket's.

**One manual probe** (item 6, `exit` provider). Start the proxy with the `exit`
provider against `http://minio:9000` and PUT an object on each write path — one
at or below `optimizations.streaming_segment_size` (12 MiB # default,
[config.go:244](../../internal/config/config.go#L244)) and one above it, since those
are the two paths [operations.go:231-243](../../internal/proxy/handlers/object/operations.go#L231-L243)
chooses between. Add a client-driven multipart upload for the third path. Per the
readings under item 6, only the first is expected to fail; record the result here
either way. If the small one fails with `failed to seek body to start`, item 6's
warning becomes a refusal and ADR 0013 D5 loses its exception; record that in the
ADR rather than here.

---

## Open questions

- **The `exit`-provider exception may be worthless — for one path, not three.** D5
  warns instead of refusing under pass-through on the assumption that such a body is
  seekable. That assumption now holds for the two multipart paths and fails for the
  single-request one (readings under item 6). The probe settles it. It does not
  block the ticket: the refusal for encrypting providers is the security-relevant
  half and is unaffected.
- **`X-Forwarded-For` stays in the logs** ([s3auth_robust.go:409-419](../../internal/proxy/middleware/s3auth_robust.go#L409-L419)).
  Accepted: it is a log field, not a key or a decision input. `SECURITY_ARCHITECTURE.md`
  §4.2 ([:443](../../SECURITY_ARCHITECTURE.md#L443)) already says so and should keep
  saying it, so the next reader does not mistake it for a trusted client identity.
- **Nothing prevents the next dead knob.** ErrorUnused (item 15) does not help: a
  field that is declared and never read passes it, and so does one whose reader
  points at the wrong object — the 2026-09-10 amendment to ADR 0013 D1 is that
  sharper failure caught in the act. The guard is review: a new key lands with the
  code that reads it and a test that proves the effect.
- **`streaming_segment_size` accepts a value the segment chain cannot use, and no
  decision covers it yet.** `validateOptimizations`
  ([config.go:634-663](../../internal/config/config.go#L634-L663)) checks only the
  5 MiB–5 GiB range. The proxy's own multipart producer uses that value as the part
  size ([operations.go:620](../../internal/proxy/handlers/object/operations.go#L620))
  and `SegmentedUpload.SealPart` refuses a non-final part whose length is not a
  multiple of `dataencryption.SegmentSize` = 65536
  ([segmented.go:121-126](../../internal/orchestration/segmented.go#L121-L126),
  [segmented_gcm.go:25](../../pkg/encryption/dataencryption/segmented_gcm.go#L25)),
  so e.g. `10000000` passes startup and fails every upload above one part with
  `ErrPartNotAligned`. ADR 0013 D7 is the principle ("a configuration that cannot
  work refuses to start") but does not name this case, and [023](023-major-v5.md)
  already announces the check as shipped ([:760-762](023-major-v5.md#L760)). Decide
  it in an ADR before writing either the check or the release note.
