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
- [ ] **2. ADR 0013 D3 — honour `max_clock_skew_seconds` on the header-signed path.**
      `validateTimestamp` compares against the package constant
      `MaxClockSkewSeconds = 900` ([s3auth_robust.go:40](../../internal/proxy/middleware/s3auth_robust.go#L40))
      at [:234](../../internal/proxy/middleware/s3auth_robust.go#L234), while the
      pre-signed path reads the configured value through `maxClockSkewSeconds()`
      ([s3auth_presigned.go:160-167](../../internal/proxy/middleware/s3auth_presigned.go#L160-L167)).
      All four example configs and both deployment values files set
      `max_clock_skew_seconds: 300`, so header auth tolerates a replay window three
      times wider than the configuration says. Call `s.maxClockSkewSeconds()` — it
      already falls back to the constant — and delete the second, unreachable
      comparison at [:238-241](../../internal/proxy/middleware/s3auth_robust.go#L238-L241):
      the absolute-difference test above it has already returned. Unit tests: a
      request 400 s old is rejected under 300 and accepted under 900. Note
      [s3auth_coverage_test.go:310](../../internal/proxy/middleware/s3auth_coverage_test.go#L310)
      already drives `validateTimestamp` through `MwauthService(t, skew)`, so the
      configured value has a seam.
- [x] ~~**3. Delete the six dead config keys.**~~ Closed by the dead-code round, 2026-09-10.
- [ ] **4. ADR 0013 D6 / ADR 0014 D5 — `s3_security.max_presign_expiry_seconds`.**
      Default 3600, hard cap 604800.
      - `S3SecurityConfig` ([config.go:64-68](../../internal/config/config.go#L64-L68))
        gains the field; `setDefaults` gains
        `viper.SetDefault("s3_security.max_presign_expiry_seconds", 3600)` beside
        [config.go:256](../../internal/config/config.go#L256);
      - `validateS3Security` ([config.go:717-729](../../internal/config/config.go#L717-L729))
        rejects `<= 0` and `> 604800`, naming the field and the rule;
      - in the middleware, replace the constant
        ([s3auth_presigned.go:24-25](../../internal/proxy/middleware/s3auth_presigned.go#L24-L25))
        with `defaultPresignExpirySeconds = 3600` and
        `presignExpiryHardCapSeconds = 7 * 24 * 60 * 60`, and add a
        `maxPresignExpirySeconds()` method mirroring `maxClockSkewSeconds()`
        ([:160-167](../../internal/proxy/middleware/s3auth_presigned.go#L160-L167))
        including its `s.config != nil` guard. It clamps to the hard cap in both
        branches: a `Config` built in code, as the middleware tests do, never passes
        through `validate()`. `validatePresignExpiry`
        ([:142-143](../../internal/proxy/middleware/s3auth_presigned.go#L142-L143))
        calls it;
      - update the doc comment at
        [s3auth_presigned.go:48](../../internal/proxy/middleware/s3auth_presigned.go#L48),
        which still states the 7-day bound as the rule.
      Two test sites use the disappearing identifier and both need the new default:
      [s3auth_presigned_test.go:198](../../internal/proxy/middleware/s3auth_presigned_test.go#L198)
      (`oversized_expires_is_rejected`) and
      [s3auth_coverage_test.go:605](../../internal/proxy/middleware/s3auth_coverage_test.go#L605).
      Why 3600 and the Velero measurement behind it: ADR 0014 D5.
- [ ] **5. ADR 0013 D5 — refuse a plain-HTTP backend under an encrypting provider.**
      A `backendUsesTLS(endpoint string) (bool, error)` helper — `https` true,
      `http` false, anything else an error, so a scheme-less `target_endpoint` is
      refused too (that is D4's second half; today the string reaches
      `o.BaseEndpoint` verbatim at [server.go:153](../../internal/proxy/server.go#L153)
      and what the SDK does with it is undefined) — plus a
      `validateBackendTransport(cfg)` called from `validate()`
      ([config.go:261-305](../../internal/config/config.go#L261-L305)) *after*
      `validateLicenseAndEncryption` ([:285](../../internal/config/config.go#L285)),
      so `GetActiveProvider()` ([config.go:732](../../internal/config/config.go#L732))
      can be trusted. When no provider is configured the check abstains: the
      configuration has other problems and this one has nothing to say about them.
      The refusal in config validation rather than in `main`, because it is a
      configuration inconsistency, it fires before a listener or an S3 client
      exists, and every entry point that loads config gets it. It surfaces through
      [main.go:74-77](../../cmd/s3-encryption-proxy/main.go#L74-L77) as a non-zero
      exit — a crash loop with a readable reason instead of a pod that is Ready and
      fails every upload. One `fmt.Errorf`, naming the symptom:
      ```
      s3_backend.target_endpoint is plain HTTP (%q) while the active encryption
      provider %q (type %q) encrypts: aws-sdk-go-v2 only sends an unseekable
      streaming body with UNSIGNED-PAYLOAD over TLS, so every upload fails with
      "failed to seek body to start". Use an https:// endpoint, or the "exit"
      provider if a pass-through proxy is what you want.
      ```
      Unit tests: http × encrypting fails naming `target_endpoint`; http × `exit`
      loads; https × encrypting loads; scheme-less fails; no provider + http loads.
- [ ] **6. ADR 0013 D5, the warning half.** The provider loop at
      [main.go:136-150](../../cmd/s3-encryption-proxy/main.go#L136-L150) already
      exists and already emits one warning — "Exit provider active: new objects are
      stored unencrypted" — from a hand-rolled scan over `cfg.Encryption.Providers`.
      What is missing is the plain-HTTP half. Rewrite that loop around one
      `cfg.GetActiveProvider()` call and emit both warnings from it. It belongs in
      `main` because it needs the logger, configured immediately above at
      [main.go:116-134](../../cmd/s3-encryption-proxy/main.go#L116-L134).
      ```
      ⚠️  Plain-HTTP S3 backend with the 'exit' provider: credentials, bucket names
      and object keys travel in clear to the backend, and an upload may still fail,
      because aws-sdk-go-v2 needs TLS for an unseekable body.
      ```
      **The seekability premise changed with the exit provider and is now split.**
      This ticket previously recorded that nothing on either write path is seekable.
      Re-read at `6eea6c3`, that holds for one path out of three:
      - single request — `putObjectSegmented` hands `h.requestParser.StreamingReader(r)`
        straight to `PutObject`
        ([operations.go:251, 259-262](../../internal/proxy/handlers/object/operations.go#L251)),
        and that reader is `r.Body` or the aws-chunked stream wrapper
        ([parser.go:108-117](../../internal/proxy/request/parser.go#L108-L117)) —
        **not seekable**;
      - the proxy's own multipart producer — under pass-through the part body is
        `bytes.NewReader(buffer[:n])`
        ([operations.go:816-818](../../internal/proxy/handlers/object/operations.go#L816-L818)) —
        **seekable**;
      - client-driven multipart — `uploadPassThroughPart` sends
        `bytes.NewReader(plaintext)`
        ([upload.go:239-246](../../internal/proxy/handlers/multipart/upload.go#L239-L246)) —
        **seekable**.
      So the probe below decides one path, not all three, and the expected failure
      is an object *at or below* one segment size, which is the opposite of what
      ADR 0013's residual-risk note assumes ("one manual upload larger than one
      segment settles it"). Run both sizes. If the small one fails, item 6's warning
      becomes a refusal for the exit provider too — a one-line change — and the ADR's
      note is what gets corrected, not this ticket.
- [x] ~~**7. Delete `use_tls`.**~~ Closed by the dead-code round, 2026-09-10.
- [x] ~~**8. Config surface — remove the dead keys.**~~ Closed by the dead-code round, 2026-09-10.
- [ ] **8b. Config surface — add the one key item 4 introduces.** Put
      `max_presign_expiry_seconds: 3600` with a one-line comment into the four
      `s3_security` blocks that exist:
      [aes-example.yaml:37-40](../../config/aes-example.yaml#L37),
      [aes-tls-example.yaml:46-49](../../config/aes-tls-example.yaml#L46),
      [exit-example.yaml:46-49](../../config/exit-example.yaml#L46),
      [multi-example.yaml:32-35](../../config/multi-example.yaml#L32), and into
      [values-production.yaml:156-157](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L156-L157)
      and [values-proxy.yaml:127-128](../../test/e2e/velero/values-proxy.yaml#L127-L128).
      Do it in the same change as item 4, never before it — see item 15.
- [ ] **9. Delete `testRateLimiting`** ([auth_test.go:389-428](../../test/integration/authentication/auth_test.go#L389-L428))
      and its call site ([:139-141](../../test/integration/authentication/auth_test.go#L139-L141)).
      It sends ten `/health` requests 100 ms apart and asserts at least one returns
      200; it would pass against an empty binary. This is not a skipped integration
      test — it is a test of a feature that does not exist and never did (ADR 0014).
      Leave `testSecurityMetrics` ([:430](../../test/integration/authentication/auth_test.go#L430)):
      it curls `/metrics`, which is Prometheus and unrelated.
- [ ] **10. Docs for items 2, 4, 5, 6 and 14.** The dead-key documentation is
      already gone and honest — `README.md` §Configuration has no dead keys, the
      "No rate limiting" bullet ([README.md:1045](../../README.md#L1045)) cites
      ADR 0014, and `SECURITY_ARCHITECTURE.md` H-7 is closed. What the open items
      still owe:
      - [README.md:331-334](../../README.md#L331-L334): the `s3_security` block —
        drop the "Pre-signed URLs only; the Authorization-header path uses a fixed
        900 seconds" caveat when item 2 lands, add `max_presign_expiry_seconds`
        with item 4;
      - [README.md:833-841](../../README.md#L833-L841), "Pre-signed URLs": it still
        states the AWS 7-day maximum as the rule. Item 4 replaces it with the knob,
        the 3600 s default and the documented deviation from the S3 maximum;
      - the `s3_backend` block [README.md:466-468](../../README.md#L466-L468) carries
        the honest inverse today — "Nothing refuses an http:// backend, not even
        under an encrypting provider". Items 5 and 6 replace it with the rule: an
        `https://` `target_endpoint` is required unless the provider is `exit`, and a
        scheme-less endpoint is refused;
      - item 2 breaks a client whose clock is between 300 s and 900 s off. Say so
        in the same change — it is the one item here that can break a healthy
        deployment;
      - `SECURITY_ARCHITECTURE.md` §6.3 ([:555](../../SECURITY_ARCHITECTURE.md#L555))
        and the H-10 block ([:881-903](../../SECURITY_ARCHITECTURE.md#L881-L903),
        checklist at [:899-903](../../SECURITY_ARCHITECTURE.md#L899-L903)): tick what
        lands, and close H-10 when all three do. H-10 already speaks of the exit
        provider, so no rename is owed there;
      - mirror both config blocks into `CLAUDE.md`.
      [023](023-major-v5.md) already carries the release-notes lines for items 2, 4,
      5, 14 and 15 (the upgrade row at [:53](023-major-v5.md#L53), "Configuration —
      refuses to start" at [:758-765](023-major-v5.md#L758) and "Configuration — new"
      at [:767-770](023-major-v5.md#L767)); check them against what actually ships
      rather than writing new ones. One of those lines is already ahead of the tree —
      see the last open question.
- [ ] **11. Full verification pass** per [Success criteria](#success-criteria).
- [x] ~~**12. pprof on its own loopback listener.**~~ Done 2026-09-07 (ADR 0013 D8).
- [x] ~~**13. Validate `metadata_key_prefix` at startup.**~~ Done 2026-09-07; the dead
      `MetadataManager.ValidateConfiguration` that contradicted the live rule went
      with the dead-code round, 2026-09-10.
- [ ] **14. ADR 0009 D2 — prefix shape.** Change `metadataKeyPrefixPattern`
      ([config.go:490](../../internal/config/config.go#L490)) from `^[a-z0-9-]+$` to
      `^[a-z0-9][a-z0-9-]{2,}-$`; the error at
      [config.go:505-507](../../internal/config/config.go#L505-L507) names the key and
      states the three rules (lowercase alphanumerics and dashes, starting with one
      of them, at least four characters, ending in `-`). Tests: `s3ep-`, `abc-`,
      `x-s3ep-dev-`, `mycompany-enc-` accepted; `s3`, `s3-`, `-abc-`, `abc`, `S3EP-`
      refused. No shipped YAML changes — the one uncommented `metadata_key_prefix`
      in the tree ([values.yaml:214](../../deploy/helm/s3-encryption-proxy/values.yaml#L214))
      sits inside `providers[0].config`, where the provider catch-all swallows it and
      nothing validates it at all, and its value `x-s3ep-` passes anyway. When
      [016](016-helm-chart-fixes.md) moves that key to the `encryption` block it
      starts being validated; that move stays a no-op here, but the two must not land
      blind to each other.
      What the rule still leaves open, reported rather than widened: no maximum
      length, so an over-long prefix fails at the backend with an opaque S3 error
      instead of at startup. Changing one valid prefix to another still passes
      startup and still makes every stored object unreadable — but loudly now:
      `InvalidObjectState` on every read verb (ADR 0003 D10, ADR 0009).
- [ ] **15. ADR 0013 D11 — an unknown configuration key refuses the start, and the
      refusal names it.** Decided 2026-09-10; it supersedes the last sentence of D10
      and it is why this release can delete twelve keys without turning each one into
      a setting the operator believes is in force. Pairs with the closed items 3 and
      7: their keys are exactly what an operator upgrading from 4.x will trip over.
      Re-verified not built at `6eea6c3`.
      - **The loader.** `Load()` calls `viper.Unmarshal(&cfg)` with no options
        ([config.go:175-197](../../internal/config/config.go#L175-L197)); it is the
        only `viper.Unmarshal` call in the tree. Pass a
        `viper.DecoderConfigOption` — `func(*mapstructure.DecoderConfig)`, viper
        1.21.0 `viper.go:90-92` — that sets `ErrorUnused: true`. Verified in the
        module cache that this reaches unknown *file* keys and not only struct
        fields: `Viper.Unmarshal` (`viper.go:938-952`) decodes `v.getSettings(v.AllKeys())`,
        and `AllKeys` carries whatever the config file contained. The `mapstructure`
        in that signature is `github.com/go-viper/mapstructure/v2`, today an indirect
        dependency ([go.mod:39](../../go.mod#L39)); importing it promotes it to a
        direct one, so `go mod tidy` runs in the same change.
      - **The error text.** mapstructure already names the offending keys —
        `has invalid keys: <sorted keys>`, prefixed by the struct path, at
        `mapstructure@v2.4.0/mapstructure.go:1601-1612`. Do not swallow that in the
        `failed to unmarshal config` wrapper: the operator must read the key name.
        For a key this release removed, point at the release notes in the same
        message; a misspelling gets the same treatment, which is the point.
      - **The catch-all must keep working.** `EncryptionProvider.Config` is
        `mapstructure:",remain"` ([config.go:38](../../internal/config/config.go#L38)),
        and `Description` is declared purely so `description:` is consumed there
        rather than falling into it. Verified in the library: a `remain` field nils
        out the unused-key set *before* the `ErrorUnused` check
        (`mapstructure.go:1596-1598`), so a provider block keeps swallowing its own
        parameters. That is ADR 0013 D11's first boundary — assert it with a test,
        do not assume it. `loadProviderConfigs` ([config.go:360-380](../../internal/config/config.go#L360-L380))
        rebuilds the providers from `viper.Get` by hand afterwards and is unaffected,
        but it must still be exercised: it is the reason a provider typo stays silent
        by design.
      - **Environment variables are out of scope** (D11's second boundary).
        `viper.AutomaticEnv()` with prefix `S3EP` ([config.go:162-163](../../internal/config/config.go#L162-L163))
        contributes nothing to `AllKeys`, so no work is needed — confirm rather
        than assume.
      - **The four shipped examples must pass.** Checked key by key at `6eea6c3`:
        every key in `aes-example.yaml`, `aes-tls-example.yaml`, `exit-example.yaml`
        and `multi-example.yaml` has a matching `mapstructure` tag. That is an
        eyeball comparison, not a run — re-run it as a test after the switch is on.
      - **The rendered chart config must pass too**, and this is where the work is.
        `templates/configmap.yaml` renders `.Values.config` verbatim into
        `config.yaml`, so every values file is a configuration document:
        - [values-production.yaml:137-171](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L137-L171)
          and [values-proxy.yaml:97-148](../../test/e2e/velero/values-proxy.yaml#L97-L148)
          are strings and carry only live keys today — they pass;
        - [values.yaml:187-214](../../deploy/helm/s3-encryption-proxy/values.yaml#L187-L214)
          is a string; its `metadata_key_prefix` sits inside the provider block, so
          the catch-all covers it (see item 14);
        - [values-monitoring.yaml:81-106](../../deploy/helm/s3-encryption-proxy/values-monitoring.yaml#L81-L106)
          carries the **deleted legacy top-level backend keys** (`target_endpoint`,
          `region`, `access_key_id`, `secret_key`), and
          [values-development.yaml:51-70](../../deploy/helm/s3-encryption-proxy/values-development.yaml#L51-L70)
          carries camelCase keys and `type: "aes-gcm"`, which is not a provider type.
          Both are also `config:` **maps** rather than the string the template
          expects. Both already produce a proxy that cannot start; D11 changes the
          failure from "target_endpoint is required" to a named key. Fixing them is
          [016](016-helm-chart-fixes.md)'s, not this item's — but this item must not
          land claiming the chart is clean when two values files are not.
      - **Tests** in `internal/config`: an unknown top-level key is refused and the
        message contains the key; an unknown key nested under `optimizations` and one
        under `s3_security` likewise; a deleted key of this release
        (`encryption.integrity_verification`) is refused by name; an unknown key
        *inside* `providers[].config` still loads; each of the four shipped example
        files loads. `viper.Reset()` between cases, as the existing tests do.

---

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
