# 032 — Open decisions from the documentation audit

The documentation audit of 2026-09-12 read every `.md` file in the repository
claim by claim against the code and applied 453 corrections across 48 files. It
turned up thirteen things that are **not** documentation defects: the document
was right and the tree is wrong, or the tree is right and nobody has decided what
it should be. None of them was fixed in that change, because each is a decision.

This file is the decision list. Every item carries what was verified and where,
the options, and the decision with its reason. **All thirteen were decided with
the owner on 2026-09-12 and 2026-09-13; none of the work is built.** Each item is
closed by doing its work; the file is deleted when the last one is closed
(ADR 0022 D4). Anything durable that comes out of an item — a rule, a rejected
alternative — goes into an ADR before this file goes.

| | Decision | ADR obligation |
|---|---|---|
| D1 | A2 — drop the held part in `RecordStreamedPart`, once the backend confirmed it | — |
| D2 | A — pass the SSE headers through on every object path | ADR 0008: the boundary between a backend-service header and a stored-object one |
| D3 | D — the chart ships no NetworkPolicy; the boundary is the administrator's | new, or a block in ADR 0026 |
| D4 | A — a written `license_file` is binding | — |
| D5 | B — both monitoring flags go; the chart renders configuration | — |
| D6 | A — a configuration file that cannot be read refuses the start | — |
| D7 | B1 — read `kek-algorithm` for diagnostics and dispatch, never as a refusal | ADR 0002: the load-bearing set, and dispatch on the fingerprint |
| D8 | A — delete `SealedPart.Streamed` | — |
| D9 | A — lint the test tree, after measuring the backlog | — |
| D10 | A — the seven stale comments in one commit | — |
| D11 | B — the ticket sweep runs before the merge, tracked in 023 | — |
| D12 | A — give the image an `ENTRYPOINT` | — |
| D13 | A — translate, `vault login`, pin the tag | — |

Everything below was read in the tree at `03d421d`, not inferred.

---

## D1 — A re-sent multipart part can produce an object that never reads

**Severity: data loss with a success response. The most serious item here.**

`SealPart` carries a guard and the comment that argues for it
([segmented_session.go:466-471](../../internal/orchestration/segmented_session.go#L466-L471)):

> A client may send any part number again with different bytes. When the part it
> replaces is the one being held, the held copy is no longer part of this object:
> leaving it would have Complete store those bytes under this number while the
> table describes these, an object that stores cleanly and fails authentication
> on every read.

The streaming path never got that guard.
[`SealStreamingPart`](../../internal/orchestration/segmented_session.go#L551) and
[`RecordStreamedPart`](../../internal/orchestration/segmented_session.go#L577)
take `s.mu`, write `s.parts[partNumber]`, and never look at `s.pending`.

| Step | Where |
|---|---|
| Part N arrives short → held, `pendingNum = N`, budget reserved | [upload.go:139-145](../../internal/proxy/handlers/multipart/upload.go#L139-L145) |
| Part N arrives again, segment-aligned and ≥ 5 MiB → streaming path | [upload.go:128-137](../../internal/proxy/handlers/multipart/upload.go#L128-L137) (`lengthKnown && CanStreamPart`) |
| The streamed part overwrites the table entry; `pending` is untouched | [segmented_session.go:577-588](../../internal/orchestration/segmented_session.go#L577-L588) |
| `Complete` computes the trailer from the table — the **streamed** length and CRC32C | [segmented_session.go:654-657](../../internal/orchestration/segmented_session.go#L654-L657) |
| `Complete` then seals `pending` — the **old short** bytes — at part N's offset and returns it as the final part | [segmented_session.go:659-660](../../internal/orchestration/segmented_session.go#L659-L660) |

The object stores the superseded bytes under a trailer that authenticates the
replacement. Every read answers `403 InvalidObjectState`, and
`CompleteMultipartUpload` answered `200 OK`. `s.reserved` is never given back
either, so the session leaks its claim on the process-wide short-part budget
until it ends — the starvation ticket 031 describes, reachable without intent.

Re-uploading a part is legal S3. A client that retries a part with different
chunking hits this.

**Options**

- **A1 — mirror the guard literally.** In `SealStreamingPart`, after taking
  `s.mu`: if `s.pending != nil && s.pendingNum == partNumber`, call
  `dropPendingLocked()` — the same position `SealPart` uses.
- **A2 — drop it in `RecordStreamedPart`**, once the backend has acknowledged the
  part and its sealed length has been checked. Same few lines, later position.
- **B — refuse the transition.** Answer `400 InvalidRequest` when a currently
  held part number arrives on the streaming path.
- **C — defer** until the next format round.

**Decision (2026-09-12): A2.**

`uploadStreamedPart` has eleven failure exits between `SealStreamingPart` and
`RecordStreamedPart` — the checksum verdict, the backend error, a part the
backend acknowledged without taking in full. The function's closing comment
states the rule they all obey: *"Every failure above returns without touching the
table, so a part stored under this number by an earlier attempt survives a later
one that fails."*

A1 breaks exactly that rule for the case where the earlier attempt was a **held**
part: `pending` would be gone, the streamed upload then fails, and the client has
lost a part it had successfully uploaded. `Complete` would fail with
`ErrPartTableInvalid` — an error rather than a broken object, so still better
than today, but needlessly. A2 makes the replacement atomic: either the new part
stands and the held copy is gone, or nothing moved.

That `SealPart` drops early is not an argument against this. On that path nothing
between the drop and the answer can fail at the backend, so the two entry points
are not symmetric here. A2 follows the principle the code already writes down
rather than the line position.

B trades a correctness defect for a conformance defect: re-sending a part at a
different size is something S3 permits and clients do on retry. C leaves a path
that returns success for an object that can never be read.

**Also in scope for this item:** `dropPendingLocked` gives the short-part budget
back, so A2 closes the reservation leak on the same path.

**Needs a test**: hold a short part, re-send it aligned and ≥ 5 MiB, complete,
read back. No suite covers the transition today.

---

## D2 — The SSE confirmation reaches the client on one write path out of two

**The audit filed this as an ADR 0008 D1 violation. That was wrong**, and the
correction matters more than the item: D1 says *"A backend response object is
never serialised onto the wire as received"*. It forbids handing the backend's
response object through as a whole. Restating one typed value the backend
returned is what `writeGetObjectResponse` already does with `ETag`,
`ContentType` and `Last-Modified`. So
[complete.go:297-302](../../internal/proxy/handlers/multipart/complete.go#L297-L302)
setting `x-amz-server-side-encryption` and
`x-amz-server-side-encryption-aws-kms-key-id` breaks no rule.

It is also an answer to a question the client asked: the proxy **forwards** the
client's SSE request headers to the backend
([storage_headers.go:106,113](../../internal/proxy/handlers/object/storage_headers.go#L106-L113)),
so the response header confirms what the client itself requested. Without this
proxy in the path the client would receive it from S3 directly.

The real defect is the asymmetry:

| Response path | Restates | SSE headers |
|---|---|---|
| `CompleteMultipartUpload` | ETag, version id | **yes** |
| `PutObject` ([operations.go:479-480](../../internal/proxy/handlers/object/operations.go#L479-L480)) | ETag, version id | no |
| `GET` ([operations.go:271-304](../../internal/proxy/handlers/object/operations.go#L271-L304)) | content type, length, ETag, last-modified, accept-ranges, CRC32C, version, entity headers, user metadata | no |
| `HEAD` ([operations.go:598-622](../../internal/proxy/handlers/object/operations.go#L598-L622)) | the same set | no |

A client that sends `x-amz-server-side-encryption: aws:kms` on a single-request
`PUT` has that header forwarded, the backend applies it and answers with it, and
the proxy drops the confirmation. On a multipart upload the same client gets it.

**The rule this settles, and its boundary.** Headers that describe a property of
the backend *service* pass through; headers that describe the **stored** object
belong to the proxy and must be restated, because the stored object is ciphertext
and the client receives plaintext. `Content-Length` is exactly such a header, and
so is a backend `x-amz-checksum-*`: forwarding either would make the response lie
about the bytes the client is getting. A blanket pass-through is therefore wrong;
the distinction has to be made per header.

**Options**

- **A — pass the SSE headers through consistently:** restate them on `PutObject`,
  `GET` and `HEAD` as `CompleteMultipartUpload` already does, and record the
  boundary above in ADR 0008 so the next reader does not re-file this as a D1
  violation — as this audit did.
- **B — record the boundary in ADR 0008 only**, leave the asymmetry.
- **C — general pass-through** of every backend response header the proxy does not
  compute itself, with an explicit deny list for those describing the stored
  object.

**Decision (2026-09-12): A.**

C is the fuller expression of the rule and is probably right in the long run, but
its deny list is a design of its own: every header has to be sorted by whether it
describes the plaintext object or the stored one, and one forgotten entry is a
false statement about customer data. That is its own ticket and needs its own ADR
rule. A is the part that is already decided, and it is small and typed: four
paths, one value the SDK hands over in a struct field. B leaves an inconsistency
that AWS SDKs do read — `PutObject` returns `ServerSideEncryption` in its
response struct and tooling asserts on it.

**ADR obligation**: ADR 0008 gets the boundary sentence in the same change. The
audit misreading D1 is the evidence that the rule as written does not carry it.

## D3 — The chart ships a NetworkPolicy it cannot get right

[values.yaml:192-210](../../deploy/helm/s3-encryption-proxy/values.yaml#L192-L210)
ships `policyTypes: [Ingress, Egress]` with one ingress rule on TCP 8080 and an
egress rule for 443 and 53.

The audit filed this as a default that blocks a port the same chart opens:
`monitoring.bind_address` is `:9090`, so turning the policy on with stock values
makes Prometheus scraping unreachable. True, but it understates the problem.

*(Corrected 2026-09-13: an earlier draft of this item also claimed the chart's
TLS listener on 8443 was cut. It is not. The chart's Service is port 8080 and
`serviceTLS.enabled` only adds `tls.enabled`, `tls.cert_file` and `tls.key_file`
to the rendered configuration — TLS is served on the same port, so the shipped
ingress rule admits it. 8443 is the demo compose container's port and appears in
the chart only inside its own test fixtures. The metrics port is the one the
default actually cuts.)* **`from: []` is allow-from-anywhere**, not a selector,
and so is `to: []`: what ships is a blanket grant wearing the name of a security
control. A chart cannot know the target topology — which namespaces may reach the
proxy, which port the backend listens on — so it cannot write these rules
correctly for anyone.

**Options**

- **A — derive the default ingress** from `monitoring.enabled` and
  `serviceTLS.enabled`.
- **B — document the limitation**, leave the values alone.
- **C — ship `ingress: []`** and force an explicit rule.
- **D — remove the NetworkPolicy from the chart.** The administrator owns it.

**Decision (2026-09-12): D.**

Blanket grants are not worth shipping: neither admitting the whole cluster to the
proxy port nor opening the metrics port to everything that can route to the pod
is a posture this project should hand an operator by default. A and C only argue
about *which* blanket grant; C is the worst of them, because `policyTypes:
[Ingress]` with an empty rule list is deny-all in Kubernetes, so enabling it as
shipped would cut 8080 as well. B leaves the trap armed behind a sentence that
the person flipping the switch is not reading.

This also finishes a decision already taken: 023 records, 2026-09-12, *"No
NetworkPolicy ships — the network boundary is the administrator's"*, for the
monitoring listener. The chart kept shipping the older optional one, so the
repository held both positions at once.

**The work**

| Step | Where |
|---|---|
| Delete the template | [templates/networkpolicy.yaml](../../deploy/helm/s3-encryption-proxy/templates/networkpolicy.yaml) |
| Remove the values block | [values.yaml:192-210](../../deploy/helm/s3-encryption-proxy/values.yaml#L192-L210), and the mention at [values.yaml:6](../../deploy/helm/s3-encryption-proxy/values.yaml#L6) |
| Remove the overrides | [values-development.yaml:27](../../deploy/helm/s3-encryption-proxy/values-development.yaml#L27), [values-production.yaml:54](../../deploy/helm/s3-encryption-proxy/values-production.yaml#L54) |
| Chart README: the feature list, the profile comparison, four values rows, the production checklist item | [README.md:8,115,260-263,547](../../deploy/helm/s3-encryption-proxy/README.md) |
| The two statements outside the chart | [README.md:518](../../README.md#L518), [SECURITY_ARCHITECTURE.md:685](../../SECURITY_ARCHITECTURE.md#L685) |

No Helm unit test covers it — `tests/` holds only `deployment_test.yaml`.

**The upgrade hazard, and it is the security-relevant half.** `v4.0.3` ships this
template. Helm ignores value keys a chart no longer declares, so an operator who
set `networkPolicy.enabled: true` and upgrades to 5.0.0 **loses the policy with
no error and no warning**. The chart README needs an explicit upgrade note
naming the key and saying that the policy is now theirs to maintain. 5.0.0 is
already a major and unreleased, so no separate version decision is needed
(ADR 0018) — but the note is not optional.

**ADR obligation**: the rule — the chart ships no network policy, the network
boundary belongs to the administrator — is carried by no ADR today. 023 took the
decision and it was never written up. It gets one, or a decision block in the
chart's own ADR 0026, in the same change.

## D4 — `license_file` is a preference, not a path

[validator.go:334-341](../../internal/license/validator.go#L334-L341) falls back
through `license.jwt`, `build/license.jwt`, `/etc/s3ep/license.jwt`,
`/opt/s3ep/license.jwt`, `/app/license.jwt` and `./config/license.jwt` when the
configured `license_file` does not resolve.

An operator who names a specific token and mistypes the path gets a **different
token**, with no message saying so. ADR 0016 makes the license a fatal startup
gate; a gate that silently substitutes its input is not one. `/app/license.jwt`
makes it concrete: an image carrying a token from some build step starts happily
even when the mounted secret is missing or misnamed, and the operator cannot tell
from the fact that the proxy is running.

**Options**

- **A — a configured `license_file` is binding.** If the key is written and the
  file cannot be read, refuse the start naming the path. The fallback list applies
  only when the key is not written.
- **B — keep the fallbacks**, log the path actually used at warn level.
- **C — drop the fallback list** entirely.

**Decision (2026-09-12): A.**

It is the rule ADR 0013 already applies to every other configuration value: an
unworkable configuration refuses to start rather than quietly meaning something
else. And it bites exactly where it should — the operator *made* a statement and
it was overruled. B relies on someone reading a warn line at startup, which for a
gate whose effect only shows at expiry is too late. C is stricter than needed and
breaks a legitimate case: `license_file` has a default and the image lives on it,
and the container paths are a real convenience for anyone running the image
without a configuration of their own. A keeps discovery for "said nothing" and
makes only the explicit statement binding.

**Implementation note — `viper.IsSet` is the wrong test here.** `setDefaults`
calls `viper.SetDefault("license_file", "config/license.jwt")`, and viper's
`find()` consults `v.defaults` unconditionally (the `flagDefault` guard covers
pflag defaults only), so `IsSet("license_file")` is **always true**. The
primitive that answers "did the operator write this key" is
`viper.InConfig("license_file")`, which searches the parsed config file alone.
There is no `--license-file` flag — the binary declares `--config`,
`--monitoring` and `--monitoring-port` and nothing else — so `InConfig` is
sufficient.

**Found while checking that**: the same mechanism at
[config.go:233-234](../../internal/config/config.go#L233-L234) guards the
`multipart_session_idle_timeout` check with `viper.IsSet`, whose comment says it
exists so that "an absent key and a written 0" do not look the same. It cannot do
that — the key has a default, so the guard is always true. No live defect, because
the default of 3600 passes the `< 1` check anyway, but the guard does not do what
it claims and should move to `InConfig` with it.

## D5 — The monitoring flags overrule the configuration, and one of them cannot

[main.go:83-87](../../cmd/s3-encryption-proxy/main.go#L83-L87):

```go
if monitoringEnabled {
    cfg.Monitoring.Enabled = true
    if monitoringPort != ":9090" {
        cfg.Monitoring.BindAddress = monitoringPort
    }
}
```

A configuration setting `monitoring.bind_address: ":7000"` plus an explicit
`--monitoring-port=:9090` yields `:7000`: the flag cannot express its own default
as an override.

**Both settings exist as configuration keys with defaults** —
`monitoring.enabled` (`false`) and `monitoring.bind_address` (`:9090`), set in
`setDefaults`. Nothing needs a flag to be expressible.

**Options**

- **A — branch on cobra's `Changed`** instead of on the value.
- **B — remove both flags.** Configuration is the one mechanism; where the
  configuration says nothing, the default applies.
- **C — leave it**, document the quirk.

**Decision (2026-09-12): B.** *(The discussion was about `--monitoring-port`;
the rule "only the configuration counts" is taken to cover `--monitoring` with
it, since the chart passes the pair together and keeping one would be
incoherent.)*

It is the rule the project already applies to the environment — no variable
overrides a configuration key, the one mechanism is a `${VAR}` written into a
value — and a flag is the same idea wearing different clothes. A would make the
flag honest but keeps a second way to say the same thing. C documents a defect as
a quirk: the flag stands in the command line, does nothing, and nothing says why.

**`config/default.yaml` correctly says nothing about monitoring** and should keep
saying nothing. The file states its own rule — *"the seven below are exactly the
settings that have no useful default and must be supplied … Everything not
written here keeps the default the proxy sets for it"* — and monitoring has a
useful default. A `${S3EP_MONITORING_*}` there would invent a mandatory variable
for every image start.

**The work**

| Step | Where |
|---|---|
| Drop both flags and the override block | [main.go:59-60](../../cmd/s3-encryption-proxy/main.go#L59-L60), [main.go:82-88](../../cmd/s3-encryption-proxy/main.go#L82-L88) |
| Render a `monitoring:` block into the chart's ConfigMap from `.Values.monitoring.{enabled,port,metricsPath}`, and drop the two args | [configmap.yaml](../../deploy/helm/s3-encryption-proxy/templates/configmap.yaml), [deployment.yaml:54-57](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L54-L57) |
| Drop the now-redundant `--monitoring` | [Makefile:471](../../Makefile#L471), [Makefile:480](../../Makefile#L480) — `config/aes-example.yaml` already sets `monitoring.enabled: true` |
| Documentation | [CONTRIBUTING.md:222](../../CONTRIBUTING.md#L222), [configuration.md:12-14](../developer/configuration.md), chart [README.md:344](../../deploy/helm/s3-encryption-proxy/README.md#L344) |

**This closes a live chart defect as a side effect.**
`.Values.monitoring.metricsPath` reaches the **ServiceMonitor** alone
([servicemonitor.yaml:27](../../deploy/helm/s3-encryption-proxy/templates/servicemonitor.yaml#L27))
and never the proxy, because the flags carry only the port. Setting it to
anything but `/metrics` makes Prometheus scrape a path the proxy does not serve —
every scrape a 404. A rendered configuration block carries `metrics_path` with
the rest and the two cannot drift.

Removing a CLI flag breaks anyone scripting it. 5.0.0 is an unreleased major, so
it lands inside one (ADR 0018), and the chart README's upgrade note carries it
with D3's.

## D6 — A `--config` that cannot be read is not reported

[config.go:196-199](../../internal/config/config.go#L196-L199) discards the
`viper.ReadInConfig()` error and `InitConfig` returns nothing:

```go
if err := viper.ReadInConfig(); err == nil {
    fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
}
```

A mistyped `--config` path, or a file whose YAML does not parse, leaves the
process on defaults. The start still fails, because
[validate](../../internal/config/config.go#L342-L344) requires
`s3_backend.target_endpoint` and nothing gives it a default — so the defect is
not a wrongly started proxy but a **misleading error**: the operator is told the
backend endpoint is missing when the truth is that their file was never read.

*(Corrected 2026-09-13: an earlier draft named `s3_clients` as the error. It is
not — `validate` checks `s3_backend.target_endpoint` first and returns before the
client check is reached. Verified by running the built binary three ways: a
non-existent `--config` path, an unparseable file, and no flag at all all print
`config validation failed: s3_backend.target_endpoint is required`.)*

It compounds with D4. Once a written `license_file` is binding, a configuration
file that was never read means `license_file` never arrives either, and the
message points in the wrong direction a second time.

**Options**

- **A — return the error always.** Any configuration file that cannot be read
  refuses the start.
- **B — refuse only when `--config` was passed explicitly.**
- **C — leave it**, extend the required-field message with a hint.

**Decision (2026-09-12): A.**

Verified that it breaks nothing that works today:

- Every shipped invocation passes `--config` — the image
  ([Containerfile:94](../../Containerfile#L94)), both compose proxies
  ([docker-compose.demo.yml:72,125](../../docker-compose.demo.yml#L72)), the chart
  ([deployment.yaml:53](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L53)),
  the conformance runner and the Makefile run targets.
- Without `--config`, viper searches for `.s3-encryption-proxy.yaml` in `$HOME`,
  `.` and `./config`. No such file is shipped, so a bare run finds nothing — and
  then fails on `s3_clients` regardless. A only changes *which* error it prints,
  from "s3_clients is required" to one naming the configuration file.
- The one invocation without `--config` is
  [performance.sh:365](../../performance.sh#L365), `--version`, which is an
  **unknown flag** today (`rootCmd` sets no `Version`), so that report line has
  always printed "Unknown". Unaffected by A, and its own small defect.

B was the cautious reading and is weaker: "found it and it does not parse" is
never a legitimate outcome, with or without `--config`, so the distinction B
draws does not earn its complexity.

**The work, and its real cost.** `InitConfig(cfgFile string)` gains an error
return. Cobra's `OnInitialize` takes a `func()`, so
[main.go:63-65](../../cmd/s3-encryption-proxy/main.go#L63-L65) either fails fatal
inside the initializer — matching how `main` already treats a failed
`LoadAndStartLicense` — or the read moves into `runProxy`. Three coverage tests
pin today's tolerant behaviour and move with it:
[loading_coverage_test.go:82](../../internal/config/loading_coverage_test.go#L82)
(`InitConfig("")`), `:92` (a missing path) and `:116` (an absent file).

## D7 — `s3ep-kek-algorithm` is written and never read

Written at [metadata.go:108](../../internal/orchestration/metadata.go#L108).
Readers exist **only in tests**: `MetadataManager` has `GetEncryptedDEK`,
`GetAlgorithm` (which reads `dek-algorithm`) and `GetFingerprint`, and no
KEK-algorithm getter.

**Options**

- **A — keep writing it**, documented as write-only provenance.
- **B1 — keep it and read it** for diagnostics and, once there is more than one
  KEK algorithm, as a dispatch input confirmed by the fingerprint. A mismatch is
  never a refusal on its own.
- **B2 — read it and refuse on a mismatch.** The field is unauthenticated, so the
  check catches accident, not an adversary.
- **B3 — bind the wrap-describing metadata into the wrap's associated data**, then
  read and verify. Format change.
- **C — stop writing it.** Three metadata keys instead of four.

**Decision (2026-09-12): B1.**

The field stays because there will be more than one KEK algorithm, and then it is
the provenance a person debugging a migration looks for. That it is read by
nothing today is itself the defect — a read path that ignores it is guessing the
moment a second algorithm exists.

**B3 was recommended first and is wrong.** What decides it is which inputs are
cryptographically load-bearing for decryption:

| Input | Where it comes from | If it is lost |
|---|---|---|
| The master key | configuration | unrecoverable |
| `s3ep-encrypted-dek` | metadata | unrecoverable — the wrap carries its own GCM tag |
| The object key | the object's own name, bound into every segment's associated data | — |
| The format id, the segment index | a constant, and the position | reconstructible |

**Exactly one of the four metadata keys is cryptographically required**:
`encrypted-dek`. `kek-fingerprint` is a selector — an offline tool can try every
configured key instead — `kek-algorithm` is read by nothing and `dek-algorithm`
names a format of which there is one. A flipped bit in either of the last two
costs a recovery attempt nothing.

B3 would grow that set from one field to four. Every field bound into the
associated data is a field whose corruption blocks decryption, including for a
deliberate out-of-band recovery. And it buys no security in exchange: every
tampering case already fails closed without it — a forged `kek-fingerprint` finds
no provider or one whose unwrap fails its tag, a forged `dek-algorithm` makes the
object foreign, and a forged `kek-algorithm` acts on nothing because the provider
is chosen by fingerprint. That stays true with several algorithms **as long as
dispatch runs on the fingerprint and not on the algorithm string**, which is the
constraint B1 has to honour. There is no downgrade through the field: the wrap
opens under the right key or not at all.

So B3 would have bought diagnostics and paid with a format break and with
recovery friction. B2 buys the same diagnostics without the break, but makes a
descriptive field load-bearing after the fact, which is the same step in
miniature.

**What B1 builds**: read the value, use it in the error text a failed provider
lookup produces (*"wrapped with algorithm `aes`; no configured provider of that
type carries fingerprint X"*), and treat it as a dispatch input once a second
algorithm exists — confirmed by the fingerprint, never replacing it. No new
refusal.

**ADR obligation**: the load-bearing set above, and the rule that dispatch runs
on the fingerprint, belong in ADR 0002. Neither is written down today.

**Out of scope here**: the deliberate out-of-band recovery path this discussion
surfaced is its own ticket, 033.

## D8 — `SealedPart.Streamed` has no caller

[segmented.go:135](../../internal/orchestration/segmented.go#L135).
`deadcode ./cmd/s3-encryption-proxy` lists it, and a search for the identifier
finds its definition and its doc comment and nothing else — no production caller
and no test.

The other three `deadcode` reports are legitimate: `Manager.ShortPartBytesHeld`,
`Server.Addr` and `naiveCRC64NVME` are reached from tests, the last as the
reference implementation the table-driven one is checked against.

**Options: A — delete it. B — keep it as part of `SealedPart`'s shape.
C — keep it and write a test.**

**Decision (2026-09-12): A.**

`CLAUDE.md` is explicit that unnecessary code goes and that backward
compatibility is not owed. A predicate nobody asks is a claim about the design
that secures nothing: `p.src != nil` is the streamed-or-buffered distinction, and
the code makes it where it needs it without this detour.

C would be the worst of the three — a test written so that a function has a
caller silences `deadcode` without anyone needing the predicate, and makes the
later deletion more expensive because a test now stands against it. B would have
an argument if `SealedPart` were published API; `internal/orchestration` cannot
be imported from outside the module, so it is not.

The field `p.src` stays; only the unused reader on it goes.

## D9 — `make lint` never sees the test tree

[Makefile:316](../../Makefile#L316) is `golangci-lint run --timeout=5m` with no
`--build-tags`. Every file behind `//go:build integration`, `conformance`, `e2e`
or `perf` is invisible to it — most of `test/` — and the CI `linter` job inherits
that.

The audit found things in that tree a linter would have caught: dead
`testing.Short()` guards in files that already carry an `integration` tag, so
they can never run in short mode; and
`test/integration/authentication/auth_test.go` hardcoding
`http://localhost:8080` in thirteen places, which is why
`make test-integration-tls` never reaches the TLS endpoint from that package.

**Options**

- **A — add `--build-tags integration,conformance,e2e,perf`** to the existing
  target.
- **B — a separate `lint-tests` target**, outside `all-checks` at first.
- **C — leave it.**

**Decision (2026-09-12): A.**

A linter that cannot see a large share of the Go files reports a false green,
which is worse than no linter: it is the state in which people believe the check
happened. B has the known weakness that a target outside `all-checks` is never
run and the backlog never shrinks; if it is ever chosen as a staging step, it
needs a date on which it moves into `all-checks`.

**What is verified, and what is not.** `go vet` is clean under all four tags
(`go vet -tags=<tag> ./...`, each exits 0), so the tree compiles and passes vet —
the linter will run. The configuration also already anticipates linting test
files: [.golangci.yml](../../.golangci.yml) carries `_test.go` exclusions for
gosec G101 and G115 with their reasons.

**Not measured**: how many findings the other linters — errcheck, revive,
staticcheck, unused, misspell — produce over the test tree on first contact.
`golangci-lint` is not installed on this machine. To get the number:

```
make tools                       # installs the pinned golangci-lint
golangci-lint run --timeout=5m --build-tags integration,conformance,e2e,perf
```

Count first, then decide whether A lands as one change or whether the findings
are cleared ahead of the flag. **What must not happen is the flag being removed
again because it turned out inconvenient** — that returns the repository to a
false green, and this time deliberately.

## D10 — Seven code comments now contradict the corrected documentation

The audit corrected the documents; these comments still state the superseded
version, and each cites the rule it now gets wrong.

| Where | Says | Truth |
|---|---|---|
| [complete.go:95](../../internal/proxy/handlers/multipart/complete.go#L95) | "serving the proxy's own is ADR 0012 D10, which is not built" | D10 shipped 2026-09-11 |
| [operations.go:1155-1157](../../internal/proxy/handlers/object/operations.go#L1155-L1157) and :1164-1166 | the producer loop treats `io.ErrUnexpectedEOF` as a clean end, via `io.ReadFull` | it reads through `fillPart`, which counts only a literal `io.EOF` |
| [config.go:207](../../internal/config/config.go#L207) | "this release's twelve deleted keys" | twenty-two |
| [config.go:416-417](../../internal/config/config.go#L416-L417) | `validateBackendTransport` refuses plain HTTP "under a provider that encrypts" | it refuses for every provider that resolves (`d2c5466`) |
| [memory_test.go:61](../../test/perf/memory_test.go#L61) | "It records only: the bound is not asserted here" | it asserts twice (`d89e443`) |
| [client.go:133-136](../../test/perf/client.go#L133-L136) | justifies not probing with a `HeadBucket` behaviour | fixed 2026-09-10 |
| [parser.go:180-186](../../internal/proxy/request/parser.go#L180-L186) | `DecodedContentLength` is "a routing hint" callers route on | nothing routes on it any more |

**Options: A — fix all seven in one commit. B — fix each when the file is next
touched. C — fix only the three that misquote a rule.**

**Decision (2026-09-12): A.**

They are wrong today and each one actively misleads. `complete.go:95` sends the
next reader off to build something that already exists — that is lost work, not
noise. The two `io.ReadFull` comments describe an error handling that no longer
exists, sitting beside the code that does it differently, so anyone changing
there relies on a false promise.

B means the wrongest survives longest, because nobody is touching those files. C
draws a line that does not exist for a reader: a comment describing behaviour
wrongly costs as much as one misquoting an ADR number — more, in `parser.go`,
where it instructs callers.

Comment-only changes, no behaviour, no tests.

**Worth noticing, not decided here**: `memory_test.go:61` and `client.go:133`
were both left behind by their own code change (`d89e443`, and the HeadBucket fix
of 2026-09-10). That is the same failure the audit found across the documents —
behaviour moved, the description beside it did not. `CLAUDE.md` requires a
document to move with the code it describes; it says nothing about the comment in
the file being changed.

## D11 — Four finished tickets are still in the tree

ADR 0022 D4: a ticket is closed by deleting the file. Verified against the code
and against each ticket's own status table:

| Ticket | State |
|---|---|
| [010](010-performance-improvements.md) | Complete since 2026-04-25. Argues about a tree that no longer exists — its links point at `aes_ctr.go`, `streaming_io.go`, `singlepart.go`, `multipart.go`, `hmac_calculator.go`, all deleted |
| [011](011-dek-cache-stale-on-reupload.md) | Done |
| [016](016-helm-chart-fixes.md) | All twenty-one items done; the ticket asks to be deleted |
| [024](024-coverage-round-findings.md) | Its own deletion condition — the S-3 decision — was met 2026-09-12 |
| [015](015-configuration-hygiene.md) | Every item landed, but 015 ties its own deletion to the 5.0.0 merge |

`docs/tickets/010-tier1.3/` and `010-tier4.1/` hold `go tool pprof -top` text and
test logs with no README saying which run they are, unlike the other `010-*`
directories. (The index gap — 030 and 031 missing from it — the audit already
closed.)

**Options: A — delete the four now. B — sweep at the 5.0.0 merge.
C — delete only 011 and 024.**

**Decision (2026-09-13): B, and it is tracked in 023, not here.**

The sweep runs immediately before the merge, and the concrete list — which ticket,
what has to be moved out of it first, and the two stray directories — is written
into 023's *Done when* section, which already carried the general obligation.
That is the right home: 023 is the umbrella whose merge the sweep is a step of,
and this ticket would otherwise have to be alive at merge time just to hold a
checklist.

What the deferral does **not** change is that extraction is the work and `git rm`
is not: 010's measurement tables belong in ADR 0020, 011's rule is ADR 0002,
016's chart decisions are partly in ADR 0026 and partly homeless. Three of the
five are still cited as evidence today — including twice in this ticket, in D3
and D5 — which is an argument for giving their content a permanent home, not for
keeping the citations pointed at tickets.

**This item is closed here.** Nothing else in 032 depends on it.

## D12 — The image has no `ENTRYPOINT`

[Containerfile:94](../../Containerfile#L94) is
`CMD ["./s3-encryption-proxy", "--config", "config/default.yaml"]` with no
`ENTRYPOINT`, so `docker run <image> --config /path/to/mine.yaml` replaces the
whole CMD and the runtime tries to exec `--config`.

The audit corrected `README.md` to document the workaround — spell the binary.
That documents a papercut rather than removing it.

**Options: A — add `ENTRYPOINT ["./s3-encryption-proxy"]`, reduce `CMD` to the
arguments. B — leave it, the README documents it.**

**Decision (2026-09-13): A.**

`docker run image --flag` is what every operator expects, and the image's own
README had to apologise for it. Under an `ENTRYPOINT`, `docker run image
--version` also becomes a clean error from the binary instead of an exec failure
from the runtime — `--version` does not exist either, which D6 turned up.

The argument against is that an entrypoint makes overriding the command harder;
`docker run --entrypoint sh image` is the established handle for that and is not
a reason to break the convention.

**The work — five places in four files**, more than the "three lines in two
files" this item first estimated:

| Step | Where |
|---|---|
| `ENTRYPOINT ["./s3-encryption-proxy"]`, `CMD ["--config", "config/default.yaml"]` | [Containerfile:94](../../Containerfile#L94) |
| Both proxy services set `command:` explicitly; under an entrypoint those become arguments **to** it and the containers break. Reduce each to the arguments alone | [docker-compose.demo.yml:72](../../docker-compose.demo.yml#L72), [:125](../../docker-compose.demo.yml#L125) |
| The alternate-proxy recipe passes `./s3-encryption-proxy --config …` | [test/perf/README.md:242-243](../../test/perf/README.md#L242-L243) |
| The recipe that spells the binary, and the sentence explaining why it has to | [README.md:835](../../README.md#L835), [README.md:690](../../README.md#L690) |

**Unaffected**: the Helm chart, which sets `command:` to the binary path and
`args:` separately — that overrides entrypoint and CMD together and stays correct
([deployment.yaml:51-53](../../deploy/helm/s3-encryption-proxy/templates/deployment.yaml#L51-L53)).
The Velero e2e stack installs the proxy through that chart, and the three
`docker run` recipes in `README.md` that pass no command at all keep working
unchanged.

## D13 — Four German comments in the demo compose file

[docker-compose.demo.yml:231,236,243,252](../../docker-compose.demo.yml#L231),
in the vault service's entrypoint: `# Warten bis Vault bereit ist`, `# Login und
Transit Engine aktivieren`, `# Beispiel-Keys erstellen`, `# Server im Vordergrund
laufen lassen`. `CLAUDE.md` rule 6 is English-only for code, comments and
documentation, and the audit found nothing else in German anywhere in the
repository.

Two neighbours in the same block:

- **Line 240**, `vault auth -method=token token=myroot`. Vault 1.x replaced
  `vault auth` as a login verb with `vault login`, so the line errors on every
  demo start — harmless only because `VAULT_TOKEN=myroot` is already set.
- **Line 209**, `image: hashicorp/vault:latest`, an unpinned floating tag in a
  repository that otherwise pins every image.

Context: **no proxy code talks to Vault.** The service is in the demo stack for
the KMS work ADR 0005 records as not built.

**Options: A — all three (translate, `vault login`, pin the tag).
B — translate only. C — remove the vault service entirely.**

**Decision (2026-09-13): A.**

The file is touched once either way, and an unpinned `latest` in the demo stack
is exactly the reproducibility hazard the rest of the repository avoids — the
demo stack is the first thing a prospect starts. B leaves a command that fails on
every start and a tag that moves unasked.

C was considered seriously: a service no code uses is dead weight, and
`CLAUDE.md` says unnecessary things go. What kept it is that Vault here is not
product code but a demonstration environment for a decision that is taken and
recorded (ADR 0005); it costs nothing at rest and makes the next KMS step
cheaper.

**On the pin**: Renovate sets no `enabledManagers`, so the built-in
`docker-compose` manager is active on this file and a pinned version will be
maintained. `:latest` gives it nothing to move — which is why the tag never
moved. The repository's own convention is visible two lines up:
`quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z`.

**Adjacent, same class, not decided here**:
[docker-compose.demo.yml:170](../../docker-compose.demo.yml#L170) is
`mastertinner/s3manager:latest`, the second unpinned image in the same file
(a third sits in the commented-out block at line 189). The pin argument applies
to it identically; whether it rides along with this change is the implementer's
call.

## Not in this list

The audit's documentation corrections themselves are done and need no decision.
The knowledge graph under `graphify-out/` is behind the code and its rebuild is a
separate, user-approved run.
