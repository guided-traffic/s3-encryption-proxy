# ADR 0016: The license is a startup gate with an explicit expiry

## Status

**Accepted.** Date: 2026-09-07.

Implemented and shipping: the startup gate itself and the hourly runtime expiry check that
stops the process, both of which predate this decision. **4.0.0** added the rejection of a
token that carries no `exp` claim and repaired the shutdown path that used to hang forever
when no license was present. Verified on
2026-09-07: no license token and no license signing key is tracked in this repository, and
none ever was.

Decided and specified, **not implemented**: holding one and the same token in the local
development copy and in the continuous-integration secret, the build step and the daily
scheduled run that fail while the token expires within 14 days, and the workstation command
that runs the same check. No work list exists for these; they are taken up when the owner
wants them (2026-09-09). Verified again 2026-09-12: no job checks the expiry claim, no
workflow samples it on a schedule, and `make check-license` does not exist.

**Done 2026-09-10, the second half of D11.** The dead development-license setup target was
deleted with the rest of the code nothing reads. `make generate-license`, which builds and runs
the license tool, is the only way to mint a token (verified 2026-09-12).

**The type the gate admits without a license is `exit`, not `none` (2026-09-12).** D1 and the
Context name `none`, which ADR 0025 replaced: `type: "none"` is now refused at startup by a
message that says so. The gate reads the **active** provider only — the one
`encryption.encryption_method_alias` names — so an `aes` provider listed beside an active
`exit` provider needs no license, which is what lets a lapsed license stop new encryption
without stopping reads.

**Closed 2026-09-10: keeping the token out of locally built container images.** The build
copied the whole working tree and then copied `config/` into the final image, and the ignore
file excluded neither, so a developer with `config/license.jwt` on disk — which is where the
documented workflow puts it — baked a token into every image they built. Reproduced against
the demo stack's image before the fix. The published release image was clean only because CI
builds where that file does not exist, which is an accident rather than a control. The ignore
file now excludes the token and, for the same reason, every `.jwt`, `.pem` and `.key`.

One item of this family is **open** and listed under Residual risks: whether the scheduled
check opens an issue or only fails the run.

## Context

The proxy is commercial software. Every encryption provider type except `none` requires a
valid license, and `none` is pass-through — it writes no ciphertext and needs no key. The
gate therefore sits exactly where the product's value does: no license, no encryption, and —
as it was decided — no decryption of anything previously written; ADR 0025 changed that second
half, see Status.

The license is a signed JWT verified against an RSA public key compiled into the binary. Its
claims name the issuer, the audience, the licensee and company, an optional Kubernetes
cluster id, and the validity window (`iat`, `nbf`, `exp`). Validation runs as part of
configuration validation, so a bad or missing license is a startup failure, not a
degradation.

Three concrete failures made this decision necessary.

**A token without an expiry started the proxy and killed it an hour later.** Validation
checked the expiry only when the claim was present, so a token with no `exp` was accepted.
The stored expiry then kept its zero value — year one — and the periodic runtime check,
which asks whether the current time is after the expiry, answered yes on its first tick.
The process terminated after 60 minutes with a log line blaming an expiry that did not
exist. Under an orchestrator that is a permanent hourly crash loop pointing at the wrong
cause.

**Every unlicensed shutdown hung.** Runtime monitoring returned early when there was no
valid license, before starting the background task whose completion was the only thing that ever
released the shutdown wait. The shutdown path then blocked forever, so an unlicensed proxy
had to be killed — under Kubernetes that is every rollout, scale-down and node drain
waiting out the grace period and then taking a hard kill, with in-flight multipart uploads
left dangling on the backend.

**The expiry date lived only in a person's memory, and in two places at once.** The token
reaches its consumers by two independent routes: a local development copy that a checkout
can inspect, and a continuous-integration secret whose expiry nobody can see without a
build. Refreshing one and not the other leaves half the pipeline dead. Nothing read the
`exp` claim of either. The proxy's own startup warning 30 days before expiry already
existed and did not help, because nobody reads proxy startup logs during a green pipeline
run. A deadline that is only warned about in a log is worse than no deadline, because it
gets relied upon.

The failure on the day is also mislabelled. An expired token is rejected during validation,
but the error that stops the process is the one for a *missing* license — "license required
for encryption provider type" — on a machine where the token is right there.

## Decision

**D1.** The proxy refuses to start without a valid license for every encryption provider
type except `none`. License validation is part of configuration validation, and a failure
is fatal — there is no degraded or grace-period mode.

**D2.** The trust anchor is the public key compiled into the binary, and it is the only one.
No configuration value, environment variable or test seam may substitute a different anchor;
policy checks that run after signature verification are what tests exercise instead.

**D3.** A token without an `exp` claim is invalid and is rejected at validation, and the
license generator cannot mint one. A perpetual license is a business decision that must be
spelled out as an explicit claim, never produced by an omission.

**D4.** A running proxy stops when its license expires. The validator re-checks hourly and
terminates the process; the operator's remedy is a new token, and restarting on the same token
changes nothing — D12 names the second remedy, which is a configuration change rather than a
restart.

**D5.** Shutdown never depends on the license. The shutdown path returns whether or not
runtime monitoring was ever started, and starting or stopping monitoring more than once is
safe.

**D6.** The license reaches every environment through the `S3EP_LICENSE_TOKEN` environment
variable. A token is never baked into a container image, and the local development token
file is excluded from the image build context so that a locally built image cannot carry
one either. The `license_file` setting stays as the on-disk route for a deployment that
mounts the token as a file.

**D7.** One token everywhere. The local development copy and the continuous-integration
secret hold the same token, so the two copies cannot drift into separate expiries again.

**D8.** The license expiry is discovered by a build, not by an environment. A check decodes
the expiry claim of whichever token the running job holds and **fails** — it does not warn —
when that token expires within 14 days, or has already expired. It runs as the first step of
the jobs that consume the token, before any image build, cluster bring-up or test suite, and
it also runs on a daily schedule so that a quiet repository is still sampled.

**D9.** That check reads the payload without verifying the signature. It answers one
question — when does this expire — and the binary remains the thing that verifies. One
implementation serves the pipeline and the workstation, exposed as `make check-license`.

**D10.** Blocking a release on a license clock is accepted deliberately. A failing check
stops the release pipeline 14 days before expiry; reissuing takes minutes, and the
alternative is the pipeline going red on the day with a message that names the wrong cause.

**D11.** The license signing key lives outside the repository and outside any directory that
a routine build clean removes. `make generate-license` is the only supported way to mint a
token; the development-license setup target that invoked a script which never existed is
deleted rather than repaired.

**D12.** The license gate is a commercial control and is never presented as a security one.
Its consequence, however, is documented as a security-relevant availability property: an
expired license stops all new encryption, and it stops reads as well until the operator
acts. The two remedies are a new token, or switching the active provider to `exit`, which
needs no license and still decrypts what the provider that wrote those objects holds the key
for (ADR 0025) — keeping that provider configured alongside it. Doing neither leaves every
object in the bucket unreadable.

## Consequences

- An expired license is a full outage of the data path in both directions for as long as the
  active provider is one that encrypts. Switching the active provider to `exit` brings reads
  back without a token, for as long as the provider that wrote those objects stays listed in
  the configuration — remove it and they are unreadable for good — and it leaves writes in
  plaintext (ADR 0025); nothing brings encryption back but a new license. This is the design,
  and it is why the expiry has to be visible long before it arrives.
- The check can fail a release for a non-defect. That is the point of D10, but it means a
  license clock is now a release-blocking dependency, and anyone waiting on a release has to
  understand why.
- Fork pull requests cannot read the continuous-integration secret, so the check fails there
  with "no license token". Those runs already fail for the same underlying reason, but the
  new step moves the failure earlier and makes it look like a licensing problem.
- Two copies of the token still exist. D7 keeps them identical by procedure, not by
  construction; nothing enforces it, and the only place that can see the secret's copy at all
  is a pipeline run.
- The startup error on the day of expiry still reads as *license required*, the message for
  a missing license. Changing the validation and error surface was deliberately left out of
  this decision, so the documented remedy is that the procedure spells the message out
  verbatim, for the next person to search for.
- Rejecting a token without `exp` (D3) closes a real crash loop but removes the only way a
  perpetual license could have been produced. If one is ever wanted, it becomes a change to
  the claim set and to the generator, not a token someone omits a field from.
- The signing key is now the single point of failure rather than the token. If it is lost,
  no token the shipped binary accepts can ever be issued again, and the recovery is a new
  keypair, a new embedded public key and a rebuild of every image — a release, not a chore.

## Alternatives Considered

**Treat a missing `exp` as "no expiry" at both ends.** Would also have stopped the hourly
kill, and would have made a perpetual license free. Rejected: a perpetual license is a
commercial decision, and inferring one from an absent field means an issuing mistake silently
produces the most valuable license the product has.

**A test seam for the trust anchor**, an unexported field a test could point at its own key.
Offered to raise coverage of the accept path, which no test can otherwise reach because the
private half of the embedded key is not in this repository. Rejected: the compiled-in key
would no longer be the only possible anchor. The post-signature policy was made directly
testable instead, leaving one uncovered line — that verification calls the policy check.

**A warning annotation instead of a failing step.** Cheaper, blocks nothing. Rejected: the
proxy's own 30-day startup warning already existed and was ignored for exactly this reason.
A control nobody is forced to read is a control that exists only in documentation.

**Put the scheduled trigger on the existing release workflow** rather than in its own. It
would need conditional guards on every heavy job and on the release step itself — more
surface, and a way to cut a release from a timer by accident. A separate, one-step scheduled
workflow was chosen.

**Make `none` the provider in the pipeline** to dodge the gate entirely. Rejected outright:
that deletes precisely the encryption coverage the suites exist for, which ADR 0019 forbids.

**Verify the signature in the expiry check.** Would catch a syntactically valid but unsigned
token. Rejected as scope creep: the binary verifies, and the integration suite in the same
job catches such a token minutes later.

**A second copy of the signing key in a repository secret.** Convenient for automating
a new token. Rejected as a trade-off, not a peer option: that secret can mint licenses the
shipped binary accepts.

## Residual risks

- **Deferred by the owner on 2026-09-07.** Where the signing key is kept, how the tool finds
  it, and whether the scheduled check opens an issue were put to the owner and deliberately
  left for later; the token's validity period is the owner's alone and is not tracked here.
- **Open: whether the scheduled check opens an issue or only fails the run.** Failing alone
  helps only if somebody reads the notification, and **it is not verified** that this
  repository notifies anyone on a failed scheduled workflow. Until that is settled or
  confirmed, the daily run is a control whose delivery is unverified.
- **Not verified: whether this repository ever sees pull requests from forks**, where the
  token secret is unavailable and the check fails for the wrong-looking reason. If it does,
  both steps need a guard.
- **The Kubernetes cluster id claim is carried but not validated.** Tokens are accepted with
  any value, including an empty one. If that validation is ever implemented, a development
  token pinned to no cluster may start behaving differently.
- **The single-token rule (D7) is procedural.** Nothing compares the two copies
  automatically; the check only ever sees the one its own job holds.
- **The expiry check trusts an unsigned payload** by design (D9), so a well-formed but
  unsigned or forged token passes it and fails at startup instead.
- **The token's routes are wider than D6 states (verified 2026-09-12).** Three environment
  variable names are accepted — `S3EP_LICENSE`, `S3EP_LICENSE_TOKEN` and
  `S3_ENCRYPTION_PROXY_LICENSE` — and beyond `license_file` a fixed list of fallback paths is
  searched, `/etc/s3ep/license.jwt` and `/app/license.jwt` among them. An operator reading D6
  cannot tell which of them a running proxy took its token from.
- **Custody of the signing key is named but not verified here.** That it exists outside a
  directory a build clean removes is a rule, not an observed state; the exact custody
  location is the owner's to name and is not recorded in this repository — see ADR 0021.
- **Minting a token puts the signing key inside the build output, which a routine clean
  deletes (verified 2026-09-12).** The license tool reads the signing keypair only from the
  directory holding its own binary, and the supported minting target builds and runs that
  binary in the build output directory — the one a build clean removes. Nothing in the tool
  takes a key location from a flag, an environment variable or the configuration, so D11's
  custody rule describes where the key rests between mintings, not where it sits while one
  runs.

## References

- ADR 0013 — *A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start* — the general form of the refuse-to-start rule D1 applies.
- ADR 0018 — *A major release is declared by a label, never discovered at merge
  deliberately* — the release path that D8 and D10 deliberately block.
- ADR 0019 — *Integration and end-to-end tests are the product; they are never skipped* —
  why dodging the gate by switching the pipeline to the pass-through provider is not an
  option.
- ADR 0021 — *Key material and licenses are generated, never committed* — where the signing
  key and the token live, and why neither is in the tree or in an image.
- ADR 0025 — *Leaving is a supported mode* — the provider type the gate admits without a
  license, and what it does and does not keep readable.
- [README.md](../../README.md) — the operator-facing license setup. The token routes and the
  exit provider's exemption are written there (verified 2026-09-12); the verbatim failure message
  to search for is not, and lands with the unbuilt half of this decision.
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — license expiry as an
  availability property with security consequences.
