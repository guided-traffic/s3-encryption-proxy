# ADR 0021: Key material and licenses are generated, never committed

## Status

**Accepted.** Date: 2026-09-07.

Implemented and released in **3.8.56**: the Helm chart no longer ships a working
key-encryption key as its default — the default values and the monitoring variant both
reference `${S3EP_AES_KEY}`, so an install that configures nothing refuses to start instead
of encrypting under a published key. Also implemented: the test certificate authority is
untracked and generated on demand, and only its generator is tracked. Verified on
2026-09-07: no license token and no license signing key is tracked in this repository, none
ever was, continuous integration passes the token only through the `S3EP_LICENSE_TOKEN`
secret, and the published container images are built from a checkout that holds neither.

**Implemented 2026-09-11: no usable key reaches a running stack from this repository.** The
statement here used to be the wider "no usable key is tracked any more", **corrected
2026-09-12** — see the block below. The on-demand generator writes
`S3EP_AES_KEY` and `S3EP_AES_KEY_RETIRED` into the repository's ignored environment file,
keeping a value that is already there so a restarted stack still reads what it wrote, and it
is called by the demo bring-up, by the end-to-end bring-up and by continuous integration.
Every example configuration, the user-facing reference and the end-to-end deployment values
reference the variable; the demo stack takes it from the same file its compose environment
reads, and the chart gained the wiring that hands it to the pod — which it had never had, so a
default install referenced a variable nothing supplied. The demo bring-up now exports
`S3EP_LICENSE_TOKEN` from the local token file the way the end-to-end bring-up does.

**Corrected 2026-09-12: D1 is met for everything an operator can copy or run, and is not met for
test fixtures.** No example configuration, chart values file, deployment values file or compose
file carries a key, and no private key, certificate or license token is tracked at all. The unit
and integration tests are the exception, and D1 names a test fixture in the same breath as an
example: twenty-one test files carry base64 literals of exactly 32 bytes, four distinct keys
between them, and each one would be accepted as a key encryption key by a configuration that used
it. The most-used of the four appears in sixteen files; the one this repository published, and
which D7 covers, in three — it never left the tests, has been in one of them since 2025-08-31,
and on 2026-09-12 it was written into a third as the fixture for the test that loads the
configuration the image ships with. The 2026-09-11 removal cleared the examples and the values
files and replaced one test fixture with a non-key string; the rest of the tests it left alone.
None of these keys encrypts anything that outlives a test process; that is an argument about
impact, not about D1.

**The key that was published stays published (D7).** One working 256-bit key and one retired
companion were in this repository's history and are to be treated as compromised: any
deployment that ever ran under either re-writes its data under a new key before the old
provider is removed. Deleting them from the tree does not un-publish them.

Still **not implemented**: moving the license signing key into custody outside any directory a
routine build clean removes.

**Corrected 2026-09-10: there are no RSA private keys in the tree.** This block used to name
two. The `rsa` key provider was deleted with ADR 0004, and every key file it needed went with
it; what remains are two obviously truncated placeholder strings in configuration tests. A
reader auditing this repository should not go looking for keys that are not there.

**Closed 2026-09-10: the token no longer reaches a locally built image.** The build context
excludes it, along with every `.jwt`, `.pem` and `.key`, and since 2026-09-11 the generated
environment file as well. Before that a developer with a token on disk baked it into every
image they built, which was reproduced and then fixed.

**Closed 2026-09-11: D3's one name.** `S3EP_AES_KEY` is the only name in the tree; the second
name that lived in the example comments is gone with the literals.

One item of this family is **open** and is listed under Residual risks: where the license signing
key is kept. The second one used to sit here — what the monitoring targets that load an example
configuration do on a fresh checkout — and is **closed 2026-09-12**: they invoke the generator,
which makes them the fourth call site the Consequences below warn about.

## Context

The proxy's entire confidentiality claim rests on one secret: the key-encryption key an
operator configures. Everything else — the per-object data key, the authenticated wrap, the
segment chain — is public construction. A key-encryption key that ships inside the product
is therefore not a weak key, it is no key at all.

**The concrete failure was the chart default.** The deployment chart shipped a working
256-bit key as the default provider key, and its monitoring values file shipped a second
one. Any install that did not override the encryption configuration encrypted every object
under a key printed in this repository — and the install *succeeded*, so nothing told the
operator anything was wrong. That is the worst shape a security defect can take: silent, on
by default, and indistinguishable from working.

**The same material sits in the example configurations**, and those are not documentation.
They are live fixtures: the demo stack mounts two of them as the running proxies'
configuration, integration tests load one directly to start a proxy instance, and monitoring
targets pass another on the command line. One key appears in three of those files, so a
single copy-paste puts the same repository-public key on three deployments. Most of those
files already carry a commented-out environment-variable form beside the literal — which is
exactly the point: a comment recommending the safe shape is documentation, and the threat
model's own rule is that a control which exists only in documentation is worse than no
control, because it gets relied upon.

**The precedent had already been set once.** The test certificate authority's private key
had been committed. It was made untracked and generated on demand, and the decision went one
step further than deleting the key: only the generator stays tracked, because a tracked
certificate stops matching a key that a fresh clone generates, and a mismatched pair fails in
a way nobody attributes to the checkout.

**The license is a bearer token and had a quiet second route.** The token file itself was
never committed and is ignored. But the container build context included the whole
configuration directory, so a locally built demo image carried the token at a fixed path
inside the image — and the demo stack silently ran on that copy rather than on the
environment variable, which is also why reissuing the token only took effect after an image
rebuild. One route everywhere is both safer and simpler than two.

**The key that mints licenses is the least protected thing in the picture.** The private half
of the license signing key lives untracked in the build output directory, has no second copy,
and a routine clean target deletes it. Losing it does not cost a token; it costs the ability
to ever issue a token the shipped binary accepts.

## Decision

**D1.** No working key material is tracked in this repository. Not a key-encryption key, not
a private key of any kind, not a license token, not a test certificate authority key — in no
example configuration, chart values file, deployment values file, test fixture or document.
A file named "example" is held to the same rule as a file named "production", because the
example is what gets copied.

**D2.** Key material that a local stack needs is **generated on demand**. One generator
produces it, writes it to an ignored path and exports it into the environment; it is called
by the demo bring-up, by the end-to-end bring-up and by continuous integration, and it
generates only when the material is absent, so a stack that is restarted can still read what
it wrote before.

**D3.** One name for the local key everywhere: the key is supplied through the environment
variable `S3EP_AES_KEY` and referenced as `aes_key: "${S3EP_AES_KEY}"` in example
configurations, chart values and deployment values alike. If the variable is unset the
configuration fails to load and the proxy refuses to start; there is no fallback and no
default key, which is the correct answer to "you did not configure encryption" (ADR 0013).

**D4.** Where a generator produces material that must agree with itself — a certificate and
its key — **no half of it is tracked**. Tracking the public half is not a safe middle: it
stops matching the private half the next clone generates.

**D5.** The license token reaches every environment through the `S3EP_LICENSE_TOKEN`
environment variable, and the local token file is excluded from the container build context
so that no image, locally built or published, can carry one. The demo bring-up exports the
token from the local file the way the end-to-end bring-up already does. The `license_file`
setting remains the on-disk route for a deployment that mounts the token itself (ADR 0016).

**D6.** The license signing key lives outside this repository and outside any directory that
a routine build clean removes, is never committed, and is never placed in a repository
secret — a secret that can mint licenses the shipped binary accepts is a distribution
channel, not a backup (ADR 0016).

**D7.** Published key material is not un-published by deleting it. Any deployment that ever
ran under a key that appeared in this repository treats every object written under it as
compromised: configure a new key, re-write the data through the proxy, and only then remove
the old provider (ADR 0002).

**D8.** User-facing documentation shows an environment reference and names the generator that
produces a key. No document, example or default in this product ever prints a usable key.

## Consequences

- **A clean clone can no longer bring the demo up by hand.** Starting the stack without the
  bring-up step fails on a missing key. That is the price of not publishing keys, and it
  makes the bring-up scripts the only supported entry point.
- **A generator, and every call site of it, becomes maintained code.** Three call sites are
  named (demo, end-to-end, continuous integration), and any new environment has to remember
  the fourth.
- **Operators who installed the chart with its defaults are broken by the upgrade**: it
  refuses to start until they supply a key, and the objects they already wrote are encrypted
  under a public key and must be re-written. That is the correct outcome, but it shipped as
  an ordinary fix rather than as a headline of the next major release, so the warning lives
  in the security documentation instead of in release notes anyone reads.
- **The history keeps the keys.** Removing a literal at the tip does not retract it. Every
  key this repository has ever contained stays retrievable, which is why D7 is rotation and
  not deletion.
- **Generated fixture keys are as durable as a working copy.** Deleting the generated file
  makes the objects a demo stack wrote before it unreadable — the same property production
  has, arrived at by accident rather than by procedure.
- **Signing-key custody becomes a manual step with no automation and no second copy.** That
  is deliberate (D6) and it means the recovery path for a lost key is a new keypair, a new
  embedded verification key and a rebuild of every image.
- **A target that used to work on a bare checkout now needs one step first.** The monitoring
  targets that load an example configuration either call the generator or document the export;
  either way the "just run it" property is gone.
- **Test fixtures lose material they got for free.** The integration tests that started a
  proxy from an example configuration with a real asymmetric key now need generated material —
  which costs nothing here only because that provider type is removed anyway (ADR 0004).

## Alternatives Considered

**Leave the example configurations as they are.** They are fixtures, the demo stack is local
and throwaway, and its object-store credentials are the well-known defaults anyway. Rejected:
a private key inside a repository reads as a real leak in every scan that looks at it, a key
in a file named "example" is what people copy, and the safe shape written as a comment beside
the unsafe literal is documentation, not a control.

**Move only the private keys out and keep the symmetric demo key.** Removes the artifact that
scans flag, at a fraction of the work. Rejected: it leaves a repository-public
key-encryption key in the file most likely to be copied, which is the exposure that actually
matters — the scan finding is a symptom, not the risk.

**Track the generated certificate and generate only its key.** Would have kept a clean clone
self-sufficient for the test stack. Rejected: the tracked certificate immediately stops
matching the freshly generated key, and the resulting failure points at everything except the
checkout.

**Keep the license token inside the locally built image and rely on that copy.** It worked,
and it is why nobody noticed. Rejected: an image is a distributable artifact, a token baked
into one is a bearer credential in a layer, and a reissued token then only takes effect after
a rebuild. One environment variable everywhere replaces two routes with one.

**Store a second copy of the license signing key in a repository secret** so reissue could be
automated. Rejected for the reason recorded in ADR 0016: that secret mints licenses the
shipped binary accepts, which makes it a stronger credential than any token it would produce.

## Residual risks

- **Open: where the license signing key is kept, and how the generator finds it.** The choice
  between pointing the generator at that location and documenting a copy step is not made.
  Until it is, the only copy sits in a build output directory that a routine clean deletes,
  and D6 is a rule rather than an observed state. Its presence was confirmed on 2026-09-07;
  nothing confirms it since, and nothing will.
- **Closed 2026-09-12: what the monitoring targets do on a fresh checkout.** They invoke the
  generator, keeping a key that is already there, and they read the license token from the local
  file when one exists. The "just run it" property is back for them, at the cost of a fourth call
  site of the generator to maintain.
- **Corrected 2026-09-12: what is still in the tree is the test fixtures.** This entry named one
  working key in three example configurations, the same key in the end-to-end deployment values,
  and two complete RSA private keys. None of that is there any more. What is there is four
  working 256-bit keys across twenty-one test files, one of which this repository published long
  ago; they are public as of the day they were committed, not as of the day anything is removed,
  and D7 governs any deployment that ever ran under one.
- **Closed 2026-09-11: the second variable name.** `S3EP_AES_KEY` is the only name in the tree,
  so a reader following a comment in an example configuration wires up the variable the bring-up
  actually sets.
- **Nothing enforces D1 mechanically, and as of 2026-09-12 this is verified rather than
  suspected.** No step of this project's own pipeline scans for secrets on a push or a pull
  request; whether the hosting platform applies its own push protection is outside the tree and
  is still unverified. The rule holds by review, which is the same class of control the decision
  itself calls insufficient — and the fixture keys above are what a review missed.
- **Not verified: whether any deployment ever ran under the published chart default or under
  an example key.** The assumption must be that at least one did; D7 is written for that case.
- **Not verified: whether a locally built image carrying the development token was ever pushed
  anywhere.** What was verified is only the negative side — no token and no signing key is
  tracked or was ever committed, continuous integration passes the token solely through its
  secret, and published images come from a checkout without one. The single identified
  exposure was a locally built demo image.
- **Generated fixture keys are never rotated** and live as long as a working copy does.
  Accepted for throwaway local stacks; it is not a model for anything an operator runs.

## References

- ADR 0002 — *One data key per object, wrapped by a configured key encryption key* — the
  rotation procedure D7 refers to.
- ADR 0004 — *One local key provider: 256 random bits, an authenticated wrap, no passphrases*
  — what counts as a valid key and which generator produces one.
- ADR 0005 — *A KMS-backed key encryption key is a provider, not a mode* — custody in a key
  management service, versus the custody-by-injection that `${S3EP_AES_KEY}` gives today.
- ADR 0013 — *A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start* — why an unset key variable is a startup failure rather
  than a default.
- ADR 0016 — *The license is a startup gate with an explicit expiry* — the token routes, the
  one-token rule and the consequences of losing the signing key.
- ADR 0019 — *Integration and end-to-end tests are the product; they are never skipped* — why
  the fixtures are generated rather than deleted.
- [README.md](../../README.md) — key generation, the environment references in the
  configuration reference, and the demo and end-to-end bring-up steps.
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the published chart default,
  and what an operator does if a deployment ran under it.
