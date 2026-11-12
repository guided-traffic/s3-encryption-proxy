# ADR 0021: Key material is generated, never committed

## Status

**Accepted.** Date: 2026-10-29.

**Implemented for everything an operator copies into a deployment.** The Helm chart ships no
working key encryption key as its default: since **3.8.56** the default values and the
monitoring variant reference `${S3EP_AES_KEY}`, and the chart hands that variable to the pod,
so an install that configures nothing refuses to start instead of encrypting under a published
key. No example configuration, chart values file, deployment values file or compose file
carries a key, and no private key or certificate is tracked at all: the test certificate
authority is generated on demand and only its generator is tracked. There are no RSA private
keys in the tree; the `rsa` key provider went with ADR 0004, and what remains of it are two
obviously truncated placeholder strings in configuration tests.

The on-demand generator writes `S3EP_AES_KEY` and `S3EP_AES_KEY_RETIRED` into the
repository's ignored environment file, keeping a value that is already there so a restarted
stack still reads what it wrote. It is called by the demo bring-up, by the end-to-end
bring-up, by continuous integration and by the two monitoring targets that load an example
configuration. Every example configuration, the user-facing reference and the end-to-end
deployment values reference the variable; the demo stack takes it from the same file its
compose environment reads. `S3EP_AES_KEY` is the only name for the active key (D3). The
generator's second name, `S3EP_AES_KEY_RETIRED`, belongs to the second provider of the
rotation example, and the conformance runner carries its own, `S3EP_CONFORMANCE_AES_KEY`.

**Not met: D1 for the test fixtures and the conformance runner.** D1 names a test fixture in
the same breath as an example, and the unit and integration tests carry base64 literals of
exactly 32 bytes, each of which a configuration would accept as a key encryption key. The
format and wrap test vectors are among them, so their number moves whenever a vector suite is
added, and it is not restated in a document that is not regenerated. One of them is a key this
repository also published outside the tests, and which D5 covers: two example configurations
and the chart's development values carried it, and it is the fixture of the test that loads
the configuration the image ships with. The conformance runner carries a working key as a
shell default, because a stored object names the fingerprint of the key that wrapped it and an
already seeded corpus would otherwise be unreadable; a `make test-conformance` run hands that
repository-public key to a real proxy. None of these keys encrypts anything that outlives a
test process or the local backend's container — an argument about impact, not about D1.

**The keys that were published stay published (D5).** Five working 256-bit keys appeared in
this repository: one across the example configurations, the user-facing reference, the
monitoring values and the end-to-end values; its retired companion in one example
configuration and the user-facing reference; a third in two example configurations and in the
chart's development values, which still serves as a test fixture; the chart's own default
before 3.8.56, a thirty-two character string that is not base64 of thirty-two bytes, which the
loader of that release took as raw bytes — a working key then, and a string today's validator
refuses; and, for five days in September 2025, base64 of thirty-two printable characters in the
example configuration of the counter-mode provider that no longer exists, which the loader of
that release took as a key encryption key and today's validator refuses on the same
printable-only rule. All five are to be treated as compromised: any deployment that ever ran
under one re-writes its data under a new key before the old provider is removed. Deleting them
from the tree does not un-publish them.

**The build context names what it keeps out.** It excludes the generated environment file and
the token file a workstation may still hold from the licensed releases (ADR 0016), which
grants nothing and still names its licensee. The wildcard rules beside them reach only the
root of the tree, so it is a rule naming the path that keeps a file out of the configuration
directory the image copies whole; a key placed in that directory needs its own rule.

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

**The same material sat in the example configurations**, and those are not documentation.
They are live fixtures: the demo stack mounts two of them as the running proxies'
configuration, integration tests load one directly to start a proxy instance, and monitoring
targets pass another on the command line. One key appeared in three of those files, so a
single copy-paste put the same repository-public key on three deployments. Most of those
files carried a commented-out environment-variable form beside the literal — which is
exactly the point: a comment recommending the safe shape is documentation, and the threat
model's own rule is that a control which exists only in documentation is worse than no
control, because it gets relied upon.

**The precedent had already been set once.** The test certificate authority's private key
had been committed. It was made untracked and generated on demand, and the decision went one
step further than deleting the key: only the generator stays tracked, because a tracked
certificate stops matching a key that a fresh clone generates, and a mismatched pair fails in
a way nobody attributes to the checkout.

## Decision

**D1.** No working key material is tracked in this repository. Not a key-encryption key, not
a private key of any kind, not a test certificate authority key — in no
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

**D5.** Published key material is not un-published by deleting it. Any deployment that ever
ran under a key that appeared in this repository treats every object written under it as
compromised: configure a new key, re-write the data through the proxy, and only then remove
the old provider (ADR 0002).

**D6.** User-facing documentation shows an environment reference and names the generator that
produces a key. No document, example or default in this product ever prints a usable key.

## Consequences

- **A clean clone cannot bring the demo up by hand.** Starting the stack without the
  bring-up step fails on a missing key. That is the price of not publishing keys, and it
  makes the bring-up scripts the only supported entry point.
- **A generator, and every call site of it, is maintained code.** Its call sites are the demo
  bring-up, the end-to-end bring-up, continuous integration and the two monitoring targets,
  and any new environment has to remember to add its own.
- **Operators who installed the chart with its defaults before 3.8.56 are broken by the
  upgrade**: it
  refuses to start until they supply a key, and the objects they already wrote are encrypted
  under a public key and must be re-written. That is the correct outcome, but it shipped as
  an ordinary fix rather than as a headline of the next major release, so the warning lives
  in the security documentation instead of in release notes anyone reads.
- **The history keeps the keys.** Removing a literal at the tip does not retract it. Every
  key this repository has ever contained stays retrievable, which is why D5 is rotation and
  not deletion.
- **Generated fixture keys are as durable as a working copy.** Deleting the generated file
  makes the objects a demo stack wrote before it unreadable — the same property production
  has, arrived at by accident rather than by procedure.
- **A generated key is a precondition of every target that starts a proxy from an example
  configuration.** The monitoring targets that load one call the generator themselves, keeping
  a key that is already there, so the "just run it" property holds for them — at the cost of
  two call sites that have to keep calling it. A target that forgets is not broken loudly; it
  starts under whatever the environment happens to hold, or refuses on a missing variable.
- **Test fixtures get no key material for free.** A test that starts a proxy from an example
  configuration needs generated material; for an asymmetric key that costs nothing, because no
  provider takes one (ADR 0004).

## Alternatives Considered

**Keep working keys in the example configurations.** They are fixtures, the demo stack is local
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

## Residual risks

- **What is still in the tree is test fixtures and the conformance runner's default.** Working
  256-bit keys sit in the unit and integration tests, and one in the conformance runner; one of
  the fixture keys this repository also published outside the tests. They are public as of the
  day they were committed, not as of the day anything is removed, and D5 governs any deployment
  that ever ran under one.
- **Nothing enforces D1 mechanically, and this is verified rather than suspected.** No step of this project's own pipeline scans for secrets on a push or a pull
  request; whether the hosting platform applies its own push protection is outside the tree and
  is still unverified. The rule holds by review, which is the same class of control the decision
  itself calls insufficient — and the fixture keys above are what a review missed.
- **Not verified: whether any deployment ever ran under the published chart default or under
  an example key.** The assumption must be that at least one did; D5 is written for that case.
- **Not verified: whether a locally built image that carried a license token of the licensed
  releases was ever pushed anywhere.** The token grants nothing (ADR 0016) and still
  names its licensee. What was verified is only the negative side — no token and no signing key
  was ever committed, and published images came from a checkout without one.
- **Generated fixture keys are never rotated** and live as long as a working copy does.
  Accepted for throwaway local stacks; it is not a model for anything an operator runs.

## References

- ADR 0002 — *One data key per object, wrapped by a configured key encryption key* — the
  rotation procedure D5 refers to.
- ADR 0004 — *One local key provider: 256 random bits, an authenticated wrap, no passphrases*
  — what counts as a valid key and which generator produces one.
- ADR 0005 — *A KMS-backed key encryption key is a provider, not a mode* — custody in a key
  management service, versus the custody-by-injection that `${S3EP_AES_KEY}` gives today.
- ADR 0013 — *A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start* — why an unset key variable is a startup failure rather
  than a default.
- ADR 0016 — *The proxy is licensed under Apache 2.0 and checks no license* — why no token and
  no signing key exists to be kept out of the tree.
- ADR 0019 — *Integration and end-to-end tests are the product; they are never skipped* — why
  the fixtures are generated rather than deleted.
- [README.md](../../README.md) — key generation and the demo bring-up steps
- [docs/operations/configuration.md](../operations/configuration.md) — the `${VAR}` references and the
  variables the shipped image reads.
- [docs/security/operational-security.md](../security/operational-security.md) — the published
  chart default, and what an operator does if a deployment ran under it.
