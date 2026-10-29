# ADR 0016: The proxy is licensed under Apache 2.0 and checks no license

## Status

**Accepted.** Date: 2026-10-29.

Built: the source is under the Apache License 2.0, the binary verifies no token, no license
generator or signing key exists in any build path, and no build, test suite or pipeline job asks
for a token. D3 keeps `license_file` decodable, so the change ships as a minor release (ADR 0018
D5), decided by the owner.

Verified 2026-10-29: the owner is the only human author in the history of `main`; every other
commit author is a bot — the release automation, the dependency updater and the organisation's
automation account. Licensing the source under Apache 2.0 needed no other contributor's consent.

## Context

The proxy encrypts data at rest for any S3 client, and the owner wants it to be free for
everyone. A license check inside such a product costs more than it protects:

- **An expiry is an outage of the data path.** A product whose job is to keep data available
  *and* encrypted cannot carry a calendar date that switches off new encryption and, with it,
  every read of what was encrypted before.
- **Every test path depends on a secret.** A fork cannot run the suites, a fresh workstation
  cannot reach the "done" bar of ADR 0019 without a token supplied out of band, and the release
  pipeline carries a clock.
- **It needs custody of a signing key** whose loss makes every shipped binary unlicensable.

Releases up to 5.1 were published under the Business Source License 1.1 and refused to start an
encrypting provider without a signed token. Configurations written for them may carry
`license_file`, which is what D3 is about.

## Decision

**D1.** The source of this project is licensed under the Apache License, Version 2.0. The
license file at the repository root is the unmodified Apache text; the published container
image carries `org.opencontainers.image.licenses=Apache-2.0`.

**D2.** Nothing in the product checks a license. No provider type is gated, nothing expires,
the binary carries no trust anchor for a token and verifies none, and no tool to mint one is
built or shipped. `S3EP_LICENSE_TOKEN` is not read. No build target, test suite, bring-up
script or pipeline job needs a token, and none supplies one.

**D3.** `license_file` stays an accepted configuration key until the next major release, which
removes it. It has no default and nothing reads the file it names; a configuration that writes
it starts and logs a warning at startup that names the key as ignored. It is the one key that
exists without code reading it for its purpose, and the one compatibility shim of the kind
ADR 0013 rejects for removed keys; both exceptions end with that major (ADR 0013 D13).

**D4.** No metric, status field or chart object describes a license. The proxy exports no
`s3ep_license_*` series, `/status` has no `license` member, and the chart ships no license
alert, no license dashboard panel and no `license.*` value. The chart has no values schema, so a
values file that still sets `license.jwt`, `license.existingSecret`, `license.existingSecretKey`
or `monitoring.prometheusRule.license.warnDays` renders as if it did not.

## Consequences

- Anyone may run, modify and redistribute the proxy under the Apache 2.0 terms, commercial use
  and offering it as a hosted service included. The product has no revenue control, and this is
  the intent.
- Nothing on a calendar can stop the data path, and no provider type needs anything beyond its
  configuration entry to start — the exit provider included (ADR 0025).
- A dashboard or alert an operator built on the `s3ep_license_*` series of an earlier release
  receives no data. A rule that compares against the series goes silent; a rule written with
  `absent()` fires and keeps firing until it is deleted.
- A configuration copied from an earlier example still carries `license_file` and starts with a
  warning. When the next major release removes the key, such a configuration refuses to start by
  the generic unknown-key message (ADR 0013 D11); the warning is the only notice before then.
- No NOTICE file exists, so a redistributor's obligation under section 4 of the license is the
  license text and the notices already in the source.

## Alternatives Considered

**Remove `license_file` outright, in a major release.** The cleaner end state, and what ADR 0013
D1 asks for. Rejected by the owner: the loader refuses an unknown key, so every configuration
written for the licensed releases would stop starting, which is a breaking change under ADR 0018
D5 and spends a major release on a key that does nothing. A major would also open its notes with
the banner the release configuration puts on every major — that objects written by an earlier
release cannot be read — which is false here, since the stored format does not move.

**Keep the Business Source License and drop only the check.** Removes the outage risk and keeps
the restriction on production use in the license text. Rejected: the product is meant to be free
for everyone, and a license that forbids production use without a grant is not that.

**A license other than Apache 2.0.** A permissive license without an explicit patent grant, or
the AGPL the Business Source License would have converted to. The owner named Apache 2.0; its
explicit patent grant and its acceptance in infrastructure software are why it was not reopened.

**Keep the license code dormant**, unreferenced but in the tree. Rejected: code nothing reads is
what ADR 0013 and the project rule against backward-compatibility code remove.

## Residual risks

- **Not decided: the license of releases up to 5.1.** Their tags keep the license file they
  shipped with. Whether the owner also offers them under Apache 2.0 is the owner's statement to
  make and is not recorded in this repository.
- **Images published for 5.1 and earlier carry `BSL-1.1` as their license label.** A registry
  scan that reads the label reports the old license for those tags.
- **Old tokens stay on workstations.** A token file left in the local configuration directory is
  still excluded from version control and from the image build context, and it still names the
  licensee it was issued to. Nothing deletes it.
- **The repository secret `S3EP_LICENSE_TOKEN` still exists** and is read by no job. Deleting it
  is a change to the repository settings, outside the tree.
- **The warning of D3 is a log line.** An operator who does not read startup logs learns about
  the key only when the next major release refuses it.

## References

- ADR 0013 — *A configuration key exists only if code reads it* — the rule D3 is the one
  exception to, written down there as D13.
- ADR 0018 — *A major release is declared by a label* — why removing the key would have been a
  major release.
- ADR 0019 — *Integration and end-to-end tests are the product* — the "done" bar no secret
  stands in front of.
- ADR 0021 — *Key material is generated, never committed* — the key-material rules that remain.
- ADR 0025 — *Leaving is a supported mode* — the exit provider.
- [LICENSE](../../LICENSE) — the license text.
- [README.md](../../README.md) — the operator-facing summary.
