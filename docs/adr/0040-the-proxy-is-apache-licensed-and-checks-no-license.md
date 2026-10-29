# ADR 0040: The proxy is licensed under Apache 2.0 and checks no license

## Status

**Accepted.** Date: 2026-10-29.

Implemented in the change that wrote this record: the source is under the Apache License 2.0,
the binary verifies no token, the license generator and its signing key are gone from every
build path, and no build, test suite or pipeline job asks for a token. **Supersedes ADR 0016
as a whole.** Amends ADR 0013 D13, ADR 0021 D1, D5 and D6, ADR 0025 D2 and ADR 0030 D4; each
of those records marks the superseded rule in place.

Released as a **minor** release, decided by the owner on 2026-10-29: D3 keeps the one key
whose removal would have broken an existing configuration, so nothing in this change carries
a breaking marker (ADR 0018 D5).

**Verified 2026-10-29: the owner is the only human author in the history of `main`.** Every
other commit author is a bot — the release automation, the dependency updater and the
organisation's automation account. Relicensing therefore needed no other contributor's
consent.

## Context

Until this record the proxy was published under the Business Source License 1.1, with no
additional use grant and a change license of AGPL-3.0-only four years after each minor
release. The license was enforced in the product: every provider type except `exit` refused
to start without a signed token, a running proxy re-checked the token hourly and shut down
when it expired, the metrics endpoint exported its validity and expiry, the chart shipped two
alerts and two dashboard panels on them, and every integration, conformance and end-to-end
job read the token from a repository secret.

The owner decided that the commercial license was a mistake and that the product is free for
everyone. The gate it enforced cost more than it protected:

- **An expired token was a full outage of the data path.** New encryption stopped, and so did
  reading anything written under an encrypting provider, until an operator either installed a
  new token or switched the active provider to `exit` (ADR 0016 D12). For a product whose
  job is to keep data available *and* encrypted, a calendar date that could switch both off
  was the largest availability risk it carried.
- **Every test path depended on a secret.** A fork could not run the suites, a fresh
  workstation could not reach the "done" bar without a token supplied out of band, and the
  release pipeline carried a clock that ADR 0016 D8 wanted turned into a release blocker.
- **It needed custody of a signing key** whose loss would have made every shipped binary
  unlicensable, and whose custody was never verified (ADR 0016, ADR 0021).

## Decision

**D1.** The source of this project is licensed under the Apache License, Version 2.0. The
license file at the repository root is the unmodified Apache text; the published container
image carries `org.opencontainers.image.licenses=Apache-2.0`.

**D2.** Nothing in the product checks a license. No provider type is gated, nothing expires,
the binary carries no trust anchor for a token and verifies none, and no tool to mint one is
built or shipped. `S3EP_LICENSE_TOKEN` is not read. No build target, test suite, bring-up
script or pipeline job needs a token, and none supplies one.

**D3.** `license_file` stays an accepted configuration key until the next major release, which
removes it. It has no default and nothing reads the file it names; a configuration that
writes it starts and logs a warning at startup that names the key as ignored. This is the one
key that exists without code reading it for its purpose (ADR 0013 D1), and the one
compatibility shim of the kind ADR 0013 rejects for removed keys; both exceptions end with
that major.

**D4.** No metric, status field or chart object describes a license. `s3ep_license_info` and
`s3ep_license_expiry_timestamp` are not exported, `/status` has no `license` member, and the
chart ships neither the `S3EPLicenseExpiringSoon` and `S3EPLicenseExpired` alerts nor the
license panels of its dashboard. The chart values `license.jwt`, `license.existingSecret`,
`license.existingSecretKey` and `monitoring.prometheusRule.license.warnDays` are gone; the
chart has no values schema, so a values file that still sets them renders as if it did not.

**D5.** The exit provider keeps the reason ADR 0025 gives for it — leaving encryption without
losing what was encrypted — and loses the one this record removes. Its exemption from the
gate is moot because there is no gate.

## Consequences

- Anyone may run, modify and redistribute the proxy under the Apache 2.0 terms, commercial
  use and offering it as a hosted service included. The product has no revenue control left,
  and this is the intent.
- An expiry can no longer stop the data path. The availability property ADR 0016 D12
  documented, and the operator procedure it required, are gone with it.
- A dashboard or alert an operator built on the license series stops receiving data. A rule
  of the shape the chart used to ship — a comparison against the series — goes silent rather
  than firing; a rule written with `absent()` fires once and keeps firing until it is deleted.
- A configuration copied from an earlier example still carries `license_file` and starts with
  a warning. When the next major release removes the key, such a configuration refuses to
  start by the generic unknown-key message (ADR 0013 D11); the warning is the only notice the
  operator gets before then.
- The repository secret that held the token is unused. Deleting it is an action in the
  repository settings and is not part of any change to the tree.
- No NOTICE file exists, so a redistributor's obligation under section 4 of the license is the
  license text and the notices already in the source.

## Alternatives Considered

**Remove `license_file` outright, in a major release.** The cleaner end state, and what
ADR 0013 D1 asks for. Rejected by the owner on 2026-10-29: the loader refuses an unknown key,
so every configuration written for the licensed releases would stop starting, which is a
breaking change under ADR 0018 D5 and spends a major release on a key that does nothing. A
major would also have opened its notes with the banner the release configuration puts on
every major — that objects written by an earlier release cannot be read — which is false for
this change, since the stored format does not move.

**Keep the Business Source License and drop only the gate.** Removes the outage risk and keeps
the restriction on production use in the license text. Rejected: the product is meant to be
free for everyone, and a license that forbids production use without a grant is not that.

**A license other than Apache 2.0.** A permissive license without an explicit patent grant,
or the AGPL the Business Source License would have converted to. The owner named Apache 2.0;
its explicit patent grant and its acceptance in infrastructure software are why it was not
reopened.

**Keep the license code dormant**, unreferenced but in the tree, in case the decision is ever
reversed. Rejected: code nothing reads is what ADR 0013 and the project rule against
backward-compatibility code remove, and reversing this decision would be a new decision with
its own design rather than a revert.

## Residual risks

- **Not decided here: the license of releases published before this record.** Their tags keep
  the license file they shipped with. Whether the owner also offers them under Apache 2.0 is
  the owner's statement to make and is not recorded in this repository.
- **Images published before this record carry `BSL-1.1` as their license label.** A registry
  scan that reads the label reports the old license for those tags; only images built from
  this change on carry the new one.
- **Old tokens stay on workstations.** A token file left in the local configuration directory
  is still ignored by version control and by the image build, and it still names the licensee
  it was issued to. Nothing deletes it.
- **The warning of D3 is a log line.** An operator who does not read startup logs learns about
  the key only when the next major release refuses it.

## References

- ADR 0016 — *The license is a startup gate with an explicit expiry* — the decision this record
  supersedes, kept as the history of why the gate existed and what it cost.
- ADR 0013 — *A configuration key exists only if code reads it* — the rule D3 is a time-limited
  exception to, and D13, which bound `license_file` to the one file read.
- ADR 0018 — *A major release is declared by a label* — why removing the key would have been a
  major release.
- ADR 0021 — *Key material and licenses are generated, never committed* — the token and
  signing-key rules this record ends.
- ADR 0025 — *Leaving is a supported mode* — the exit provider, which no longer needs an
  exemption.
- ADR 0030 — *The network boundary belongs to the administrator* — D4, which kept the licensee
  off the scrape and is moot now that no license series exists.
- [LICENSE](../../LICENSE) — the license text.
- [README.md](../../README.md) — the operator-facing summary.
