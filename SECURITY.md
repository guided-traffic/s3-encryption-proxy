# Security policy

## Reporting a vulnerability

Report privately. Do not open a public GitHub issue and do not describe the
problem in a pull request.

- Open a **private security advisory** on
  <https://github.com/guided-traffic/s3-encryption-proxy/security/advisories/new>.
  This is the preferred route and reaches the maintainers without disclosing the
  issue.
- If that page is not available to you, open a GitHub issue that says only that
  you have a security report and asks for a private channel — **no details** —
  and wait for a maintainer to open one.

> **Gap, stated plainly:** this repository carries no dedicated security contact
> and no published disclosure window. [CONTRIBUTING.md](CONTRIBUTING.md) points
> at issues and discussions, both public. The advisory form above is the only
> private route, and it has not been exercised.

Please include: the version or commit, the configuration that reproduces it
(**with every key and credential redacted**), what you observed, and what you
expected. A proof of concept against the local demo stack (`./start-demo.sh`) is
the most useful form, because it can be replayed without touching production
data.

## What is already known

The security design of this product, including the gaps it does not close, is
documented under [docs/security/](docs/security/). Anything written there is
known — a report that adds a working exploit, a wider consequence, or a case the
analysis missed is still valuable. Anything that is **not** written there is
what we most want to hear about.

## Supported versions

Fixes land on `main` and ship in the next release. There is no long-term support
branch and no backport of a fix to an earlier major release; stored-object
compatibility across a major release is not owed either (ADR 0017).
