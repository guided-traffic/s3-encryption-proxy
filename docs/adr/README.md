# Architecture Decision Records

Every durable design decision of this proxy lives here, one file per decision family. An ADR
records **what was decided, why, what was rejected, and what it costs** — so a later change can
argue with the decision instead of rediscovering it.

**An ADR is not a ticket.** A ticket is a work list: it exists while work is outstanding and is
**deleted** when the work lands. An ADR is the decision behind that work and stays. Nothing
outside `docs/tickets/` may reference a ticket — not the README, not the security architecture,
not a code comment, not a commit message. ADRs may be referenced from anywhere.

## Format

Filename: `NNNN-kebab-case-title.md`, numbered in the order they were written.

Sections, in this order:

| Section | Content |
|---|---|
| `# ADR NNNN: Title` | The decision as a title, not a topic |
| `## Status` | `Accepted` / `Superseded by ADR NNNN` / `Amended`, plus `Date:` and what is implemented versus still open |
| `## Context` | The forces and the concrete failure that made the decision necessary |
| `## Decision` | `D1 … Dn`, each a rule that holds going forward, in present tense |
| `## Consequences` | What this costs, including the parts nobody likes |
| `## Alternatives Considered` | Each option and why it lost |
| `## Residual risks` | Accepted risks, open items, and what was **not** verified |
| `## References` | Sibling ADRs and user-facing documents |

## Ground rules

- **English only.**
- **A decision, not an implementation.** An ADR states what the product does and why. It carries
  **no references into the code**: no file paths, no line numbers, no function, type or package
  names, and no links into the tree. A reader must be able to act on the decision without opening
  the repository, and the ADR must not go stale when a file is renamed.
- **The product's own vocabulary is not a code reference.** Configuration keys
  (`encryption.integrity_verification`), stored metadata keys (`s3ep-kek-fingerprint`), S3 error
  codes (`InvalidObjectState`), header names and algorithm names are the interface the decision is
  about. Name them exactly.
- **Say what is decided, and separately what is built.** The `Status` section carries the
  implementation state; the `Decision` section is written in the present tense either way.
- **Mark what was not verified.** An assumption never travels as a fact.

## Keeping them current

**An ADR is part of the product, not a historical note.** When a decision changes, the ADR is
updated in the same change — the `Decision` section states the new rule, the `Status` section
records the amendment with its date, and the superseded rule is marked in place rather than
deleted. A reader must never find the old rule stated as current.

## Index

### Foundations

| ADR | Decision |
|---|---|
| [0001](0001-the-backend-is-hostile.md) | The S3 backend is an adversary; only the proxy's own verification counts, and integrity is not configurable |
| [0006](0006-the-proxy-serves-any-s3-client.md) | Any S3 client is in scope; compatibility is argued from S3 semantics, never from one observed client |

### Stored format

| ADR | Decision |
|---|---|
| [0002](0002-one-data-key-per-object.md) | One random data key per object, wrapped by the configured key encryption key and carried in the object's own metadata |
| [0003](0003-objects-are-an-authenticated-segment-chain.md) | Objects are a chain of AES-256-GCM segments plus an authenticated trailer; no byte is served unverified |
| [0004](0004-one-local-key-provider.md) | One local key provider: base64 of 32 random bytes, an authenticated wrap, a derived fingerprint, no passphrases |
| [0005](0005-a-kms-key-is-a-provider.md) | A key held in a KMS is a provider type of its own; delivering a local key from a secret store is not a KMS |
| [0009](0009-the-metadata-prefix-is-the-proxys-namespace.md) | The configured metadata prefix is the proxy's exclusive namespace: a client write into it is refused, and it never appears in a response |
| [0023](0023-filename-encryption-encrypts-directory-segments.md) | If filename encryption ships it encrypts directory segments only, deterministically, with no mapping index |

### The S3 surface

| ADR | Decision |
|---|---|
| [0007](0007-forward-it-or-refuse-it.md) | Forward it or refuse it with a named S3 error; never accept, discard and answer success |
| [0008](0008-every-response-describes-the-proxy.md) | Every response is composed by the proxy — status, code, headers and body — and never echoes the backend |
| [0010](0010-sizes-and-listings-describe-the-plaintext.md) | Every reported size and every listing describes the plaintext, computed without a per-object round trip |
| [0011](0011-the-proxy-owns-the-part-layout.md) | The proxy fixes the part layout it writes, refuses one it cannot verify, and refuses server-side copy |
| [0012](0012-client-checksums-are-verified-never-forwarded.md) | Client upload checksums are verified against the plaintext, never forwarded to the backend and never stored |

### Operation

| ADR | Decision |
|---|---|
| [0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) | A configuration key exists only if code reads it; an unworkable configuration refuses to start |
| [0014](0014-authentication-is-sigv4-no-rate-limiting.md) | SigV4 in both forms against static configured clients; no rate limiting and no per-address blocking |
| [0015](0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) | No wall clock on a transfer; only the header phase, the idle connection and shutdown are bounded |
| [0016](0016-the-license-is-a-startup-gate.md) | The license is a fatal startup gate, an explicit expiry claim is mandatory, and the expiry is discovered by a build |
| [0021](0021-key-material-is-generated-never-committed.md) | No working key material or license token in the repository: generated on demand, injected through the environment |

### Process

| ADR | Decision |
|---|---|
| [0017](0017-stored-data-compatibility-is-not-owed.md) | No compatibility is owed for data at rest; a major release may break the format, with re-upload as the migration |
| [0018](0018-a-major-release-is-declared-by-a-label.md) | Releases are computed from the commits that reach `main`; a major requires a deliberate label on the pull request |
| [0019](0019-integration-and-e2e-tests-are-the-product.md) | The integration and end-to-end suites are part of the product and are never skipped, weakened or disarmed |
| [0020](0020-performance-is-measured-before-and-after.md) | Every performance claim carries a before-and-after measurement; the gate is a ratio, never an absolute number |
| [0022](0022-tickets-are-work-lists-that-get-deleted.md) | Tickets are deleted when the work lands; every durable decision lives in an ADR, and nothing outside the ticket directory cites a ticket |

## Related documents

* [README.md](../../README.md) — user-facing reference
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model, trust boundaries and the hardening checklist
* [CLAUDE.md](../../CLAUDE.md) — project conventions, the ticket lifecycle and the ADR obligation
