# 033 — A deliberate out-of-band recovery path for a damaged object

Raised 2026-09-12, out of the discussion that produced ADR 0002 D13 — which
stored inputs are load-bearing for decryption, and why that set is kept as small
as it is. Recorded here so it is not lost; **not scheduled**.

## The requirement

Integrity verification stays as it is: on by default, not configurable, and a
failure aborts the transfer rather than delivering a byte the proxy has not
authenticated. That is the product and it does not move.

What is missing is the other half. Metadata or stored bytes can be damaged
without an attacker — a flipped bit at rest, a transmission error nobody noticed.
When the data is urgently needed, the owner may knowingly accept the risk and
want the ciphertext decrypted anyway, with whatever is recoverable recovered and
the damage reported. **The proxy must not do this**: it is not a serving path and
must never hand out an unauthenticated byte. It belongs in a separate tool, run
deliberately, by someone who has decided to buy the risk.

## What the design already gives it

Established while deciding D7, verified in the tree:

| Input | Where it comes from |
|---|---|
| The master key | the operator's configuration |
| `s3ep-encrypted-dek` | the object's metadata; the only metadata key that is cryptographically required |
| The object key | the object's own name, bound into every segment's associated data |
| The format id, the segment index | a constant, and the segment's position |

`kek-fingerprint` is only a selector — a tool can try every configured key
instead. `kek-algorithm` and `dek-algorithm` are descriptive. So a flipped bit in
any of those three costs a recovery attempt nothing, and keeping that property is
a constraint on future format work: **the set of cryptographically load-bearing
inputs stays as small as it is**.

Per-segment authentication is what makes partial recovery meaningful at all: each
segment carries its own tag, so damage is contained to the segment it hit and
every other segment still opens and verifies.

## What it cannot recover, and this is not solvable here

- **Damage inside `s3ep-encrypted-dek`.** The data key is gone; nothing recovers
  the object. The only defence would be a second copy of the wrap, which the
  format does not carry.
- **The master key.** Outside the tool's reach by definition.

## Open questions for whoever takes this

- Where it lives: a subcommand of an existing binary, or a tool of its own that
  never links the serving path.
- What it outputs: plaintext with the damaged ranges named and zero-filled, or a
  refusal plus a damage report, or both behind a flag.
- How the operator states consent, and how the run is made auditable.
- Whether it reads the configuration or takes the key on its own terms.
- What `SECURITY_ARCHITECTURE.md` has to say about a tool that deliberately
  serves unauthenticated bytes, and which residual risk it opens.
- Whether the decision — recovery is possible, out of band, never in the proxy —
  is an ADR of its own or an amendment to the record that owns the stored format.
