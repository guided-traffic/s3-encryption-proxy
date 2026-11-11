# ADR 0040: The Go module path carries the release's major version

## Status

**Accepted.** Date: 2026-11-07.

Implemented with this decision: the module path is
`github.com/guided-traffic/s3-encryption-proxy/v5`, and every import inside the tree uses it.
An importer can require a release by its tag from 5.3.0 on; 5.0.0 to 5.2.1 stay unrequirable
(see *Consequences*). D2 is a step of the pull request that declares a major, and no check
enforces it (see *Residual risks*).

## Context

Releases are tagged `vMAJOR.MINOR.PATCH`, computed from the commits that reach `main`
(ADR 0018), and the line has been past major 1 since 2.0.0 on 2025-09-15. Go's semantic import
versioning requires a module released at major 2 or above to end its module path in `/vN`, with
N the major. The module path never carried that suffix.

On 2026-11-06 another Go program imported the proxy's encryption packages to write objects in
the proxy's stored format, and met both consequences:

- **No release can be required by its tag.** `go get github.com/guided-traffic/s3-encryption-proxy@v5.2.1`
  is refused, and so is the same version under the `/v5` path: *module declares its path as:
  github.com/guided-traffic/s3-encryption-proxy but was required as:
  github.com/guided-traffic/s3-encryption-proxy/v5*.
- **A commit can be required, under a version the project never released.** The Go tool names
  the commit with a pseudo-version derived from the newest tag it accepts for the unsuffixed
  path, which is the last 1.x tag, 1.24.1. Release 5.2.1 therefore appears in the importer's
  dependency list as `v1.24.2-0.<timestamp>-<commit>`. The importer cannot read which release
  it builds against, and a dependency bot cannot offer it the next one.

Nothing the proxy ships depends on the module path. The binary, the image, the chart and the
version stamp do not carry it.

## Decision

**D1.** The module path ends in `/vN`, where N is the major version of the release line that
`main` builds: `github.com/guided-traffic/s3-encryption-proxy/v5` for 5.x. Every import inside
the tree uses that path.

**D2.** A pull request that declares a major with `release:major` (ADR 0018 D4) moves the
suffix to the new major in the same pull request. The first tag of a new line resolves for an
importer, and no major is cut with the previous line's suffix.

**D3.** Adding the suffix to a line that lacked it is not a breaking change, and it ships as a
minor release on that line. Before the change no release could be required by its tag, and a
requirement by pseudo-version still resolves at the commit it names. So nothing that worked
stops working. ADR 0018 D5 defines a break as stored data, an existing configuration or a
client-visible answer, and the module path is none of these.

## Consequences

- An importer requires a release by its tag, under the `/v5` path, from 5.3.0 on.
- Releases 5.0.0 to 5.2.1 stay unrequirable by tag. Their module declarations lack the suffix,
  and a published tag is not moved (ADR 0018).
- Every major release rewrites every import line inside the tree. The pull request of a major
  carries about one hundred and fifty files of mechanical change. Review that part as a counted
  replacement, not file by file.
- An importer crosses a major by rewriting its own imports. That is Go's mechanism, and here it
  is wanted. A major is where stored-data compatibility may end (ADR 0017), and an importer that
  writes objects in the proxy's format has to notice that.
- A program that already requires the unsuffixed path by pseudo-version keeps building at the
  commit it names. Moving forward means switching to the `/v5` path.
- Under ADR 0018 D5 a change to the Go interface of an importable package is not a break. A
  minor release can therefore stop compiling against an importer's code. An importer pins an
  exact version and moves deliberately.

## Alternatives Considered

**Move to `/v6` in a major release now.** Rejected, because nothing breaks (D3). A major also
costs every operator the reading of its notes. Under ADR 0017 it also announces a break in the
stored format, and this change does not make one.

**Keep the unsuffixed path, and let importers require a commit.** Rejected. The importer's
dependency list then names a version this project never released, and no update tool can
propose the next release.

**A separate module for the importable packages, versioned on its own.** Rejected. It means a
second release line with its own tags and its own changelog, and the proxy would require its own
format code across a module boundary. Two versions of that code could then build into one
program, and there is exactly one stored format (ADR 0003).

**Tag in a form Go accepts for an unsuffixed path (`v0`/`v1`).** Rejected. The release numbers
belong to the product and are computed from its commits (ADR 0018 D1). The module path follows
them.

## Residual risks

- **D2 is a convention, not a check.** A major cut without moving the suffix produces a tag that
  no importer can require, and the next release corrects it. A check could compare the suffix
  with the major that the release dry run computes on every pull request (ADR 0018 D6). None
  exists.
- **The Go interface of the importable packages is not a compatibility promise** (see
  *Consequences*). ADR 0041 D8 applies the same rule to the client library, the one package
  written for importers.
- **Verified with the 5.3.0 tag.** The public module proxy and the checksum database resolve
  `github.com/guided-traffic/s3-encryption-proxy/v5@v5.3.0`, and an importing module builds
  against it. Before the tag existed, a file-based module proxy had shown the same for the
  changed tree, and had shown the Go tool refusing the 5.2.1 tag under the `/v5` path with the
  message quoted in *Context*.

## References

- ADR 0018 — A major release is declared by a label (D4 the label, D5 what a break is, D6 the
  dry run)
- ADR 0017 — Stored data compatibility is not owed
- ADR 0003 — Objects are an authenticated segment chain; one stored format
- ADR 0041 — The project ships a client library for its stored format
- [DEVELOPER.md](../../DEVELOPER.md) — the steps that move the suffix in a major's pull request
