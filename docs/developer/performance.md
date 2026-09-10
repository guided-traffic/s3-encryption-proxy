# Performance

The rule is [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md):
**measured before and after, never asserted.** A performance claim without two
recorded columns is an opinion.

The instrument set and how to run it are documented where they live:
[`test/perf/README.md`](../../test/perf/README.md). That page has the commands,
the environment traps and what each target measures. This page is the part that
is easy to get wrong.

## Before you change a hot path

Record the before column first. Not after the change, not from memory, not from
an earlier run on a different day — the whole value of the number is that the
only thing that differs between the two columns is your change.

Recorded runs live in `perf-baseline/<timestamp>-<commit>/`. They are committed,
so a comparison can be reconstructed later.

## What ruins a comparison

**A different power source.** A laptop on battery throttles. If the before column
was recorded on mains, the after column has to be too, or the numbers are noise
wearing a lab coat.

**A different Go toolchain.** Coverage data and benchmark timings both shift
between releases. The Makefile pins the toolchain from the Containerfile for
exactly this reason.

**A cold-versus-warm proxy.** The resident-memory figure is only cold once.
Restart the proxy containers before a run you intend to keep.

**Other suites competing for the backend.** The performance suite runs alone;
that is why the Makefile has a separate target for it.

## What the instrument can and cannot separate

The three-leg upload comparison writes the same object three ways: straight to
the backend, through a proxy on the single-request write path, and through a
proxy on the internal multipart producer. It exists to separate the pipeline's
cost from the cipher's — and it is what falsified the theory that the multipart
deficit came from the self-copy, by showing the streaming proxy beating the
backend it was writing to.

The second leg needs a proxy configured to take the single-request path at sizes
the first proxy would route to multipart. **That lever is
`optimizations.streaming_segment_size`** — set it large and everything routes to
one `PutObject`. (It used to be `integrity_verification`, which no longer routes
anything; if you find that recipe in a comment, it is stale.)

What the instrument **cannot** do is attribute a change to one commit when
several landed together. The 5.0.0 format change, the producer restructuring and
the removal of the self-copy are in one commit, so a before/after across them
measures the release, not any one of them. Say so in the report rather than
implying an attribution the numbers do not support.

## Reporting

State what was measured, on what machine, against which recorded column, and what
the instrument could not separate. A number without those four is not reusable by
the next person.
