# ADR 0024: An upload forwards while it receives

## Status

**Accepted.** Date: 2026-09-10. **Implemented the same day** on the 5.0.0 branch, in the change
that rewrote the write paths for the segment chain (ADR 0003) and the part layout of ADR 0011.
The producer reads plaintext into a bounded pool of buffers and the upload workers seal while
they send, so receiving, sealing and sending overlap.

**Measured 2026-09-11** (`perf-baseline/20260911T103132Z-cc62c05/`, against the before column
`perf-baseline/20260910T090543Z-530472c/`, same machine and power source). The three-leg
comparison moved where this decision said it would and nowhere else: the **multipart leg** gains
34 %, 33 %, 47 % and 44 % at 16, 24, 64 and 256 MiB, while the **single-request leg**, which
never enters the producer, is 0 to 8 % slower — the cost of the segment chain and of ADR 0012's
checksum verification. End to end the deficit the Context measures is closed: a proxy upload
was 46-72 % of the same client writing to the backend directly and is now 78-125 %.

D7's condition is met and an upload speed-up may now be stated, with the two limits ADR 0020's
record puts on it: nothing below roughly 15 % end to end is a claim at all, and the gain cannot
be attributed to this decision alone, because the format change, the producer restructuring and
the self-copy removal landed in one commit.

## Context

A proxy that streams is **faster than the backend it writes to**. Measured with the local baseline
suite (ADR 0020) on one machine, three legs writing the same object with the same client call: the
backend directly at 165 MiB/s, the proxy's streaming write path at 104 % to 112 % of it while
encrypting every byte and crossing loopback twice, and the same proxy's internal multipart path at
57 % to 70 %.

Everything the deficit could plausibly have been was measured and ruled out:

* **The second write.** The server-side rewrite that runs after every multipart completion was
  modelled as the whole cause and would have had to run at 231–372 MiB/s. Timed directly it runs at
  4826–7485 MiB/s — about a twentieth of the gap, not the whole of it.
* **The extra network hop.** The streaming path pays it too and is still faster than the direct leg.
* **The cipher.** It occupies 3.8 % to 6.1 % of the proxy's per-byte upload time; the segment
  chain's measured 1.75× is worth roughly two percent end to end.
* **The integrity pass** of the format being replaced: 7.7 % of the gap.

What remains is the shape of the producer, and a size sweep separates it from fixed cost. Comparing
the two proxy write paths against each other from 8 MiB to 256 MiB, the streaming path is 1.96×
ahead at one part, and the ratio settles at about 1.45× from roughly six parts upward. At 256 MiB
the three extra backend round trips — create, complete, and the rewrite — are amortised to a few
percent, while the deficit stays at 1.45×. **The cost is per byte, not per request.** It is the
serialisation itself: no byte of a part moves towards the backend until the last byte of that part
has arrived and been encrypted.

The segment chain removes the reason parts had to be encrypted in sequence, and it deletes the
post-completion rewrite. Neither addresses the serialisation. A write path that still materialises
a whole part before sending it would keep the ratio near 59 %, and the release would ship a faster
cipher with nothing measurable at the edge.

## Decision

**D1** An upload forwards bytes towards the backend while it is still receiving them. No write path
waits for a complete object, or a complete part, before it begins sending that unit.

**D2** Receiving the next part overlaps sending the current one. The producer never blocks on an
upload it has already dispatched.

**D3** Encrypting a part never serialises the pipeline. Segments are independent (ADR 0003), so
parts are encrypted concurrently with the transfers of other parts.

**D4** The memory this puts in flight is bounded and configured, never implied: the number of parts
in flight is `optimizations.multipart_upload_concurrency`, each of `optimizations.streaming_segment_size`,
and that product is what an operator budgets against the container limit. Overlapping transfers may
not raise the bound.

**D5** A part stays retriable. The proxy retains a part until the backend has acknowledged it, and
replays it from that retained copy on a retry; it never asks the client for the same bytes twice.
Overlap therefore buys latency, not memory.

**D6** This restructuring ships in 5.0.0, with the format change, not after it. The write paths are
being rewritten for the segment chain in the same release, and a path that is rewritten once is
measured once.

**D7** No upload speed-up is claimed for the release until the three-leg comparison has been re-run
after the restructuring and has moved (ADR 0020). The measurement to repeat is that comparison, not
a crypto benchmark.

## Consequences

* The producer becomes a pipeline with a retained, bounded window instead of a loop over
  materialised parts. That is more concurrency in the most correctness-sensitive path the proxy has,
  and it is being introduced in the same release that replaces the stored format.
* D5 keeps the memory profile of today: a part is held until it is acknowledged either way. What
  changes is when the transfer starts, not how much is resident.
* The client-driven multipart path does not get the same treatment from this decision alone: there
  the client dictates part boundaries and arrival order, and the part it uploads is the unit the
  proxy receives. D1 still binds it — the part is forwarded as it arrives rather than materialised
  first — but no cross-part overlap is promised.
* Single-`PutObject` uploads already satisfy D1 and are the evidence that the shape works: they are
  what measured above the backend.
* The three-leg instrument now carries sizes above 16 MiB with the direct leg dropped, because the
  backend refuses an aws-chunked chunk that large and both proxies re-frame towards it. Those rows
  compare the two proxy paths with each other and carry no backend ratio.

## Alternatives Considered

**Raise the routing boundary instead, so more uploads take the single-`PutObject` streaming path.**
Cheap — a condition, in a handler the format change rewrites anyway — and the measurement says the
streaming path stays ahead to at least 256 MiB. It was not taken as the fix because it narrows the
problem instead of solving it: an upload whose length the client does not declare, and any object
beyond what a single `PutObject` can carry, stays on the slow path, and the whole measurement is
loopback, where a single stream is never latency-bound. It remains available as a routing decision
on its own merits, and is not one this ADR takes.

**Ship 5.0.0 without it and restructure in 5.1.** Rejected: the same code is being rewritten now for
the segment chain. Deferring means writing the path twice and measuring it twice.

**Accept 57–70 % of the backend on the multipart path.** Rejected. It is the path every large
upload from every client takes, and the release that rewrites it is the cheapest opportunity there
will be.

**Attribute the remaining cost with a blocking profile before deciding.** Not required for the
direction, and it is not free: no blocking profile is enabled anywhere in the product today. The
size sweep separates per-request from per-byte cost, which is what the decision turns on. The
profile stays the fallback if the restructuring does not move the measurement.

## Residual risks

* **The attribution is by substitution and by a size sweep, not by a profile.** If the rewrite does
  not move the three-leg comparison, the mechanism was misidentified and a blocking profile under
  this exact load is the next step, before any further change.
* **Every leg is loopback on one machine**, against a backend deliberately capped at two CPUs. On a
  real network with latency, concurrent part transfers may already hide part of the serialisation,
  and the measured gain may not transfer. Not verified.
* **The sizes from 24 MiB upward were first measured ad hoc**, with three to five repetitions on
  battery power. They are the reason the instrument was extended; the recorded before-column taken
  with the full repetition count is what a later comparison uses.
* **D5's retry path is a decision, not a design.** Replaying a retained part is not what the AWS SDK
  does on its own for a body it cannot rewind, so the retry belongs to the proxy and has to be built
  and tested deliberately.
* The interaction between D2's overlap and the short-part buffer bound of ADR 0011 has not been
  worked through: both hold parts in memory, and their sum is what an operator budgets.

## References

* [ADR 0003](0003-objects-are-an-authenticated-segment-chain.md) — segments are independent, which is
  what allows parts to be encrypted concurrently
* [ADR 0011](0011-the-proxy-owns-the-part-layout.md) — the part layout, the short-part buffer bound
  and the removal of the post-completion rewrite
* [ADR 0020](0020-performance-is-measured-before-and-after.md) — the measurement rules this decision
  was reached under, and the rule that no claim ships without a before and an after
* [ADR 0001](0001-the-backend-is-hostile.md) — why nothing may be served, or trusted, before the
  proxy has verified it
