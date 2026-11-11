# Tickets: 036 High Availability

> 7 nodes · cohesion 0.33

## Key Concepts

- **Pin as Address with Instance Identity (Decision 9)** (3 connections) — `docs/tickets/036-high-availability.md`
- **Store-Clock Idle Sweep by Compare-and-Set (Decision 10)** (3 connections) — `docs/tickets/036-high-availability.md`
- **Row Completion State Machine (open/completing/completed/dead) via CAS** (2 connections) — `docs/tickets/036-high-availability.md`
- **Held Short Part Stays with its Holder** (2 connections) — `docs/tickets/036-high-availability.md`
- **Idle Clock vs Lease (two clocks, two owners)** (2 connections) — `docs/tickets/036-high-availability.md`
- **Peer Listener for Forwarded Complete** (2 connections) — `docs/tickets/036-high-availability.md`
- **Shutdown Lets Go, Aborts Only What Dies with the Process (Decision 13)** (2 connections) — `docs/tickets/036-high-availability.md`

## Relationships

- [ADR Corpus and Release History](ADR_Corpus_and_Release_History.md) (2 shared connections)

## Source Files

- `docs/tickets/036-high-availability.md`

## Audit Trail

- EXTRACTED: 9 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*