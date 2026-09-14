#!/usr/bin/env python3
"""Compare two performance baseline runs.

    ./test/perf/compare.py perf-baseline/<before> perf-baseline/<after>

Reads run.json from both and prints, per measurement, how the proxy moved.

Where a measurement has a direct-to-backend sibling, the verdict is formed from
the **ratio** proxy/direct within each run, not from the proxy's absolute median
(ADR 0020 D11). Absolute medians move with the machine: a laptop that thermally
throttles, a backend under a different load, a different power source all shift
both legs together, and the proxy's own cost is what the ratio isolates. The
reference leg's own move is printed beside it, because a reference that shifted
is what makes a ratio move without the proxy changing at all.

A change counts only when it clears the spread the two runs themselves showed
(ADR 0020 D21): the instrument's repeatability, not a fixed percentage, is what
decides whether a difference means anything.
"""

import json
import math
import sys
from pathlib import Path

UNSTABLE_RSD = 10.0
# The floor under the spread test. Two runs of the same commit on the same
# machine differ by a few percent with no code change at all, so a difference
# smaller than this is never reported as a change whatever the spread says.
NOISE_PCT = 3.0
# Subject that measures the backend without the proxy in the path.
REFERENCE_SUBJECT = "direct"


def load(path):
    p = Path(path)
    if p.is_dir():
        p = p / "run.json"
    with p.open() as fh:
        return json.load(fh)


def key(m):
    return (m["instrument"], m["transport"], m["operation"], m["subject"], m["size_bytes"])


def reference_key(k):
    return (k[0], k[1], k[2], REFERENCE_SUBJECT, k[4])


def human(n):
    if n <= 0:
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.0f} TiB"


def machine_line(run):
    h = run["hardware"]
    return (f'{h.get("cpu_model", "?")}, {h.get("cpu_physical", "?")} cores, '
            f'{h.get("go_version", "?")}, {h.get("power_source", "?")}')


def lower_is_better(unit):
    return unit in ("ns/op", "bytes", "s")


def combined_spread(*rsds):
    """The spread of a comparison, from the spreads that went into it."""
    return math.sqrt(sum(r * r for r in rsds if r))


def verdict(change, spread, unstable):
    """What a change of this size means against the noise that produced it."""
    if unstable:
        return "unstable"
    threshold = max(NOISE_PCT, spread)
    if abs(change) < threshold:
        return f"unchanged (±{threshold:.0f} % noise)"
    return "SLOWER" if change < 0 else "faster"


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    before, after = load(sys.argv[1]), load(sys.argv[2])

    if before["schema_version"] != after["schema_version"]:
        print("refusing to compare: different schema versions", file=sys.stderr)
        return 1

    mb, ma = machine_line(before), machine_line(after)
    print(f'before: {before["run"]["label"]}  {before["run"]["git"]["commit"][:12]}  {mb}')
    print(f'after:  {after["run"]["label"]}  {after["run"]["git"]["commit"][:12]}  {ma}')
    if mb != ma:
        print("\n!! different machines or power sources — these runs are not comparable")
    print()

    bmap = {key(m): m for m in before["measurements"]}
    amap = {key(m): m for m in after["measurements"]}

    rows = []
    for k in sorted(set(bmap) | set(amap)):
        b, a = bmap.get(k), amap.get(k)
        if b is None:
            rows.append((k, None, a, "only in after", ""))
            continue
        if a is None:
            rows.append((k, b, None, "only in before", ""))
            continue
        if not b["median"]:
            rows.append((k, b, a, "no before median", ""))
            continue

        sign = -1.0 if lower_is_better(a["unit"]) else 1.0
        unstable = b["rsd_pct"] > UNSTABLE_RSD or a["rsd_pct"] > UNSTABLE_RSD

        absolute = sign * (a["median"] - b["median"]) / b["median"] * 100
        rb, ra = bmap.get(reference_key(k)), amap.get(reference_key(k))
        paired = (k[3] != REFERENCE_SUBJECT and rb and ra
                  and rb["median"] and ra["median"] and rb is not b)

        if not paired:
            # No reference leg: the absolute number is all there is. The
            # reference rows themselves land here, and are reported as what
            # they are rather than counted as the proxy getting slower.
            if k[3] == REFERENCE_SUBJECT:
                rows.append((k, b, a, f"{absolute:+.1f} %  reference", ""))
                continue
            spread = combined_spread(b["rsd_pct"], a["rsd_pct"])
            rows.append((k, b, a, f"{absolute:+.1f} %  {verdict(absolute, spread, unstable)}", ""))
            continue

        # The proxy's cost against the backend it sits in front of, in each run.
        eff_b = b["median"] / rb["median"]
        eff_a = a["median"] / ra["median"]
        relative = sign * (eff_a - eff_b) / eff_b * 100
        spread = combined_spread(b["rsd_pct"], a["rsd_pct"], rb["rsd_pct"], ra["rsd_pct"])
        unstable = unstable or rb["rsd_pct"] > UNSTABLE_RSD or ra["rsd_pct"] > UNSTABLE_RSD
        reference_move = sign * (ra["median"] - rb["median"]) / rb["median"] * 100
        rows.append((
            k, b, a,
            f"{relative:+.1f} % of direct  {verdict(relative, spread, unstable)}",
            f"abs {absolute:+.1f} %, direct {reference_move:+.1f} %",
        ))

    width = max(len(" / ".join(str(x) for x in k[:4])) for k, _, _, _, _ in rows) if rows else 40
    for k, b, a, result, detail in rows:
        instrument, transport, operation, subject, size = k
        label = f"{instrument} / {transport} / {operation} / {subject}"
        bm = f'{b["median"]:.1f}' if b else "—"
        am = f'{a["median"]:.1f}' if a else "—"
        unit = (a or b)["unit"]
        print(f"{label:<{width}}  {human(size):>8}  {bm:>12} → {am:>12} {unit:<7} {result}"
              + (f"   [{detail}]" if detail else ""))

    slower = [r for r in rows if "SLOWER" in r[3]]
    unstable = [r for r in rows if "unstable" in r[3]]
    moved = [r for r in rows if "reference" in r[3] and abs(float(r[3].split()[0])) >= NOISE_PCT]
    print(f"\n{len(rows)} measurements, {len(slower)} slower, {len(unstable)} not comparable, "
          f"{len(moved)} reference legs that moved")
    # Always 0: no performance measurement fails a build (ADR 0020 D11). This is
    # a report for a person to read, and an exit code would make it a gate.
    return 0


if __name__ == "__main__":
    sys.exit(main())
