#!/usr/bin/env python3
"""Compare two performance baseline runs.

    ./test/perf/compare.py perf-baseline/<before> perf-baseline/<after>

Reads run.json from both and prints, per measurement, the relative change of the
median. A measurement that either run marked as widely spread is flagged: it
carries no comparison value (ADR 0020 D21).
"""

import json
import sys
from pathlib import Path

UNSTABLE_RSD = 10.0
# Below this, a change is inside the noise the instrument itself produces.
NOISE_PCT = 3.0


def load(path):
    p = Path(path)
    if p.is_dir():
        p = p / "run.json"
    with p.open() as fh:
        return json.load(fh)


def key(m):
    return (m["instrument"], m["transport"], m["operation"], m["subject"], m["size_bytes"])


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
            rows.append((k, None, a, "only in after"))
            continue
        if a is None:
            rows.append((k, b, None, "only in before"))
            continue
        if not b["median"]:
            rows.append((k, b, a, "no before median"))
            continue
        change = (a["median"] - b["median"]) / b["median"] * 100
        # Latency-style units get better when they fall.
        if a["unit"] in ("ns/op", "bytes", "s"):
            change = -change
        flag = ""
        if b["rsd_pct"] > UNSTABLE_RSD or a["rsd_pct"] > UNSTABLE_RSD:
            flag = "unstable"
        elif abs(change) < NOISE_PCT:
            flag = "unchanged"
        elif change < 0:
            flag = "SLOWER"
        else:
            flag = "faster"
        rows.append((k, b, a, f"{change:+.1f} %  {flag}"))

    width = max(len(" / ".join(str(x) for x in k[:4])) for k, _, _, _ in rows) if rows else 40
    for k, b, a, verdict in rows:
        instrument, transport, operation, subject, size = k
        label = f"{instrument} / {transport} / {operation} / {subject}"
        bm = f'{b["median"]:.1f}' if b else "—"
        am = f'{a["median"]:.1f}' if a else "—"
        unit = (a or b)["unit"]
        print(f"{label:<{width}}  {human(size):>8}  {bm:>12} → {am:>12} {unit:<7} {verdict}")

    slower = [r for r in rows if "SLOWER" in r[3]]
    unstable = [r for r in rows if "unstable" in r[3]]
    print(f"\n{len(rows)} measurements, {len(slower)} slower, {len(unstable)} not comparable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
