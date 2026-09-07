#!/usr/bin/env python3
"""Per-package coverage table for the CI report.

Reads the text profiles that `make coverage-report` writes into the coverage
directory: merged.out (every source), plus unit.out and integration.out when
the matching counter directories existed. Prints a markdown table with one
column per source and the combined result, one row per package and a total row.

Every column is measured against the same denominator, the statements in the
merged profile. A package without unit tests therefore shows 0% in the unit
column instead of vanishing, and no source can exceed the combined number.
This is also why the unit total here is below the total of a unit-only
`go tool cover -func`, which only knows the packages that have tests.

The numbers are summed out of the profile rather than awked out of
coverage.txt: that file has one line per function, so an unweighted mean over
it would be wrong. Summing statements gives one row per package and a total
that matches `go tool cover -func` exactly. A block counts as covered when its
count is above zero, which is the right test under both profile modes
(`go tool covdata textfmt` emits `mode: atomic`).
"""

import argparse
import collections
import os

REPO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SOURCES = (("unit", "Unit"), ("integration", "Integration"))


def module_path():
    with open(os.path.join(REPO_ROOT, "go.mod")) as fh:
        for line in fh:
            if line.startswith("module "):
                return line.split()[1] + "/"
    raise SystemExit("go.mod has no module line")


def read_profile(path):
    """{location: (statements, count)} for one text-format profile."""
    blocks = {}
    with open(path) as fh:
        next(fh, None)  # the "mode:" line
        for line in fh:
            line = line.strip()
            if line:
                loc, num_stmt, count = line.rsplit(" ", 2)
                blocks[loc] = (int(num_stmt), int(count))
    return blocks


def percent(covered, total):
    return f"{100.0 * covered / total:.1f}" if total else "0.0"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("coverage_dir", help="directory holding merged.out and the per-source profiles")
    parser.add_argument(
        "--totals",
        metavar="FILE",
        help="write one `<source>=<percent>` line per source (unit, integration) to FILE, "
        "the format $GITHUB_OUTPUT expects; a missing source is written as N/A",
    )
    args = parser.parse_args()

    module = module_path()
    merged = read_profile(os.path.join(args.coverage_dir, "merged.out"))
    columns = []  # (key, title, profile)
    for key, title in SOURCES:
        path = os.path.join(args.coverage_dir, f"{key}.out")
        if os.path.exists(path):
            columns.append((key, title, read_profile(path)))
    columns.append(("combined", "Combined", merged))

    statements = collections.Counter()
    covered = {key: collections.Counter() for key, _, _ in columns}
    for loc, (num_stmt, _) in merged.items():
        pkg = loc.rsplit(":", 1)[0].rsplit("/", 1)[0].removeprefix(module)
        statements[pkg] += num_stmt
        for key, _, profile in columns:
            block = profile.get(loc)
            if block is not None and block[1] > 0:
                covered[key][pkg] += num_stmt

    print("| Package | " + " | ".join(title for _, title, _ in columns) + " | Statements |")
    print("|---|" + "---:|" * (len(columns) + 1))
    for pkg in sorted(statements):
        cells = " | ".join(f"{percent(covered[key][pkg], statements[pkg])}%" for key, _, _ in columns)
        print(f"| `{pkg}` | {cells} | {covered['combined'][pkg]}/{statements[pkg]} |")

    total = sum(statements.values())
    totals = {key: percent(sum(covered[key].values()), total) for key, _, _ in columns}
    cells = " | ".join(f"**{totals[key]}%**" for key, _, _ in columns)
    print(f"| **Total** | {cells} | {sum(covered['combined'].values())}/{total} |")

    if args.totals:
        with open(args.totals, "w") as fh:
            for key, _ in SOURCES:
                fh.write(f"{key}={totals.get(key, 'N/A')}\n")


if __name__ == "__main__":
    main()
