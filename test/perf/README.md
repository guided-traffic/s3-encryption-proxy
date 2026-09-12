# Local performance baseline

The instrument set of [ADR 0020](../../docs/adr/0020-performance-is-measured-before-and-after.md)
D17, in one place. It is **local by design** (D18): comparing one commit against another
is only meaningful on one machine, and a shared continuous-integration runner cannot do
it. The suite carries the `perf` build tag and is referenced by no workflow, so nothing in
continuous integration can pick it up and the pipeline does not grow when an instrument is
added here.

Almost nothing in this suite asserts: it records, and a human compares two records. The one
exception is the memory instrument, which fails on a hard bound — what a load costs may not
exceed twice the part buffers the configuration budgets for it (120 MiB at the demo stack's
12 MiB segments and four workers), and it may never scale with the object size (ADR 0020 D14).
Every other number is a number in a report.

## Running it

The stack-dependent instruments need the demo stack:

```bash
export S3EP_LICENSE_TOKEN="$(cat /path/to/license.jwt)"  # only when the token is not in config/license.jwt
./start-demo.sh

S3EP_PERF_LABEL="pre-v2" make perf-baseline
```

**The proxies need the token, and `./start-demo.sh` finds it for you.** It takes
`S3EP_LICENSE_TOKEN` from the environment, falls back to `config/license.jwt`, and warns twice
when it has neither — so the export above is only needed when the token lives somewhere else.
It matters because the compose file passes `S3EP_LICENSE_TOKEN` into both proxy containers
and does **not** mount `config/license.jwt` into them, so the `license_file` key in the
config points at a path that does not exist inside the container. Without the variable the
proxies exit 1 at startup with
`license required for encryption provider type 'aes'`. MinIO and Vault stay healthy, and
`docker ps` still lists the `proxy-healthcheck` sidecar and the `encrypted-manager` explorer,
both restart-looping against a proxy that is not there — so the output looks half-plausible. If a run reports every instrument as
`blocked`, check `docker logs proxy` first.

Restart the proxies before a run you intend to keep. The cold resident-memory figure is only
cold once:

```bash
docker compose -f docker-compose.demo.yml restart s3-encryption-proxy s3-encryption-proxy-tls
```

| Target | What it runs |
|---|---|
| `make perf-baseline` | everything, 7 repetitions, sizes to 128 MiB (256 MiB in the upload-path instrument when it has its second proxy) |
| `make perf-baseline-quick` | everything, 3 repetitions, **throughput** sizes to 8 MiB |
| `make perf-baseline-offline` | only the instruments that need no stack |
| `make perf-compare BEFORE=… AFTER=…` | compares two recorded runs |

"Quick" only shortens the throughput matrix. Every other instrument keeps its own sizes: the
ranged-read instrument still uploads a 128 MiB source object per leg, the memory instrument
still drives 128 MiB transfers, and the crypto floor still runs to 128 MiB. A quick run is
shorter, not small.

| Variable | Default | Effect |
|---|---|---|
| `S3EP_PERF_LABEL` | `unlabelled` | names the run in its report |
| `S3EP_PERF_REPS` | `7` | repetitions per measured point |
| `S3EP_PERF_MAX_SIZE` | none | drops **throughput** sizes above this many bytes; no other instrument reads it |
| `S3EP_PERF_PROFILE_SECONDS` | `30` | length of the CPU profile capture |
| `S3EP_PERF_ALT_PROXY` | none | a second proxy whose segment size is above every size measured; without it the upload-path comparison records itself as skipped |
| `S3EP_PERF_OUTDIR` | `../../perf-baseline` | where a run writes |

## Comparing two commits

```bash
git checkout <before>;  S3EP_PERF_LABEL="before" make perf-baseline
git checkout <after>;   S3EP_PERF_LABEL="after"  make perf-baseline
```

Same machine, same power source, nothing else running. Then:

```bash
make perf-compare BEFORE=perf-baseline/<before-id> AFTER=perf-baseline/<after-id>
```

It prints one line per measurement with a verdict — `faster`, `SLOWER`, `unchanged`, or
`unstable`. The `direct` rows are the exception: they carry the reference leg's own move and
the word `reference` instead of a verdict, and a row that exists in only one of the two runs
says so rather than being judged. The last line counts all four: measurements, slower, not
comparable, and reference legs that moved. An `unstable` row carries no comparison value; that
mark is the point of running repetitions at all. It refuses exactly one thing — two runs with
different `schema_version`. A difference in machine, toolchain or power source is a loud
warning, not a refusal: it prints both machine lines, says they are not comparable, and
compares them anyway. No performance number turns it red: a comparison is a report for a
person to read, and an exit code would make it a gate
([ADR 0020](../../docs/adr/0020-performance-is-measured-before-and-after.md) D11). The one
assertion D11 carves out is the memory bound of D14, and it lives in the run, not in the
comparison.

**Where a measurement has a `direct` sibling, the verdict is the ratio, not the median.**
Absolute medians move with the machine — thermal throttling, a busier backend, a different
power source shift both legs together — so a proxy row is judged by `proxy / direct` within
each run, and the row carries `[abs …, direct …]` so the reference leg's own move is visible.
Judging medians made the tool report a machine that had slowed down as the proxy getting
slower, and a 10 % slower reference leg as nothing at all.

**A change counts when it clears the spread the runs themselves showed**, never at a fixed
percentage: the threshold is the combined `RSD` of every leg that went into the comparison,
with a 3 % floor under it. Two runs of the same commit on the same machine used to come back
with 63 of 234 measurements marked `SLOWER`; under the ratio and the spread test the same two
runs report 7.

## Things that will bite you

**The backend refuses an aws-chunked chunk above 16 MiB; the proxy does not.** A single
`PutObject` of a large body makes the SDK emit one chunk the size of the body, and MinIO
answers `400 BadRequest: chunk too big: choose chunk size <= 16MiB`. The proxy accepts the
same request, because it decodes the framing and re-frames towards the backend. That is a
real asymmetry and not a defect, but it means the direct leg fails where the proxy leg
succeeds. Above 16 MiB the throughput instrument therefore switches **both** legs to a
multipart uploader with 16 MiB parts, and says so in the measurement's note — a comparison
between two different client methods is not a comparison.

**`HeadBucket` through the proxy used to answer 200 for a bucket that does not exist.**
Measured 2026-09-09, when `HEAD /{bucket}` was served as a listing with a page size of zero and
the backend short-circuited that before it checked the bucket was there. Since 2026-09-10 it is
a real bucket-existence call and a missing bucket answers 404
([ADR 0010](../../docs/adr/0010-sizes-and-listings-describe-the-plaintext.md) D10). The helper
that prepares a bucket still never probes with `HeadBucket`; it calls `CreateBucket`
unconditionally and tolerates the already-exists error, which is one backend request per bucket
instead of two. Leave it that way.

**Adding an instrument: make every variant allocate the same.** Two measurement bugs were
found and fixed on the first run of the crypto floor, both from one variant reusing a
destination buffer while another allocated a fresh one. They moved the result by 35 % in one
direction and 37 % in the other. For a throughput comparison, the right amount for both
sides to allocate is nothing: preallocate, reuse with `dst[:0]`, and run a primed pass before
timing.

## How big a change has to be to be real

Two runs of **identical code** were compared on 2026-09-09 to find the instruments' own noise
floor. On the in-process instruments at 1 MiB and above, the same code measured between 6.5 %
slower and 8.9 % faster; at 64 KiB it swung by 13 %. **Only one of those two runs was kept**,
so these three figures cannot be recomputed from the tree. They are recorded because the
conclusion outlives the runs; repeat the exercise if you doubt it — run the offline
instruments twice and compare. So:

- Below roughly **10 %**, a difference at these sizes is the machine, not the code.
- At 64 KiB and smaller the in-process instruments are **impressions, not
  measurements**. Read the larger sizes.
- Raise `S3EP_PERF_REPS` if you need to resolve something smaller, and expect the
  run to take proportionally longer.

The end-to-end instruments have not been checked this way across two full runs. What every
report does carry is the **within-run** spread, as `RSD`. On the proxy leg of the throughput
and ranged-read instruments it is 1.4–24.5 % at 1 MiB and above (median 4.7 %) and 5.0–21.9 %
below 1 MiB (median 11.1 %). The widest single row is the largest TLS upload; small objects
are noisy on reads as well as writes. Treat the between-run
figure as at least the within-run one.

## What a run writes

`perf-baseline/<UTC timestamp>-<commit>/`:

| File | Content |
|---|---|
| `run.json` | every measurement, machine-readable, `schema_version` 1 |
| `REPORT.md` | the same run as tables, generated |
| `FINDINGS.md` | hand-written, optional: what the numbers mean, written the day they were taken |

A run in which **no instrument ran at all** — every one filtered out by `-run`, or the package
skipped before any instrument reached its status line — writes no directory, so an empty record
never sits beside real ones. A run whose instruments ran and all skipped still writes one, and
says in its instrument table why each skipped: that is a result, not an absence. A run also
rewrites `perf-baseline/LATEST` with the id of the run it just finished. That file is a marker
for the next command, not a record, and is not committed.

`REPORT.md` is regenerated on every run and says what was measured. `FINDINGS.md` is written
by a person and says what it means — which rows support a claim, which only suggest one, and
what the run cannot answer. A run kept as a baseline is worth much more with one; the
`pre-v2` run has it.

Every measurement has the same shape whatever produced it, so two runs diff without
per-instrument parsing:

```json
{
  "instrument": "throughput", "transport": "tls", "operation": "download",
  "subject": "proxy", "size_bytes": 8388608, "unit": "MiB/s",
  "samples": [250.56, 235.45, 242.03, 244.45, 260.51, 253.19, 248.37],
  "n": 7, "median": 248.37, "mean": 247.79, "min": 235.45, "max": 260.51,
  "p90": 256.12, "stddev": 8.12, "rsd_pct": 3.28,
  "note": "whole-object GetObject drained to io.Discard"
}
```

That is a real row from the `pre-v2` run, samples rounded. The recorder computes everything
from `n` downwards; an instrument only supplies the first six fields, the samples and the note.

`subject` names the leg: `proxy` and `direct` wherever a comparison has two, `proxy-streaming`
for the second write path `uploadpath` measures, and the in-process names of the stack-free
instruments (`in-process`, `aes-256`, `rsa-2048`, `rsa-4096`). The report groups on
(`transport`, `operation`, `size_bytes`) and divides every other subject by `direct` when it
renders; an instrument that has no `direct` leg is rendered on its own. Ratios are
never stored (D20) — the two legs stay visible, and a missing leg shows as missing rather
than as a plausible number.

A run also records the machine it ran on (D19): processor, core counts, memory, operating
system and kernel, toolchain, container runtime, **power source**, and the load average
before and after. Two runs from different machines, or from the same laptop on mains and
on battery, are not comparable.

An instrument that produced nothing says why, under `instruments`, so a partial run cannot
be read as a complete one.

## The instruments

| File | Instrument | Needs the stack |
|---|---|---|
| `throughput_test.go` | whole-object upload and download, both transports | yes |
| `rangeread_test.go` | ranged reads at aligned, unaligned and tail offsets | yes |
| `smallobject_test.go` | small-object request rate at three concurrencies | yes |
| `memory_test.go` | proxy resident memory, and CPU and heap profiles | yes |
| `uploadpath_test.go` | the single-request write path against the multipart producer, both against the backend | yes, **plus a second proxy** |
| `unwrap_test.go` | key-encryption-key wrap and unwrap | no |
| `cryptofloor_test.go` | the segment chain in process: the raw cipher floor and the shipped codec | no |

`uploadpath` is the one that is not a two-leg comparison: it has three legs, and the report
divides every leg by the `direct` one.

### The second proxy that `uploadpath` needs

Which write path an object takes is decided by its size alone: at or below
`optimizations.streaming_segment_size` the proxy writes it in one request, above it the
multipart producer takes over. So the only way to put the same size through both paths at once
is a second proxy with a different segment size — one high enough that everything measured here
fits in a single request. Without `S3EP_PERF_ALT_PROXY` the instrument records itself as
`skipped` with the reason, rather than quietly measuring nothing:

```bash
sed 's/streaming_segment_size: 12582912/streaming_segment_size: 5368709120/' \
    config/aes-example.yaml > /tmp/aes-onepart.yaml
docker run -d --name proxy-onepart \
    --network s3-encryption-proxy_s3-demo -p 8090:8080 \
    -e S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" \
    --env-file .env \
    -v /tmp/aes-onepart.yaml:/etc/s3ep/config.yaml:ro \
    s3-encryption-proxy-s3-encryption-proxy \
    ./s3-encryption-proxy --config /etc/s3ep/config.yaml

S3EP_PERF_ALT_PROXY=http://127.0.0.1:8090 make perf-baseline
docker rm -f proxy-onepart
```

The `--env-file` is not optional: `config/aes-example.yaml` reads its key as `${S3EP_AES_KEY}`,
`scripts/gen-keys.sh` writes that key into `.env`, and compose loads that file where a plain
`docker run` does not. Without it the alternate proxy exits at startup with
`encryption.providers[0].config.aes_key: environment variable ${S3EP_AES_KEY} is not set or empty`.

It has exactly one **three-leg** size, 16 MiB: below it the two proxies agree (both write in
one request) and above it the direct leg cannot follow, because the backend refuses an
aws-chunked chunk above 16 MiB and moving that leg to a multipart uploader would change the
very thing under test. At 24, 64 and 256 MiB the instrument drops the direct leg and compares
the two proxy write paths with each other — both proxies re-frame towards the backend, so a
single `PutObject` of those sizes goes through where the direct leg cannot follow. Those rows
carry no backend ratio and say so in their note; they are the range the multipart producer is
measured on.

The recipe above was run on 2026-09-10: the alternate proxy writes 256 MiB in a single
request, so the largest proxy-only size does reach the backend on both legs.

The last two need no stack and no stored object, so they run on any commit and on a machine
with nothing else set up. Run them with `make perf-baseline-offline`. They are not immune to a
storage format change: when the format changed, the crypto floor's rows changed with it, and
rows measuring a format that no longer exists were dropped rather than kept as a comparison
against nothing.

Profiles are written to `perf-baseline/profiles-pending/` and are not committed; the
recorded numbers are.
