# Local performance baseline

The instrument set of [ADR 0020](../../docs/adr/0020-performance-is-measured-before-and-after.md)
D17, in one place. It is **local by design** (D18): comparing one commit against another
is only meaningful on one machine, and a shared continuous-integration runner cannot do
it. The suite carries the `perf` build tag and is referenced by no workflow, so nothing in
continuous integration can pick it up and the pipeline does not grow when an instrument is
added here.

Nothing in this suite asserts. It records; a human compares two records.

## Running it

The stack-dependent instruments need the demo stack:

```bash
export S3EP_LICENSE_TOKEN="$(cat config/license.jwt)"
./start-demo.sh

S3EP_PERF_LABEL="pre-v2" make perf-baseline
```

**The export is not optional and the failure is silent-ish.** The compose file passes
`S3EP_LICENSE_TOKEN` into both proxy containers and does **not** mount `config/license.jwt`
into them, so the `license_file` key in the config points at a path that does not exist
inside the container. Without the variable the proxies exit 1 at startup with
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
| `make perf-baseline` | everything, 7 repetitions, sizes to 128 MiB |
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
| `S3EP_PERF_ALT_PROXY` | none | a second proxy with integrity verification off; without it the upload-path comparison records itself as skipped |
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

It prints one line per measurement with the relative change and a verdict — `faster`,
`SLOWER`, `unchanged` (inside 3 %), or `unstable`. An `unstable` row carries no comparison
value; that mark is the point of running repetitions at all. It refuses exactly one thing —
two runs with different `schema_version`. A difference in machine, toolchain or power source
is a loud warning, not a refusal: it prints both machine lines, says they are not comparable,
and compares them anyway.

## Things that will bite you

**The backend refuses an aws-chunked chunk above 16 MiB; the proxy does not.** A single
`PutObject` of a large body makes the SDK emit one chunk the size of the body, and MinIO
answers `400 BadRequest: chunk too big: choose chunk size <= 16MiB`. The proxy accepts the
same request, because it decodes the framing and re-frames towards the backend. That is a
real asymmetry and not a defect, but it means the direct leg fails where the proxy leg
succeeds. Above 16 MiB the throughput instrument therefore switches **both** legs to a
multipart uploader with 16 MiB parts, and says so in the measurement's note — a comparison
between two different client methods is not a comparison.

**`HeadBucket` through the proxy answers 200 for a bucket that does not exist.** Measured
2026-09-09: the same request against the backend directly answers 404, and a listing of the
same name through the proxy correctly answers `NoSuchBucket`. `HEAD /{bucket}` is served as a
listing with a page size of zero, and the backend short-circuits that before it checks the
bucket is there. The helper that prepares a bucket therefore never probes with `HeadBucket`;
it calls `CreateBucket` unconditionally and tolerates the already-exists error. Do not
reintroduce the probe. That `HEAD /{bucket}` becomes a real existence check is
[ADR 0010](../../docs/adr/0010-sizes-and-listings-describe-the-plaintext.md) D10.

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
says in its instrument table why each skipped: that is a result, not an absence.

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

`subject` is `proxy` or `direct`; the report pairs them on
(`transport`, `operation`, `size_bytes`) and derives the ratio when it renders. Ratios are
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
| `uploadpath_test.go` | the streaming write path against auto-multipart, both against the backend | yes, **plus a second proxy** |
| `selfcopy_test.go` | the backend's server-side copy onto the same key | yes |
| `unwrap_test.go` | key-encryption-key wrap and unwrap | no |
| `cryptofloor_test.go` | the crypto paths in process, current and the shipped codec | no |

Two of these are **not comparisons and say so**. `selfcopy` has one leg by nature: the
operation has no proxy-side counterpart, so it is a profiling harness and is labelled one in
its own status line (ADR 0020 D12). `uploadpath` has three legs rather than two, and the
report divides every leg by the `direct` one.

### The second proxy that `uploadpath` needs

The comparison only means something with a proxy whose integrity verification is off, because
that is what routes the same object size onto the streaming write path instead of
auto-multipart. Without `S3EP_PERF_ALT_PROXY` the instrument records itself as `skipped` with
the reason, rather than quietly measuring nothing:

```bash
sed 's/integrity_verification: "strict"/integrity_verification: "off"/' \
    config/aes-example.yaml > /tmp/aes-nohmac.yaml
docker run -d --name proxy-nohmac \
    --network s3-encryption-proxy_s3-demo -p 8090:8080 \
    -e S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" \
    -v /tmp/aes-nohmac.yaml:/etc/s3ep/config.yaml:ro \
    -v "$PWD/test/ssl-setup:/certs:ro" \
    s3-encryption-proxy-s3-encryption-proxy \
    ./s3-encryption-proxy --config /etc/s3ep/config.yaml

S3EP_PERF_ALT_PROXY=http://127.0.0.1:8090 make perf-baseline
docker rm -f proxy-nohmac
```

Its sizes stop at 16 MiB on purpose: the backend refuses an aws-chunked chunk above that, and
moving a leg to a multipart uploader would change the very thing under test.

The last two are the only "before" that survives a storage format change unchanged: they
depend on no stack and no stored object. Run them with `make perf-baseline-offline`.

Profiles are written to `perf-baseline/profiles-pending/` and are not committed; the
recorded numbers are.
