# S3 Encryption Proxy - AI Coding Instructions

## Project Overview
A Go-based transparent S3 encryption proxy. It sits between S3 clients and S3 storage,
encrypting objects before storage and decrypting them on retrieval. Every object is stored in
one format: an authenticated AES-256-GCM segment chain closed by a sealed trailer (ADR 0003),
under one random data key per object that is wrapped by the configured key encryption key
(ADR 0002). There is no second cipher, no configurable integrity mode and no format switch.

## Decisions live in ADRs; tickets are work lists that get deleted

**Every design decision of this project is recorded as an ADR** under
[docs/adr/](docs/adr/) — see [docs/adr/README.md](docs/adr/README.md) for the
format and the ground rules. Write the ADR in the session the decision is taken,
not when the work is finished. An ADR states what the product does and why; it
carries **no references into the code** (no file paths, line numbers, function or
package names) so it stays true when the tree moves. The product's own vocabulary
— configuration keys, `s3ep-*` metadata keys, S3 error codes, header and
algorithm names — is not a code reference and must be exact.

**A ticket is a work list and nothing else.** It lives in `docs/tickets/`, it
exists while work is outstanding, and it is closed by **deleting the file** when
the work lands. Before deleting it, move anything durable out of it: the decision
into an ADR, the user-facing consequence into `README.md` or
`SECURITY_ARCHITECTURE.md`. Finish, document, delete — a backlog that outlives
its work costs focus.

**Nothing outside `docs/tickets/` may reference a ticket.** Not `README.md`, not
`SECURITY_ARCHITECTURE.md`, not this file, not a code comment, not a commit
message, not a pull request. Cite the ADR instead; ADRs may be referenced from
anywhere. A code comment that has to point at a pending change points at its ADR
("the segmented format, ADR 0003"), never at a ticket number. Before deleting a
ticket, `git grep` for its number and clear whatever is left.

## Developer documentation lives in `docs/developer/`

Overviews for people changing the code — the package map, the storage format and
its invariants, the request paths, multipart, the error conventions, where a
configuration value comes from, the test layers, how to measure performance.
Start at [docs/developer/README.md](docs/developer/README.md).

**Read the page for a subsystem before you change it**, and **update it in the
same change** when you move what it describes. Unlike an ADR, a page here points
at files and functions on purpose, so it goes stale when the tree moves.

Where a durable insight belongs:

| Kind | Home |
|---|---|
| A decision — what the product does and why, what was rejected | an [ADR](docs/adr/), with no references into the code |
| How a subsystem works, an invariant, a hard-won detail | [docs/developer/](docs/developer/) |
| What an operator or a client needs | [README.md](README.md) |
| The threat model and residual risks | [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) |
| Work still outstanding | a [ticket](docs/tickets/), deleted when the work lands |

Do not let implementation detail accumulate in `README.md`; that page is for
operators and clients. If you catch yourself explaining the code there, the
explanation belongs in `docs/developer/`.

## Start with the knowledge graph (graphify)

This project has a graphify knowledge graph at `graphify-out/` (`graph.json`,
`GRAPH_REPORT.md`, `wiki/`). It is the fastest way to see how the pieces hang
together before touching code, and it is committed, so it is always available.

**The committed graph was built on 2026-09-10 and predates the 5.0.0 removal**
that deleted the pre-segment-chain code. A large share of its articles name
packages, files and symbols that no longer exist — `internal/validation`,
`pkg/encryption/envelope`, the AES-CTR and AES-GCM data encryptors, every HMAC
article, the old orchestration `singlepart`/`multipart`/`streaming_io` split.
Use it for shape, never for facts, until it is rebuilt.

**Use it first, especially at the start of a ticket and for any code research:**
- Read `graphify-out/wiki/index.md`, then the community articles that name the
  packages the task touches (e.g. *Bucket Sub-Resource Handlers*, *Metadata
  Manager*, *SigV4 Header Authentication*, *Pre-Signed URL Authentication*).
  One article is a map of one subsystem; read two or three before opening raw
  files.
- `graphify query "<question>"` gives BFS context around a question,
  `graphify explain "<symbol>"` explains one node and its neighbours,
  `graphify path "A" "B"` finds how two concepts connect. All read
  `graphify-out/graph.json` and cost no API tokens.
- Before answering architecture or codebase questions, read the *Community Hubs*
  section of `graphify-out/GRAPH_REPORT.md`. Skip its *God Nodes* section: in this
  repo it lists test fixtures and constructors (`EnsureMinIOAndProxyAvailable()`,
  `NewErrorWriter()`, `MockS3Backend` twice over), which are call-resolution
  artifacts, not architectural hubs.
- Treat a graph hit as a pointer, not a fact. Wiki articles built from a document
  inherit that document's staleness, and several were built from documents that
  have since been deleted (`internal/orchestration/README.md`,
  `docs/architecture/`, `test/integration/README.md`). Verify in the code before
  citing anything.
- The graph lags the code. The build date is in the first line of
  `GRAPH_REPORT.md`; `git log -1 --format=%ad -- graphify-out` shows when it was
  last committed.

**Updating the graph is a manual, user-approved step.** `graphify update .`
(AST-only, no API cost) and the full `/graphify` run both rewrite `graphify-out/`
and are committed as their own change. They need explicit approval from the user
and are usually run in a separate session. Never run them unprompted. After
changing code, say in the final report that the graph is behind and needs an
update; do not run it yourself. Corpus scope lives in `.graphifyignore`
(`test-results`, `coverage`, `build`, `dist` and graphify's own outputs are
excluded). Its graphify-out rules name sub-paths instead of the whole directory
on purpose: graphify always scans `graphify-out/memory/` (Q&A results filed by
`graphify save-result`) when it exists but still applies the ignore file to it,
so a blanket `graphify-out` rule would drop it. That directory does not exist in
this repo yet.

## Architecture

The package map, the storage format and its invariants, the request paths, the
two multipart paths, the error conventions, the test layers and the performance
rules live in [docs/developer/](docs/developer/) — start at its
[README](docs/developer/README.md). The contributor guide — repository layout,
the build/test/lint matrix, continuous integration, the extension checklists and
the project conventions — is [DEVELOPER.md](DEVELOPER.md). The threat model is
[SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md). **Read the page for a
subsystem before you change it, and update it in the same change.**

What has to be in your head before anything else:

- **One stored format**, `s3ep-gcm-seg-v2`: an AES-256-GCM segment chain closed
  by a sealed trailer, under one random data key per object wrapped by the
  configured key encryption key. No second cipher, no configurable integrity
  mode, no format switch (ADR 0001, ADR 0002, ADR 0003)
- **Exactly four metadata keys** under `metadata_key_prefix` (`s3ep-` default):
  `dek-algorithm`, `encrypted-dek`, `kek-algorithm`, `kek-fingerprint`. Nothing
  else is written, nothing unprefixed is read, and a client key inside the prefix
  is refused with `400 InvalidArgument` (ADR 0009)
- **Two KEK providers**, `aes` and `exit`. `exit` holds no key material, stores
  what the client sent on every write path, and still decrypts per object what
  `aes` wrote — so the `aes` provider stays configured beside it (ADR 0004,
  ADR 0025). There is no tink provider and no KMS provider (ADR 0005)
- **The DEK layer is not pluggable.** It is the segment chain, always; changing
  it is a storage format change (ADR 0003, ADR 0017)
- **Encryption happens exactly once**, in the handler's call into
  `orchestration.Manager`. There is no second layer

Integrity is not configurable and never was a layer: it is the storage format
itself. An object with no proxy metadata, or a wrapped data key that does not
authenticate, is refused with `403 InvalidObjectState` under an encrypting
provider — on GET, HEAD and ranged GET alike, with no pass-through opt-out.

## Development Workflows

### Build Commands (Makefile-driven)
```bash
make build              # Build main binary to build/s3-encryption-proxy
make build-keygen       # Build AES key generator to build/s3ep-keygen
make license-tool       # Build the license tool to build/license-tool
make build-all          # All three binaries
make test-unit          # Unit tests (-short)
make test-integration   # Integration tests against the plain-HTTP proxy (requires ./start-demo.sh)
make test-integration-tls          # Same suites against the TLS endpoint (aws-sdk-go-v2 emits STREAMING-UNSIGNED-PAYLOAD-TRAILER framing only over HTTPS, so only this run reaches the trailer decoder)
make test-integration-performance  # Proxy-vs-MinIO throughput, run alone on purpose
make test-integration-all          # HTTP + TLS + performance
make e2e-rclone         # rclone against the demo stack (e2e-rclone-up + test-e2e-rclone)
make e2e-s3cmd          # s3cmd, the same. Never bundled — see "one tool, one job"
make perf-baseline      # Local before/after throughput baseline (ADR 0020); perf-baseline-quick, perf-baseline-offline, perf-compare
make coverage           # Unit-test coverage report; see Makefile for the combined unit + integration flow (GOCOVER=1)
make lint / fmt / gosec / vuln / all-checks
./start-demo.sh         # Build project in container and run a docker compose-environment with minio and s3-encryption-proxy
```

### Go toolchain version
The Go version is spelled out in exactly two files. Every other place derives
it, so a bump touches only these two and they must always agree:

| File | Line | Role |
|---|---|---|
| `Containerfile` | `FROM golang:<version>-alpine AS builder` | Source of truth for the shipped image. The Makefile parses this line into `GO_VERSION` and pins `GO_PIN := GOTOOLCHAIN=go$(GO_VERSION)` for `vuln`, `test-unit-coverage` and `coverage-report`. |
| `go.mod` | `go <version>` | Source of truth for CI and local builds: every `setup-go` step in `.github/workflows/test-pipeline.yml` uses `go-version-file: go.mod`, and the go command auto-downloads this toolchain for anyone running an older local Go. |

Derived, no literal, do not add one:
- `Makefile`: `GO_VERSION` / `GO_PIN` (parsed from the Containerfile)
- `.github/workflows/test-pipeline.yml`: `go-version-file: go.mod` (no `GO_VERSION` env)
- `README.md` and `.github/release-template.hbs`: the Go badge is the shields.io `go-mod/go-version` endpoint that reads go.mod

Renovate (`renovate.json`) bumps both literals in one PR, group "Go version": the
`dockerfile` manager handles the Containerfile (depName `golang`), a custom regex
manager handles the go directive in go.mod (depName `go`). No Renovate PR has
ever bumped the go directive deliberately (the one gomod-manager "Update
dependency go" PR moved only the since-removed `toolchain` line), which is why
the regex manager exists. If you introduce a new place that needs the version, derive it
from one of the two files or extend the custom manager and this table; never
hardcode it.

Why the Makefile pins the Containerfile version rather than trusting go.mod:
combined coverage merges unit-test data with data from the instrumented proxy
binary, and Go coverage data only merges across identical toolchains (block
layout and package hashes change between releases; a 1.26/1.27 mix reported a
package at 25.9% that was really at 62.8%). A newer local Go would satisfy
go.mod but silently corrupt that merge.

### Key Generation Patterns
```bash
# AES keys (cmd/keygen prints a banner around the key; sed -n 2p takes the key line)
make build-keygen && ./build/s3ep-keygen

# Development license: config/license.jwt (gitignored) or S3EP_LICENSE_TOKEN, supplied
# out of band. `make generate-license` builds and runs cmd/license-tool, which needs
# license_private_key.pem / license_public_key.pem next to the binary (not in the repo,
# ADR 0021). There is no setup-dev-license target.
```

### Testing Strategy
- **Unit tests**: `make test-unit` - Fast tests with `-short` flag
- **Integration tests**: `make test-integration` - Requires MinIO via `./start-demo.sh`
- Use build tag `//go:build integration` for integration tests. Every file under `test/integration/` carries it except `test/integration/conformance/`, which is tagged `//go:build conformance` because it runs against a backend of its own (ADR 0027); the four untagged `bucket_*_test.go` files that used to be the exception were deleted (they imported no package of this project)
- Three build tags carry the test tree: `integration`, `conformance`, and `e2e` for everything under `test/e2e/` — the Velero suite, the two client suites and the shared `test/e2e/harness/` package, whose non-test files carry the tag too or they would break the untagged build
- Integration packages: `test/integration` (helpers + `s3_signing_test.go`), `180-degree-variants`, `360-degree-variants`, `authentication`, `encryption-modes`, `s3-methods` (the bulk of the suite) and `performance-test`, which the Makefile runs on its own because it measures proxy-vs-MinIO throughput and the other packages would compete for the same backend
- `test/integration/conformance` is not one of them and is deliberately outside `INTEGRATION_PKGS`: it carries its own `//go:build conformance` tag and asserts what S3 specifies against a proxy pointed at *any* backend — the same binary runs against each, and the difference between two backends is the finding, not a flake (ADR 0027). It is driven by `scripts/conformance-run.sh <backend>` through `make test-conformance` (minio + localstack, free) and `make test-conformance-wasabi` (**billed**), and the `conformance` CI job is a release gate
- Test helper: `test/integration/minio_test_helper.go` provides `TestContext` with MinIO and proxy clients; `encryption_validation_helper.go` asserts that stored bytes are ciphertext (entropy checks)
- You are not allowed to disable, skip or remove integration or e2e tests — Velero, rclone or s3cmd — they represent the end-user experience (ADR 0019)
- Don't call your work done until the suites tell the truth about your change: every test that was green before it is green after, and any test that is red is red for a target the product has not met yet, not for something your change broke (ADR 0031 D2)
- Integration Test need to be prepared with ./start-demo.sh (it takes 30 seconds to start)
- If you want to get the recent logs from s3-encryption-proxy container use: docker logs proxy | tail -50 (the TLS listener is a second container, `proxy-tls`)
- Try integrate new unit-tests into existing files if it makes sense

#### Velero e2e suite (`test/e2e/velero/`)
- **e2e tests**: `make test-e2e-velero` - build tag `//go:build e2e`, 13 tests: a preflight plus the V1-V10 backup/restore scenarios (V1b and V8b included), with encryption-at-rest assertions read directly from the MinIO backend
- Environment: `make e2e-up` brings it up, `make e2e-down` tears it down, `make e2e-velero` does up + run for a cold machine. Both scripts live next to the tests (`test/e2e/velero/e2e-up.sh`, `e2e-down.sh`) and CI runs the identical scripts, so a workstation and a runner cannot drift apart
- Bring-up cost is nothing like the 30 seconds of `./start-demo.sh`: `e2e-up` generates the test PKI when needed, creates a kind cluster, builds and side-loads the proxy image for the local architecture, installs MinIO over TLS, the CSI hostpath driver + snapshotter, the proxy via its own Helm chart and Velero, and waits for the BackupStorageLocation to go Available. It is idempotent and reloads a freshly built image, so retest a code change with `make e2e-up && make test-e2e-velero` rather than recreating the cluster. The suite itself ran 592s on 2026-09-06; the CI job budgets 45 minutes for up + run + down
- `e2e-up` needs a license or the proxy pod never becomes ready: it takes `S3EP_LICENSE_TOKEN`, falls back to `config/license.jwt`, and aborts if neither exists. Supply the token out of band (CI injects the `S3EP_LICENSE_TOKEN` secret)
- The no-skip rule above covers this suite: it is the end-user experience of one supported S3 client exercised end to end, and `e2e-velero` is a deliberate release gate in `.github/workflows/test-pipeline.yml`

#### Client e2e suites (`test/e2e/rclone/`, `test/e2e/s3cmd/`)
- **rclone**: `make test-e2e-rclone`, cases R1-R7. **s3cmd**: `make test-e2e-s3cmd`, cases S1-S7. Same `//go:build e2e` tag, one package each, every case over both proxy endpoints
- Environment is the demo stack, not a cluster: `make e2e-rclone-up` / `make e2e-s3cmd-up` install the pinned client and hand the stack to `./start-demo.sh`; either `*-down` target stops it, because there is one demo stack and not one per suite. There is deliberately no target that runs both. Seconds, not minutes: 5s and 8s on a warm stack (2026-09-13)
- The clients are real pinned binaries, installed by the up-scripts into `test/e2e/rclone/bin/` and `test/e2e/s3cmd/venv/` (both gitignored) and overridable with `RCLONE_BIN` / `S3CMD_BIN`. Versions live in each suite's `versions.env`, tracked by Renovate as the group "client e2e" and never automerged: a client release can change the verdict, and that is the finding
- **Every case asserts the target behaviour**, so both suites are RED today: 13 of 28 rclone cases and 10 of 19 s3cmd cases fail, and they stay red until the entity-tag question of ADR 0010 D12 and the two routing gaps are answered. That is the suites working — see *A test asserts the TARGET behaviour* below
- Each run writes `test-results/e2e-<client>-verdicts.md`: one row per case per endpoint with the client's own sentence. That table is the evidence behind what this project claims about these clients (ADR 0006 D5, D7)
- The no-skip rule covers both suites, and `e2e-rclone` and `e2e-s3cmd` are release gates alongside `e2e-velero` — one CI job each
- Shared helpers are `test/e2e/harness/` (the demo-stack coordinates, the process runner, the backend client, the at-rest assertion, the verdict recorder). `test/e2e/harness/demo-stack.env` is read by both the bash up-scripts and the Go suites, so a port or a credential cannot drift between them


#### Maintaining the e2e suites — read this before you touch one

**A test asserts the TARGET behaviour of the software, never the behaviour it has
today** (ADR 0031). This is not a style preference, it is the rule:

- Write what the product is *supposed* to do. If it does not do that yet, the test is
  **red, and it stays red until the product is fixed**. A red suite is a correct suite.
- **Committing a red test is allowed and wanted** — before a fix, alongside a bug report,
  as the record of a defect nobody has got to yet. Do not wait for the fix to land the test.
- **Never encode the current, broken behaviour as the expectation.** Not with an "expected
  failure" marker, not with a table of known defects, not with a comment saying "today it
  answers X". Each of those turns a broken product into a green pipeline, and a green
  pipeline says "this may be merged" — which is the one thing it must not say while the
  defect is open.
- Never `t.Skip` a case to make a suite green either. Skipping and pinning are the same
  mistake wearing different clothes (ADR 0019).

**This was got wrong once, on 2026-09-13, and it is why the rule is written out here.** The
rclone and s3cmd suites first shipped with every open defect recorded as an *expected*
refusal. Both suites were green, the release gate was green, and the pipeline reported that
a product which cannot upload *or download* a single-request object through two named
clients was ready to merge. The defects were in a generated table nobody opens when the
check is green. Tests exist to surface a problem, not to file it.

**How to know what is still broken:** run the suites and read what fails. Every failure
names the rule it wants and the ADR that rule belongs to. The two client suites also write
`test-results/e2e-<client>-verdicts.md` with a `Still broken` section, and their CI jobs put
the same list in the step summary — so a red check names the defects without anyone opening
an artifact or grepping the test tree.

**The tree was swept against this rule on 2026-09-13** and 27 tests were found asserting a
known-wrong answer; they now assert the target and are red, which is why `make test-unit`
and the integration suites do not pass on this branch. 28 further candidates were checked
and left alone because an ADR decides them — a refusal that an ADR records as the product's
intent is the product working, not a pinned defect, and that is the distinction to make
before touching any of them.

**A change to `test/e2e/harness/` is a change to all three suites.** Compiling and running
the two client suites proves two of them. The Velero suite has to be run for real before
such a change lands: it is a release gate, and `go vet` does not execute an assertion.
Budget it — `make e2e-up` is minutes, the suite ran 579s on 2026-09-13.

**The harness has two halves, and a new helper belongs on one of them.**
`stored.go` and `atrest.go` take the client and the bucket as parameters and know nothing
about where a stack lives — that is what lets Velero, whose proxy and MinIO are Services in
a kind cluster, share them. `backend.go` resolves the demo stack's own coordinates and is
for the client suites only. Putting a demo-stack lookup into the shared half silently
breaks Velero at runtime, not at compile time.

**The stored contract stays spelled out per suite.** Each suite passes its own
`harness.Format{MetadataPrefix, ID}` — Velero as a literal, the client suites out of
`demo-stack.env`. Do not collapse them into a constant in `harness`: each suite is a
black-box client, and a change to `s3ep-` or to `s3ep-gcm-seg-v2` has to fail in every
suite separately rather than being edited once. The assertion is shared; the claim is not.

**After changing proxy code, rebuild before you retest.** Every e2e suite talks to a built
binary, never to your working tree: `./start-demo.sh` for the client suites (`rebuild` to
force it), `make e2e-up` for Velero, which reloads a freshly built image without recreating
the cluster.

**Moving a client version pin is an experiment, not a dependency bump.** `versions.env`
carries one release and never `latest`; each suite's preflight asserts the installed binary
matches the pin, so a bump without a reinstall fails loudly. Renovate groups both under
"client e2e" and never automerges them: run the suite and read the verdict table before
merging, because a changed verdict is the finding.

**The verdict tables are generated.** `test-results/e2e-<client>-verdicts.md` is written by
each run, `test-results/` is gitignored, and nothing hand-edits them. They are the evidence
a support claim names (ADR 0006 D5, D7) — copy a table into an ADR or a ticket when it is
the record of a decision, never into the repository as a file.

**One tool, one suite, one job — never bundled.** Each e2e client gets its own package,
its own Make targets and its own CI job, and no target or job ever runs two of them
together. Adding a third tool means adding a third job, not another step inside an
existing one. The reasons are all about what a failure tells you:
- a red gate names the client in the job name, so nobody opens a log to learn which one broke;
- **the job name is `E2E <tool> (<backend>)`: procedure first, then the tool, then the S3
  backend it ran against** — `E2E s3cmd (minio)`, `E2E Velero (kind)`. The procedure leads
  because that is what groups the jobs in a check list; the backend is named the way
  `Conformance (minio)` names it, never the stack that happened to host it, because a verdict
  is about the backend and the same suite against another backend is another job;
- one client's trouble — a download, an upstream release, a flake — cannot withhold the
  other's verdict, and both verdicts are what the suites exist to produce;
- a required check is per job, so bundling makes it impossible to require one client and
  not another, or to see in a pull request's check list which client is failing;
- runtime and failure mode belong to the client, and bundling hides which one costs what.
This was got wrong once: rclone and s3cmd shipped as a single `e2e-clients` job on
2026-09-13 and were split the same day.

**Every e2e job gates the release.** `e2e-velero`, `e2e-rclone` and `e2e-s3cmd` are on
`semantic-release`'s `needs:`. A new e2e job needs a second step that is not in this
repository: its job name on the required-check list in branch protection, or it runs on
every pull request and blocks nothing. Order matters — merge the workflow first, then add
the context, or every pull request waits on a check that never reports. The full checklist
for adding a client suite is in [DEVELOPER.md](DEVELOPER.md), *Adding things*.

## Project-Specific Conventions

### Complete Configuration Structure
This is every key the code reads, and since ADR 0013 D11 it is also every key the
proxy accepts: the loader decodes in its exact mode, so a key that is not here
refuses the start and the error names it. Values marked `# default` are the
defaults set in `internal/config/config.go` (`setDefaults`); everything else is an
example. **Adding a key to the struct and forgetting this table is now a startup
failure for anyone whose configuration carries it**, so the two move together.

```yaml
# Server Configuration
bind_address: "0.0.0.0:8080"  # default
log_level: "info"             # default; debug, info, warn, error
log_format: "text"            # default; text or json
log_health_requests: false    # default
shutdown_timeout: 30          # example, seconds; unset = 30s fallback. One budget for
                              # the whole shutdown: the request drain, the multipart
                              # sweep in the manager stop and the listener close
                              # (ADR 0029 D1/D3). The chart derives
                              # terminationGracePeriodSeconds from it
read_timeout: 0               # default, seconds; 0 = no deadline on a request body
write_timeout: 0              # default, seconds; 0 = no deadline on a response body
read_header_timeout: 30       # default, seconds; may not be 0 (slow-header bound)
idle_timeout: 60              # default, seconds; may not be 0 (keep-alive bound)
tls:                          # TLS listener of the proxy itself
  enabled: false              # default
  cert_file: "test/ssl-setup/public.crt"   # example, gen-certs.sh output
  key_file: "test/ssl-setup/private.key"   # example, gen-certs.sh output

# S3 Backend Configuration
s3_backend:
  target_endpoint: "https://minio:9000"  # example; required, and its scheme decides
                                         # whether the backend leg is TLS. A missing
                                         # scheme refuses the start, and so does
                                         # http:// under a provider that encrypts
  region: "us-east-1"                    # default
  access_key_id: "minioadmin"            # example
  secret_key: "minioadmin123"            # example, ${ENV} references work
  insecure_skip_verify: false            # default; the demo configs set true

# S3 Client Authentication (required - the proxy refuses to start without at least one)
s3_clients:
  - type: "static"                  # the only supported type
    access_key_id: "username0"      # minimum 8 characters, enforced at startup
    secret_key: "minimum-16-chars"  # minimum 16 characters, enforced at startup
    description: "Client authentication"

# S3 Security Configuration
# Both keys govern both authentication forms (ADR 0014 D4/D5). Neither accepts 0:
# there is no value that switches a check off, and a silent fallback to the
# default is what ADR 0017 D8 forbids.
s3_security:
  max_clock_skew_seconds: 900       # default, 1-3600 checked at startup
  max_presign_expiry_seconds: 3600  # default, 1-604800 (the S3 seven-day maximum)

# Monitoring
monitoring:
  enabled: false                        # default
  bind_address: ":9090"                 # default
  metrics_path: "/metrics"              # default
  pprof_enabled: false                  # default
  pprof_bind_address: "127.0.0.1:6060"  # default; with pprof_enabled: true it must be a loopback IP or "localhost" or startup fails (heap holds DEKs); unchecked while pprof is off

# License
license_file: "config/license.jwt"  # default

# Encryption Configuration
encryption:
  encryption_method_alias: "current-provider"  # active for writes; must name one of the providers
  metadata_key_prefix: "s3ep-"                 # default; must match ^[a-z0-9][a-z0-9-]{2,}-$
                                               # (ADR 0009 D2) or startup fails
  providers:
    - alias: "current-provider"
      type: "aes"  # or "exit"
      description: "Provider description"   # parsed, never read
      config: { ... }

# Performance Optimizations
# The validate:"min=..." struct tags in config.go are never evaluated (no validator
# library); only the ranges written out in validateOptimizations() are enforced.
optimizations:
  streaming_segment_size: 12582912  # default, 12MB (5MB - 5GB and a multiple of 65536,
                                    # checked at startup). Two jobs: the size of one S3
                                    # part in the internal multipart producer, and the
                                    # ceiling above which a PUT stops being a single request
  multipart_session_cleanup_interval: 300  # default, seconds, minimum 1 checked at startup
                                           # (a written 0 stranded the short-part budget)
  multipart_session_idle_timeout: 3600     # default, seconds, minimum 1 checked at startup
                                           # (0 would expire every open upload); counted from the
                                           # last part an upload received (ADR 0028), not from its start
  multipart_upload_concurrency: 4          # default, parallel S3 UploadPart calls in the internal producer (1-32 checked at startup)
  max_request_document_size: 2097152  # default, 2MB (4KB - 64MB, checked at startup; a written 0
                                      # refuses the start). The ceiling on every request document
                                      # the proxy buffers whole: each bucket and object
                                      # sub-resource body and the Delete document of a batch
                                      # delete. Above it: 400 EntityTooLarge, before the backend
                                      # is called (ADR 0024 D8)
  multipart_short_part_buffer_size: 67108864  # default, 64MB (minimum 5MB when set); what all
                                              # client-driven uploads together may hold for their
                                              # short last parts (ADR 0011 D5). Over it: SlowDown;
                                              # over the whole budget: EntityTooLarge, before the
                                              # part is read
```

There is no legacy top-level backend block any more. A configuration that still
uses top-level `target_endpoint` / `region` / `access_key_id` / `secret_key` /
`use_tls` / `skip_ssl_verification` refuses the start, and the error names those
keys (ADR 0013 D11).

No environment variable overrides a configuration key: the one mechanism is a
`${VAR}` reference written into one of the fields that are expanded — the four
under `s3_backend`, the two per entry under `s3_clients`, and every string under
`encryption.providers[].config` — and an unset or empty one refuses the start.
A `${VAR}` anywhere else is kept verbatim. The license token is the exception,
read from `S3EP_LICENSE`, `S3EP_LICENSE_TOKEN` or `S3_ENCRYPTION_PROXY_LICENSE`
before `license_file` is opened. The image starts from `config/default.yaml`,
which takes every value it needs that way
([docs/developer/configuration.md](docs/developer/configuration.md)).

### Integrity is not configurable
There is no `encryption.integrity_verification` and no `off`/`lax`/`strict`/`hybrid`
mode. Integrity is inseparable from decryption (ADR 0001, ADR 0003):

- Every segment is opened with its own tag under associated data that binds the format id, the object key and the segment index. A byte the reader has not authenticated is never handed out
- The trailer authenticates the object's plaintext length and its CRC32C, and the reader verifies it before it reports `io.EOF`. A truncated, extended or reordered chain fails
- An object with no proxy metadata, or metadata naming a format this proxy does not read, is refused under an encrypting provider: `403 InvalidObjectState`, on GET, HEAD and ranged GET alike. There is no pass-through opt-out and no setting that softens it. The one provider that serves such an object is `exit`, and it decides per object — an object that *does* carry the format's metadata is still opened and still refused when its key material does not authenticate
- A wrapped data key that does not authenticate is the same answer, deliberately not a 5xx: it is a permanent state of that object and a retrying SDK must not report it as a passing outage

**The read is tail-first (ADR 0003 D14, built 2026-09-11).** A whole-object GET
reads the object's end first — one segment plus the trailer, `bytes=-65604` — and
its beginning second under `If-Match` on the first answer's ETag; HEAD reads the
trailer alone, `bytes=-40`. Both answer with `x-amz-checksum-crc32c` and with the
plaintext length the **trailer** authenticates. An object of at most one segment
still costs one backend request, a larger one costs two, and every stored byte is
fetched once. A damaged trailer, a truncation, and a stored length the trailer
contradicts are refused with `403 InvalidObjectState` before the response begins;
a fault inside a segment still cuts the body, because the status is out by then.
Under the exit provider a whole-object read stays one forward pass and carries no
checksum header: a plain object has no trailer, and deciding per object would
cost a HEAD on every read (ADR 0025).

**The upload leg (ADR 0012, built 2026-09-11).** Every checksum a
client declares is verified against the decoded plaintext — `Content-MD5`,
`x-amz-checksum-crc32`/`-crc32c`/`-crc64nvme`/`-sha1`/`-sha256`/`-sha512`/`-md5`,
as a request header or as an aws-chunked trailer — on every write path, and then
dropped: no value reaches the backend and none is stored. Anything else under
`x-amz-checksum-` answers `501 NotImplemented` (the `xxhash` family the SDK can
send, which has no stdlib hash); `-algorithm`, `-mode` and `-type` carry no
digest and pass. `CompleteMultipartUpload` is the one exemption: there the header
is the digest of the completed **object**, not of the document, so it is read
through `ReadBodyUnverified` and dropped. A mismatch is `400 BadDigest`, a
value that is not a digest of its length is `400 InvalidDigest`, and
`DeleteObjects` refuses a request carrying no digest with `400 InvalidRequest`.
The verifier is `internal/proxy/request/checksum.go`, wrapped around both parser
entry points; it holds the final payload byte back until the verdict is in, so a
refused upload stores nothing. `MapError` recognises all three sentinels —
mismatch, malformed and unsupported — so a verdict is never reported as a 5xx.
D10 — the proxy's own sealed CRC32C, served on a whole-object GET and on
HEAD — landed with ADR 0003 D14.

### Provider Types and Configuration
#### AES Provider (type: "aes")
```yaml
- alias: "aes-envelope"
  type: "aes"
  description: "AES envelope encryption"
  config:
    aes_key: "base64-encoded-256-bit-key"  # base64 of exactly 32 random bytes
```
`validateAESKey` refuses anything that is not base64 of exactly 32 bytes, and
additionally refuses a decoded value that is all printable ASCII or carries fewer
than 16 distinct byte values — that is a passphrase, not a key. Generate one with
`s3ep-keygen` or `openssl rand -base64 32`.

#### Exit Provider (type: "exit")
```yaml
- alias: "exit"
  type: "exit"
  # No config: it holds no key material. Keep the aes provider that wrote the
  # existing objects listed alongside it, or they become unreadable.
```

### Metadata Conventions
- Encryption metadata stored with prefix `s3ep-` (configurable via `encryption.metadata_key_prefix`)
- Written keys are exactly the four listed above, by `MetadataManager.BuildSegmentedMetadata` alone. It is called from `Manager.newSegmentedObject`, which every write path goes through: single-request PUT, the internal multipart producer and client-driven CreateMultipartUpload
- Only the prefixed key is ever read. The unprefixed name lies outside the proxy's namespace, so a client could set it through `x-amz-meta-*` (ADR 0009 D1)
- The prefix is the proxy's exclusive namespace in both directions: `object.UserMetadata` — the one collector all three write paths use — refuses a client `x-amz-meta-<prefix>*` header with `400 InvalidArgument` naming it (ADR 0009 D6), and `Handler.cleanMetadata` drops every key carrying the prefix on the way out, case-insensitively, on GET, HEAD and ranged responses
- **Important**: `provider_alias` is NOT stored in metadata - only used for configuration selection and logging

### Error Handling Patterns
- Use structured logging with `logrus.WithFields()` for all error reporting and context
- Log errors with appropriate levels: `logrus.Error()`, `logrus.Warn()`, `logrus.Debug()`
- Provider errors should include provider alias and type
- Include relevant context fields: bucket, key, operation, error details in log entries
- Never reflect a raw error string into a response body; the client-facing wording per S3 error code is fixed. See [docs/developer/errors.md](docs/developer/errors.md)

### File Naming Patterns
- Interfaces: `pkg/encryption/interfaces.go`
- KEK provider implementations: `pkg/encryption/keyencryption/{name}.go` (flat files, not directories)
- The codec: `pkg/encryption/dataencryption/segmented_gcm{,_io,_range}.go`
- Unit tests next to the code; the `*_coverage_test.go` files are the coverage round of 2026-09 and are ordinary unit tests
- Integration tests: `*_test.go` with `//go:build integration` under `test/integration/<package>/`, plus `test/integration/s3_signing_test.go` next to the helpers. `test/integration/conformance/` is the exception: same layout, tag `//go:build conformance`
- End-to-end suites: one package per client under `test/e2e/<client>/`, tag `//go:build e2e`, an `e2e-up.sh`/`e2e-down.sh` pair and a `versions.env` beside the tests; shared helpers in `test/e2e/harness/`
- Config examples: `config/{provider}-example.yaml` (aes-example.yaml, aes-tls-example.yaml, multi-example.yaml, exit-example.yaml)
- ADRs: `docs/adr/NNNN-<kebab-title>.md`, index in `docs/adr/README.md` — permanent
- Tickets: `docs/tickets/NNN-<slug>.md` — work lists, deleted when the work lands, referenced from nowhere else

## Common Development Tasks

### Adding a new KEK provider
1. Implement `KeyEncryptor` (`pkg/encryption/interfaces.go`) in `pkg/encryption/keyencryption/{name}.go`
2. Add the type to `KeyEncryptionType` and `CreateKeyEncryptorFromConfig` in `pkg/encryption/factory/factory.go`
3. Update `isValidProviderType` and `validateProvider` in `internal/config/config.go`, and the provider-type switch in `NewProviderManager` (`internal/orchestration/providers.go`)
4. Add config example in `config/{name}-example.yaml`
5. Add integration test in `test/integration/`

`Fingerprint()` must identify the key without revealing anything about it, and it
must be stable: it is what a stored object names, so a provider that changes its
fingerprint stops reading its own objects.

There is no DEK provider extension point. The data layer is the segment chain,
and changing it is a storage format change (ADR 0003, ADR 0017).

### Debugging Encryption Issues
- Enable debug logging: `log_level: "debug"` in config
- Check provider fingerprints in logs and metadata; a `403 InvalidObjectState` on a GET is one of three — an object this proxy did not write, a wrapped data key that does not authenticate under the fingerprint it names, or stored bytes that do not authenticate under a key that did unwrap. The message says which
- Use `TestContext` in tests for MinIO/proxy client comparison
- `optimizations.streaming_segment_size` (min 5MB, a multiple of 64 KiB, default 12MB) decides both the single-request PUT ceiling and the internal part size
- Sizes: stored and plaintext lengths convert both ways without a key (`CiphertextSize` / `PlaintextSize`). A stored length no chain of this format could have produced is an error, never a fabricated size
- Chunked encoding: the handlers route on `request.Parser.PlaintextContentLength`, which returns the declared plaintext length *and* whether that number really describes the plaintext — an aws-chunked body without `X-Amz-Decoded-Content-Length` answers false. A PUT that answers false becomes the internal multipart producer; an `UploadPart` is streamed only when the answer is true *and* the length covers whole segments and clears the backend's 5 MiB minimum, and is otherwise held in memory and sealed at Complete (ADR 0011 D5). `DecodedContentLength` (`X-Amz-Decoded-Content-Length` when present, else `Content-Length`) is the sizing hint the buffered body reader uses; nothing routes on it
- Encryption happens exactly once, in the handler's call into `orchestration.Manager`; there is no second encryption layer

### Docker Development
`docker-compose.demo.yml` (started by `./start-demo.sh`) runs `minio`, the proxy
twice (services `s3-encryption-proxy` / `s3-encryption-proxy-tls`, containers
`proxy` on :8080 and `proxy-tls` on :8443, same Containerfile build),
`proxy-healthcheck`, one S3 explorer through the proxy (service
`s3-explorer-encrypted`, container `encrypted-manager`, :8081) and `vault`.
Container names go with `docker logs`, service names with `docker compose`. The
second, direct-to-MinIO explorer is commented out in the compose file. The MinIO
console on :9001 shows the raw stored objects. Vault runs in development mode and
no proxy code talks to it — it is there for the KMS work that is not built
(ADR 0005).

## Key Files for Context
- **Main entry**: `cmd/s3-encryption-proxy/main.go`
- **Config loading**: `internal/config/config.go` (`setDefaults`, `validate`, `validateEncryption`, `validateProvider`, `validateAESKey`, `validateOptimizations`, `validateS3Clients`, `validateMonitoring`)
- **Routes**: `internal/proxy/router.go`
- **Object handler**: `internal/proxy/handlers/object/operations.go` (GET/PUT/HEAD/DELETE, `putObjectAutoMultipart`) and `range.go`
- **Multipart handler**: `internal/proxy/handlers/multipart/` (`create.go`, `upload.go`, `complete.go`, `abort.go`)
- **Encryption entry points**: `internal/orchestration/segmented.go` and `segmented_session.go`
- **The codec**: `pkg/encryption/dataencryption/segmented_gcm.go` (+ `_io.go`, `_range.go`)
- **KEK registry**: `pkg/encryption/factory/factory.go`
- **Test helpers**: `test/integration/minio_test_helper.go`; `test/e2e/harness/` for the e2e suites
- **Security design**: `SECURITY_ARCHITECTURE.md` (threat model, H-1..H-n hardening list)

## Where the flows are written down

The PUT, GET, ranged GET, HEAD, DELETE and multipart paths — including the
exit-provider branch of each — are [docs/developer/request-paths.md](docs/developer/request-paths.md)
and [docs/developer/multipart.md](docs/developer/multipart.md). The four things
that decide the branching, and nothing else, are:

- **A PUT routes on `request.Parser.PlaintextContentLength`** against
  `optimizations.streaming_segment_size`. Above it, or with a length that does not
  describe the plaintext — an aws-chunked body without
  `X-Amz-Decoded-Content-Length`, or no declared length at all — it becomes the
  internal multipart producer. `DecodedContentLength` is a sizing hint the
  buffered body reader uses, and no handler routes on it
- **A whole-object GET reads the object's end first** (`bytes=-65604`), then the
  beginning under `If-Match`; HEAD reads `bytes=-40`. Both state the plaintext
  length the **trailer** authenticates and serve `x-amz-checksum-crc32c`
  (ADR 0003 D14)
- **A ranged read of an object this proxy wrote never forwards the client's Range
  header.** The stored window is computed by `PlanRange`, which needs no key. The
  one arm that forwards it verbatim is the exit provider's pass-through, where a
  HEAD has already said the object is not this proxy's and stored bytes are the
  plaintext
- **Under the exit provider every read decides per object**, and only that
  provider pays the extra round trip it costs (ADR 0025)
# MAIN GOALS
1. Ensure data is always encrypted at rest in S3
2. encrypt and decrypt data as fast as possible (performance is key)
3. use streaming to decrease memory footprint
4. keep the architecture as simple as possible (no unnecessary layers)

# WORK ORDER
1. use sha256 hashed to compare files in tests, no hex dumps


## Always pay attention to performance. If you notice an underperforming implementation, stop what you are doing and report the problem to me.

# WE DONT NEED BACKWARD COMPATIBILITY, remove unnecessary code
