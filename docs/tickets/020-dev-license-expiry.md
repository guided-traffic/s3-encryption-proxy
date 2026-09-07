# Ticket 020: Development license expiry, and a CI check that says so early

## Status (2026-09-06)

**Open, and the most time-critical of the Velero follow-ups.** `config/license.jwt`
carries `exp = 1791225552`, which is **2026-10-05 18:39:12 UTC** — 29 days from
today. On that date the local demo stack, both integration transports and the
Velero e2e stop working at once, and so does the CI job, which uses a *second*
copy of the token in the `S3EP_LICENSE_TOKEN` GitHub secret whose expiry nobody
can see. This ticket carries [D-18](README.md#decisions-d-1-to-d-19) and depends
on nothing else: it does not touch the storage format, the handlers or the
config schema, so it can land before, after or beside the v2 work.

---

## Context

Every encryption provider except `none` refuses to start without a valid
license. The gate is [`ValidateProviderType`](../../internal/license/validator.go#L127),
called from [`validateLicenseAndEncryption`](../../internal/config/config.go#L504)
at [config.go:527](../../internal/config/config.go#L527), reached from `validate`
at [config.go:400](../../internal/config/config.go#L400), which `Load` calls at
[config.go:238](../../internal/config/config.go#L238). The failure is fatal at
[main.go:78](../../cmd/s3-encryption-proxy/main.go#L78).

**The failure does not look like an expiry.** An expired token is rejected at
[validator.go:93](../../internal/license/validator.go#L93), and the reason
("license expired on 2026-10-05 18:39:12 UTC", built at
[validator.go:96](../../internal/license/validator.go#L96)) is logged only as a
`Warn` by [logger.go:14](../../internal/license/logger.go#L14). The error that
actually stops the process comes from
[validator.go:130](../../internal/license/validator.go#L130) and reads:

```
config validation failed: license required for encryption provider type 'aes'
Please obtain a license from https://s3ep.com
Or start with a provider of type 'none' for read-only mode
```

So the operator-visible signal on 2026-10-05 is "license required" — the message
for a *missing* license — on a machine where the license file is right there.
In the e2e that surfaces even further from the cause: the guard in
[e2e-up.sh:36](../../test/e2e/velero/e2e-up.sh#L36) only checks that the token is
non-empty, so bring-up proceeds, the proxy pod CrashLoopBackOffs, and the visible
failure is a BackupStorageLocation that never goes Available.

A proxy that is already running does not survive the date either: the runtime
monitor ([validator.go:142](../../internal/license/validator.go#L142)) ticks every
60 minutes and calls `os.Exit(1)` at
[validator.go:200](../../internal/license/validator.go#L200) once the expiry passes.
Under Kubernetes that is a restart loop; under compose the container stops.

**Two copies, one of them invisible.** The token reaches its consumers by two
independent routes, and only the first is inspectable from a checkout:

| Copy | Where | Consumers |
|---|---|---|
| `config/license.jwt` | untracked, ignored at [.gitignore:43](../../.gitignore#L43) | `docker compose` env pass-through ([docker-compose.demo.yml:58](../../docker-compose.demo.yml#L58), [:100](../../docker-compose.demo.yml#L100)), the e2e fallback ([e2e-up.sh:38](../../test/e2e/velero/e2e-up.sh#L38)), and the integration suites, which read the file directly when the env var is unset ([aes_provider_test.go:43](../../test/integration/encryption-modes/aes_provider_test.go#L43), [rsa_provider_test.go:43](../../test/integration/encryption-modes/rsa_provider_test.go#L43)) |
| `secrets.S3EP_LICENSE_TOKEN` | GitHub repository secret | [release.yml:208](../../.github/workflows/release.yml#L208) (compose bring-up), [:264](../../.github/workflows/release.yml#L264) (`make test-integration`), [:275](../../.github/workflows/release.yml#L275) (`make test-integration-tls`), [:287](../../.github/workflows/release.yml#L287) (`make test-integration-performance`), [:513](../../.github/workflows/release.yml#L513) (`make e2e-up`) |

Refreshing one and not the other leaves half the pipeline dead. Nothing today
reads the `exp` claim of either.

A third copy appears wherever the image is built from a tree that has the file:
`.dockerignore` does not exclude `config/`, so `COPY . .` and
[Containerfile:70](../../Containerfile#L70) put it at `/app/config/license.jwt`.
Verified by copying it back out of the locally built
`s3-encryption-proxy-s3-encryption-proxy:latest`. A CI-built image has none,
because the file is gitignored — so this copy is a leak to keep out of any
pushed image, not a route to rely on.

**Threat-model framing.** This is not a security control, and it should not be
dressed as one — the license gate is a commercial one. But rule 2 of the
[three rules](../../SECURITY_ARCHITECTURE.md#12-three-rules) applies in its general form: a
deadline that lives only in a person's memory is worse than no deadline, because
it gets relied upon. The reason it belongs in CI is that CI is the only place
that can see the secret's copy at all.

---

## Scope

**In**

- Reissue `config/license.jwt` before 2026-10-05.
- Reissue and refresh the `S3EP_LICENSE_TOKEN` GitHub repository secret.
- A CI step that decodes the `exp` claim of whichever token the job holds and
  **fails** when it expires within 14 days.
- A scheduled trigger, because the current trigger set cannot deliver a two-week
  warning on its own (see below).
- Delete `make setup-dev-license`, which invokes a script that does not exist.
- Document the reissue procedure where an operator will look for it.
- Get the license *signing* key out of `build/`, where `make clean` deletes it.

**Out**

- Any change to how the license is validated, loaded or enforced
  ([internal/license/](../../internal/license/) stays as it is).
- Any change to the claim set or to `cmd/license-tool`. `generate-license` is
  interactive and prints the token to stdout; that stays, and the procedure
  documents the copy step rather than growing a flag.
- Removing the license gate, or making `none` the CI provider to dodge it —
  that would delete exactly the coverage the suites exist for.

**Scope amended 2026-09-07 (D-25).** The "Out" list above excluded any change to how the
license is validated. Two findings from [024](024-coverage-round-findings.md) are about
exactly that, no other ticket covers the license runtime, and the owner assigned them
here:

- **A-1 — `Stop()` blocks forever without a valid license.** `StartRuntimeMonitoring`
  returns before starting the goroutine whose deferred close is the only thing that ever
  closes `doneChan`; `Stop()` then blocks on it, and `main` calls `Stop()` on the shutdown
  path. Every unlicensed shutdown has to be killed, which under Kubernetes is every rollout
  waiting out the grace period. Fix: close `doneChan` on the early-return path, with a
  test that `Stop()` returns when monitoring never started.
- **A-2 — a token without `exp` is accepted and then terminates the proxy after 60
  minutes.** Validation checks expiry only when the claim is present, `ExpiresAt` keeps the
  zero time, and the hourly check `now.After(ExpiresAt)` is always true, so `os.Exit(1)`
  fires with a log line blaming an expiry that does not exist. Decided: **a token without
  `exp` is rejected at validation.** A perpetual license is a business decision and must be
  spelled out as an explicit claim if it is ever wanted, never produced by an omission. Test:
  a token with no `exp` fails `ValidateLicense`, and `license-tool` cannot mint one.

**Closes:** D-18, D-25. **Touches no other item**: not D-1/N-1..N-8 (storage format
v2), not D-9, not D-6/D-7/N-5. Nothing here is blocked by, or blocks, the v2
ticket.

---

## What is in the tree today, verified

### The token

Decoded from `config/license.jwt` on 2026-09-06:

| Claim | Value |
|---|---|
| `alg` | `RS256` (header) |
| `iss` / `sub` / `aud` | `s3ep.com` / `s3-encryption-proxy-license` / `["s3-encryption-proxy"]` |
| `iat`, `nbf` | 1759689552 — 2025-10-05 18:39:12 UTC |
| `exp` | **1791225552 — 2026-10-05 18:39:12 UTC** |
| `licensee_name` / `licensee_company` | `Hans Fischer` / `Development of s3ep` |
| `k8s_cluster_id` | `""` (empty; validation is a TODO at [logger.go:42](../../internal/license/logger.go#L42)) |

Its signature verifies against the 4096-bit RSA public key embedded at
[validator.go:22](../../internal/license/validator.go#L22) (checked with
`openssl dgst -sha256 -verify`).

### Issuing a new one

[`make generate-license`](../../Makefile#L47) builds `cmd/license-tool` into
`build/` and runs it. The tool looks for `license_private_key.pem` and
`license_public_key.pem` **next to its own binary**
([main.go:84](../../cmd/license-tool/main.go#L84)), prompts for licensee, company,
note, cluster id and a duration in `2y100d` form
([main.go:172](../../cmd/license-tool/main.go#L172), parsed at
[main.go:207](../../cmd/license-tool/main.go#L207)), builds the claims at
[main.go:188](../../cmd/license-tool/main.go#L188) and prints the signed token to
stdout ([main.go:78](../../cmd/license-tool/main.go#L78)). It does not write
`config/license.jwt`; that copy is manual.

[`make setup-dev-license`](../../Makefile#L42) runs `./setup-dev-license.sh`. **That
script does not exist** — not in the working tree, not in `git ls-files`. The
target has been broken for as long as it has been referenced, and it is the
command both the findings doc and the e2e error message
([e2e-up.sh:41](../../test/e2e/velero/e2e-up.sh#L41)) tell the operator to run.

### The signing key is one `make clean` away from gone

`build/license_private_key.pem` (mode 0600, untracked; `build/` is ignored at
[.gitignore:34](../../.gitignore#L34)) is the private half of the key embedded in
the binary — verified: the SPKI DER SHA-256 of `build/license_public_key.pem` is
`f45b2b0d6e8a7b6531685669eda8d6ff5f78465f92a45830e39fc2c3e8fb0659`, and
`config/license.jwt` verifies under it.

[`make clean`](../../Makefile#L165) does `rm -rf build/`. There is no second copy in
this repository. Running one routine target destroys the only key that can ever
issue a license the shipped binary accepts — after which every provider except
`none` is permanently unusable, for the demo stack, the suites and any
deployment. Fixing the license clock while leaving the key in the blast radius
of `make clean` would be treating the symptom.

---

## The CI check

### Where it goes, and why also on a schedule

The step belongs in **`.github/workflows/release.yml`, job `integration-tests`**
([release.yml:180](../../.github/workflows/release.yml#L180)), as its **first**
step — before the Docker Hub login and before
`docker compose ... up -d --build` at
[release.yml:206](../../.github/workflows/release.yml#L206). That job is the first
consumer of the secret, it is required by `semantic-release`
([release.yml:549](../../.github/workflows/release.yml#L549)), and failing there
before a 60-minute suite is the cheapest possible place to learn about it.

The same step goes into **job `e2e-velero`**
([release.yml:459](../../.github/workflows/release.yml#L459)), before
`make e2e-up` at [release.yml:511](../../.github/workflows/release.yml#L511). That
job holds the secret independently and would otherwise spend ~20 minutes
building a kind cluster to fail on a BSL timeout.

That alone does **not** deliver the promised two-week warning. `release.yml`
triggers on push to `main`, PR to `main` and `workflow_dispatch`
([release.yml:3](../../.github/workflows/release.yml#L3)) — nothing else. If the
repository is quiet for two weeks, the window is never sampled and the check
first fires on the day someone needs a green pipeline. So a second, tiny
workflow runs the same script on a daily cron:
`.github/workflows/license-expiry.yml`, `on: schedule` + `workflow_dispatch`,
one job, one step. A separate file rather than a `schedule:` entry on
`release.yml`, because a cron on that workflow would also need `if:` guards on
every heavy job and on `semantic-release` — more surface, more ways to
accidentally cut a release from a timer.

**Deliberate tradeoff, named:** a failing check blocks `semantic-release`
14 days before expiry, so a release can be stopped by a license clock rather
than by a defect. That is the point. A warning annotation would be a control
that exists only in documentation; reissuing takes minutes, and the alternative
is the pipeline going red with a message that says the wrong thing.

### The script

One implementation, used by both jobs and by a developer at a workstation —
same principle as `e2e-up.sh` being the script CI runs. POSIX shell, no new
dependency; the repo already keeps operational scripts at the root
(`start-demo.sh`, `performance.sh`). Verified against `config/license.jwt` on
darwin (BSD `base64`) — it reports `days_left=29` and exits 0 at
`LICENSE_WARN_DAYS=14`, exits 1 at `LICENSE_WARN_DAYS=30`. GNU `base64 -d`
takes the same flag.

`check-license-expiry.sh` (repo root, mode 0755):

```sh
#!/usr/bin/env sh
# Fail when the license token expires within LICENSE_WARN_DAYS (default 14).
# Reads S3EP_LICENSE_TOKEN, else config/license.jwt, so CI checks the secret's
# copy and a workstation checks the local one.
set -eu

WARN_DAYS="${LICENSE_WARN_DAYS:-14}"

token="${S3EP_LICENSE_TOKEN:-}"
if [ -z "$token" ] && [ -f config/license.jwt ]; then
  token="$(tr -d '\n\r' < config/license.jwt)"
fi
if [ -z "$token" ]; then
  echo "no license token: set S3EP_LICENSE_TOKEN or provide config/license.jwt" >&2
  exit 1
fi

# The JWT payload is the second dot-separated field, base64url, unpadded.
payload="$(printf '%s' "$token" | cut -d. -f2)"
case $(( ${#payload} % 4 )) in
  2) payload="${payload}==" ;;
  3) payload="${payload}=" ;;
  1) echo "malformed JWT payload" >&2; exit 1 ;;
esac
json="$(printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null)" || {
  echo "license token is not a decodable JWT" >&2; exit 1; }

exp="$(printf '%s' "$json" \
  | grep -o '"exp"[[:space:]]*:[[:space:]]*[0-9][0-9]*' | head -1 | tr -dc '0-9')"
[ -n "$exp" ] || { echo "license token carries no exp claim" >&2; exit 1; }

now="$(date -u +%s)"
days_left=$(( (exp - now) / 86400 ))
echo "license expires $(date -u -r "$exp" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null \
      || date -u -d "@$exp" '+%Y-%m-%d %H:%M:%S UTC') (${days_left} days left)"

if [ "$exp" -le "$now" ]; then
  echo "::error::the S3EP license has expired; reissue it and refresh BOTH copies (config/license.jwt and the S3EP_LICENSE_TOKEN secret) - see README" >&2
  exit 1
fi
if [ "$exp" -le $(( now + WARN_DAYS * 86400 )) ]; then
  echo "::error::the S3EP license expires in ${days_left} days (threshold ${WARN_DAYS}); reissue it and refresh BOTH copies (config/license.jwt and the S3EP_LICENSE_TOKEN secret) - see README" >&2
  exit 1
fi
```

The `date` line is the only part that needs both dialects: `date -u -r <epoch>`
on BSD, `date -u -d @<epoch>` on GNU; the `||` picks whichever works. Everything
else is portable.

This is the same shape as the certificate freshness check the e2e already
relies on ([gen-certs.sh:28](../../test/ssl-setup/gen-certs.sh#L28), 30-day
`openssl x509 -checkend`) — that one heals itself by regenerating, which a
license cannot do, so this one fails instead.

### The workflow steps

In `integration-tests`, immediately after `Checkout`
([release.yml:185](../../.github/workflows/release.yml#L185)):

```yaml
      # Fails 14 days before the token expires, not on the morning the whole
      # pipeline stops with "license required for encryption provider type".
      # Checks the secret's copy, which is invisible from a checkout.
      - name: Check the license token expiry
        run: ./check-license-expiry.sh
        env:
          S3EP_LICENSE_TOKEN: ${{ secrets.S3EP_LICENSE_TOKEN }}
```

The identical step in `e2e-velero`, after its `Checkout`
([release.yml:464](../../.github/workflows/release.yml#L464)).

And `.github/workflows/license-expiry.yml`:

```yaml
name: License Expiry
on:
  schedule:
    - cron: '17 6 * * *'
  workflow_dispatch:
jobs:
  license-expiry:
    name: License Expiry
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v7
      - run: ./check-license-expiry.sh
        env:
          S3EP_LICENSE_TOKEN: ${{ secrets.S3EP_LICENSE_TOKEN }}
```

---

## Work breakdown

- [ ] **Move the signing key out of `build/`.** Copy `license_private_key.pem`
      and `license_public_key.pem` to the offline location the repository owner
      keeps secrets in, verify the copy still verifies `config/license.jwt`
      (`openssl dgst -sha256 -verify`), and only then continue. Nothing else in
      this ticket is safe to do before this. Do **not** commit them.
- [ ] Point `cmd/license-tool` at that location, or document the copy-into-`build/`
      step in the procedure below — whichever costs less code. `findRSAKeys`
      ([main.go:84](../../cmd/license-tool/main.go#L84)) only looks next to the
      binary today.
- [ ] **Reissue `config/license.jwt`** with `make generate-license`. Same
      licensee, company and note as the current token; duration `2y` (expiry
      about 2028-09; long enough that this ticket does not recur every quarter,
      short enough to stay a development license). Write the token to
      `config/license.jwt` with no trailing newline, and confirm the file is
      still ignored (`git check-ignore -v config/license.jwt` →
      [.gitignore:43](../../.gitignore#L43)).
- [ ] **Refresh the `S3EP_LICENSE_TOKEN` repository secret** at
      `guided-traffic/s3-encryption-proxy` → Settings → Secrets and variables →
      Actions, with the *same* token. One token in both places from now on, so
      the two copies cannot drift into separate expiries again.
- [ ] Add `check-license-expiry.sh` at the repo root, mode 0755, exactly as
      above.
- [ ] Add a `check-license` target to the [Makefile](../../Makefile) that runs it,
      register it in `.PHONY` ([Makefile:1](../../Makefile#L1)) and in the help
      block ([Makefile:203](../../Makefile#L203)).
- [ ] **Delete the broken `setup-dev-license` target**
      ([Makefile:42](../../Makefile#L42)) and its `.PHONY` entry —
      `./setup-dev-license.sh` does not exist and never has in this tree, and
      `generate-license` already does the job (no backward compatibility
      wanted; do not resurrect the script).
- [ ] Update the two places that name the dead target: the e2e error message at
      [e2e-up.sh:41](../../test/e2e/velero/e2e-up.sh#L41) and the findings doc's
      D-18 entry.
- [ ] Add the expiry step to `integration-tests`
      ([release.yml:180](../../.github/workflows/release.yml#L180)) as its first
      step after `Checkout`.
- [ ] Add the same step to `e2e-velero`
      ([release.yml:459](../../.github/workflows/release.yml#L459)) before
      `make e2e-up`.
- [ ] Add `.github/workflows/license-expiry.yml` with the daily cron.
- [ ] **Document the procedure** in [README.md](../../README.md), as a
      "Development license" subsection under `## Development`
      ([README.md:761](../../README.md#L761)) (`## License` at
      [README.md:784](../../README.md#L784) is the project's own Apache licence and
      is a different subject — do not merge the two). Both line numbers moved in
      `087f739`; the headings are what to search for. It must state, in this
      order: that every provider except `none` needs a token
      ([validator.go:127](../../internal/license/validator.go#L127)); that the
      token reaches a container through `S3EP_LICENSE_TOKEN` rather than through
      the `license_file` path, because `license_file: "config/license.jwt"`
      ([config/aes-example.yaml:72](../../config/aes-example.yaml#L72)) is relative
      to the working directory and resolves inside the image *only when the file
      was in the build context* — `WORKDIR` is `/app` and `config/` is copied in
      at [Containerfile:70](../../Containerfile#L70), while a CI build has no such
      file (it is gitignored), so the env var is the only route that always
      works; the two copies and that **both** must be refreshed; that a locally
      built image therefore carries the token at `/app/config/license.jwt` and
      must not be pushed; `make generate-license` and
      where the signing key lives; `make check-license`; and what the failure
      looks like when it lapses, verbatim, so the next person can search for it.
- [x] ~~While in the README: `See [Development Guide](./docs/development.md)` (quoted, not a live link) pointed at a file that does not exist.~~ **Done in `087f739`**, which
      removed the link while correcting what the README claimed; `grep -n
      "docs/development.md" README.md` returns nothing. Nothing to do, kept so
      the item is not rediscovered.

---

## Success criteria

- [ ] `sh check-license-expiry.sh` prints the new expiry and exits 0 with the
      reissued `config/license.jwt` in place.
- [ ] `LICENSE_WARN_DAYS=100000 sh check-license-expiry.sh` exits 1 and prints
      the reissue instruction — proves the failure branch, not just the pass.
- [ ] `S3EP_LICENSE_TOKEN=garbage sh check-license-expiry.sh` exits 1; so does
      an empty token in a directory without `config/license.jwt`.
- [ ] The token in the GitHub secret and the token in `config/license.jwt` decode
      to the **same** `exp` and `jti`. Check the secret's copy through the CI
      step's log line, not by printing the token.
- [ ] `make test-unit` green (nothing here touches Go code unless the
      `cmd/license-tool` key path is changed; if it is, its behaviour is covered
      by running the tool once and verifying the token it emits).
- [ ] `./start-demo.sh` brings both proxies up on the reissued token, and
      `make test-integration` **and** `make test-integration-tls` are green —
      these are the suites that read `config/license.jwt` directly
      ([aes_provider_test.go:43](../../test/integration/encryption-modes/aes_provider_test.go#L43)),
      so they are the ones that would have broken silently.
- [ ] `make test-integration-performance` green (isolated package, unchanged
      numbers expected — this ticket touches no data path).
- [ ] `make e2e-up && make test-e2e-velero && make e2e-down`: all 13 scenarios
      pass on the reissued token, proving the Helm secret path
      ([e2e-up.sh:148](../../test/e2e/velero/e2e-up.sh#L148) →
      [values-proxy.yaml:78](../../test/e2e/velero/values-proxy.yaml#L78)) took it.
- [ ] One CI run on the PR shows the new step passing in both
      `integration-tests` and `e2e-velero`, with the days-left line in the log.
- [ ] `workflow_dispatch` on `license-expiry.yml` runs green once, so the cron
      is known to work before it is relied on.
- [ ] A copy of the signing key exists outside `build/`, verified by re-verifying
      `config/license.jwt` against its public half.

---

## Risks and open questions

- **The signing key is the real single point of failure**, not the token. It is
  untracked, has no second copy in this repository, and
  [`make clean`](../../Makefile#L165) removes it. If it is already gone from this
  machine, everything above is impossible and the ticket becomes "generate a new
  keypair, change the embedded key at
  [validator.go:22](../../internal/license/validator.go#L22), rebuild every image,
  and reissue" — a release, not a chore. **Verify the key is present before
  planning anything else.**
- **A 14-day threshold with a daily cron only helps if someone reads the
  notification.** Whether the repository is configured to notify on a failed
  scheduled workflow is **not verified** from the tree. If it is not, the check
  is a control that exists only in configuration. Worth confirming, and worth
  considering whether the cron job should open an issue rather than only fail.
- **`secrets.S3EP_LICENSE_TOKEN` is not available to workflow runs from forked
  PRs.** The check would then fail with "no license token". The
  `integration-tests` job would already be failing on such a PR for the same
  reason, so this adds no new breakage — but it is **unverified** whether this
  repository ever sees fork PRs, and the new step would move the failure earlier
  and make it look like a licensing problem. If fork PRs matter, guard both
  steps with `if: github.event.pull_request.head.repo.fork != true`.
- **Two years is a guess.** A longer duration reduces the recurrence; a shorter
  one keeps the expiry path exercised. The check makes either safe, which is the
  point — pick the duration for the licensing story, not for the CI risk.
- **The runtime monitor's own 30-day warning
  ([validator.go:167](../../internal/license/validator.go#L167),
  [logger.go:55](../../internal/license/logger.go#L55)) already exists and did not
  help**, because nobody reads proxy startup logs during a green CI run. That is
  the evidence that the warning has to be a failing step rather than a log line;
  it is not a reason to change the monitor.
- **`k8s_cluster_id` validation is a TODO**
  ([logger.go:42](../../internal/license/logger.go#L42)), so the reissued token's
  empty cluster id is accepted everywhere. If that TODO is ever implemented, a
  development token pinned to no cluster may start behaving differently —
  out of scope here, noted so it is not a surprise.
- **The check reads the payload without verifying the signature.** That is
  deliberate: it answers "when does this expire", and the binary is the thing
  that verifies. It does mean a syntactically valid but unsigned token would
  pass the CI check and fail at startup. The integration suite catches that
  within the same job, minutes later.
