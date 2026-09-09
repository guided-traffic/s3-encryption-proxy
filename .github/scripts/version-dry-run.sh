#!/usr/bin/env bash
# The dry run of ADR 0018 D6: compute the next release version for a pull request
# with the release tool itself, print it, and check it against the release:major
# label. Pull requests only; it writes no tag, no changelog and no release.
#
# Environment:
#   PR_BRANCH              head branch of the pull request; checked out, full history and tags
#   HAS_MAJOR_LABEL        "true" when the pull request carries the release:major label
#   GITHUB_TOKEN           semantic-release verifies push access with `git push --dry-run`
#                          before it analyses anything, even in dry-run mode
#   SEMANTIC_RELEASE_ARGS  extra arguments, used by the local test only
#   GITHUB_STEP_SUMMARY    optional; the job summary the verdict is appended to
#
# Exit codes: 0 verdict ok; 1 verdict failed, or no version could be computed.
set -euo pipefail

: "${PR_BRANCH:?PR_BRANCH is required}"
HAS_MAJOR_LABEL="${HAS_MAJOR_LABEL:-false}"

last_tag=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)
last_version="${last_tag#v}"

# --no-ci: on a pull_request run the CI detection would stop before analysing.
# --branches: the pull request branch stands in for the release branch.
# GITHUB_REF: on a pull_request run it names the merge ref, refs/pull/N/merge, and
# semantic-release takes the branch to analyse from it; it has to be the branch.
# shellcheck disable=SC2086
if ! log=$(GITHUB_REF="refs/heads/${PR_BRANCH}" npx semantic-release --dry-run --no-ci --branches "$PR_BRANCH" ${SEMANTIC_RELEASE_ARGS:-} 2>&1); then
  printf '%s\n' "$log"
  echo "::error::the semantic-release dry run failed"
  exit 1
fi
printf '%s\n' "$log"

next=$(printf '%s\n' "$log" | sed -n 's/.*next release version is \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | tail -n 1)
if [ -z "$next" ]; then
  if printf '%s\n' "$log" | grep -q 'no new version is released'; then
    next="none"
  else
    echo "::error::the dry run printed neither a next version nor 'no new version is released'"
    exit 1
  fi
fi

is_major=false
if [ "$next" != "none" ] && { [ -z "$last_version" ] || [ "${next%%.*}" -gt "${last_version%%.*}" ]; }; then
  is_major=true
fi

verdict="ok"
if [ "$HAS_MAJOR_LABEL" = "true" ] && [ "$is_major" != "true" ]; then
  verdict="release:major is set, but the computed version is ${next}: no commit carries a breaking marker"
elif [ "$HAS_MAJOR_LABEL" != "true" ] && [ "$is_major" = "true" ]; then
  verdict="the computed version ${next} is a major bump without the release:major label"
fi

echo "last release: ${last_tag:-none}; computed next version: ${next}; release:major label: ${HAS_MAJOR_LABEL}; verdict: ${verdict}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Version dry run"
    echo
    echo "| Last release | Computed next version | release:major label | Verdict |"
    echo "|---|---|---|---|"
    echo "| ${last_tag:-none} | ${next} | ${HAS_MAJOR_LABEL} | ${verdict} |"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$verdict" != "ok" ]; then
  echo "::error::${verdict}"
  exit 1
fi
