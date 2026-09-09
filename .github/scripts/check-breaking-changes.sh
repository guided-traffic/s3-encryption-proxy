#!/usr/bin/env bash
#
# check-breaking-changes.sh -- report Conventional Commits breaking-change markers.
#
# Backs the pull-request guard of ADR 0018: a breaking marker reaching main is
# what computes a major release, so every place a marker can be written has to be
# inspected before the merge button is pressed.
#
# Three sources are inspected, because all three can end up in the message the
# release analyser reads:
#   * the commits the pull request adds (merge-commit merge: each one reaches
#     main individually and is analysed on its own)
#   * the pull-request title (squash merge: it becomes the commit subject)
#   * the pull-request body (squash merge: it becomes the commit body, so a
#     BREAKING CHANGE footer typed there is analysed too)
#
# Two markers are looked for, the ones the conventionalcommits preset acts on:
#   * a "!" before the colon of the header line
#   * a line starting with BREAKING CHANGE or BREAKING-CHANGE
#
# Both patterns are deliberately broader than the parser's own: case insensitive,
# and no space required after the colon. Over-reporting costs a label that was
# not strictly needed; under-reporting costs an unplanned major release. Only one
# of those can be taken back.
#
# Usage:
#   check-breaking-changes.sh [--range <git-range>] [--message <label> <text>]...
#
#   --range      a git revision range, e.g. "origin/main..HEAD"
#   --message    a labelled message that is not a commit, e.g. a pull-request title
#
# Exit codes: 0 nothing breaking, 1 at least one marker found, 2 usage error.
#
# By hand:
#   .github/scripts/check-breaking-changes.sh --range origin/main..HEAD

set -uo pipefail

readonly HEADER_PATTERN='^[[:alnum:]]+(\([^)]*\))?!:'
readonly FOOTER_PATTERN='^[[:space:]*|]*BREAKING[ -]CHANGE[[:space:]:]'

range=""
sources=()
bodies=()

add_message() {
  sources+=("$1")
  bodies+=("$2")
}

die() {
  echo "check-breaking-changes.sh: $*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --range)
      [[ $# -ge 2 ]] || die "--range needs a revision range"
      range="$2"
      shift 2
      ;;
    --message)
      [[ $# -ge 3 ]] || die "--message needs a label and a text"
      # An empty text is not an error: a pull request may have no body.
      [[ -n "$3" ]] && add_message "$2" "$3"
      shift 3
      ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      die "unknown argument '$1'"
      ;;
  esac
done

if [[ -n "$range" ]]; then
  # -z separates commits by NUL so a message containing blank lines stays one
  # record. Each record is the full hash, a newline, then the raw message.
  while IFS= read -r -d '' record; do
    sha="${record%%$'\n'*}"
    add_message "commit ${sha:0:8}" "${record#*$'\n'}"
  done < <(git log -z --format='%H%n%B' "$range") || die "git log $range failed"
fi

if [[ ${#bodies[@]} -eq 0 ]]; then
  echo "No messages to inspect."
  exit 0
fi

found=0
for i in "${!bodies[@]}"; do
  message="${bodies[$i]}"
  header="${message%%$'\n'*}"
  reasons=()

  if grep -Eqi "$HEADER_PATTERN" <<<"$header"; then
    reasons+=("'!' before the colon of the header")
  fi
  if grep -Eqi "$FOOTER_PATTERN" <<<"$message"; then
    reasons+=("a BREAKING CHANGE footer")
  fi

  if [[ ${#reasons[@]} -gt 0 ]]; then
    found=1
    printf '%s: %s\n' "${sources[$i]}" "$header"
    for reason in "${reasons[@]}"; do
      printf '    marked breaking by %s\n' "$reason"
    done
  fi
done

if [[ $found -eq 0 ]]; then
  printf 'No breaking-change marker in %d message(s).\n' "${#bodies[@]}"
  exit 0
fi

exit 1
