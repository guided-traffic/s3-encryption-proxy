#!/usr/bin/env bash
# Stops the demo compose stack the s3cmd e2e suite ran against.
#
# The installed client stays: it is pinned, it costs a download to replace, and
# it is gitignored. Remove test/e2e/s3cmd/venv by hand to force a reinstall.
#
# Both client suites share one stack, so this also stops the other one's
# environment. That is deliberate — there is one demo stack, not one per suite.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO"
echo "stopping the demo stack"
docker compose -f docker-compose.demo.yml down
