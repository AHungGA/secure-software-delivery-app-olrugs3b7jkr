#!/usr/bin/env bash
# Start the workshop Node app with .env applied in the *shell* first.
# SSI reads DD_ENV / DD_SERVICE / DD_VERSION before Node runs -r preloads;
# sourcing .env here fixes Datadog env showing as "none".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

exec node -r ./dotenv-load.js src/index.js "$@"
