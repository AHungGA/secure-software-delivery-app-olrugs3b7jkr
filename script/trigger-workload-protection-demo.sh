#!/usr/bin/env bash
# Deprecated name: delegates to trigger-cws-workload-protection-demo.sh (CWS / Workload Protection).
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/trigger-cws-workload-protection-demo.sh" "$@"
