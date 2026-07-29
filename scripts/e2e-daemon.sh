#!/usr/bin/env bash
set -euo pipefail

if test "$#" -ne 1 || ! [[ "$1" =~ ^[0-9]+$ ]]; then
  echo "usage: $0 PORT" >&2
  exit 2
fi

e2e_port="$1"
e2e_root="$(mktemp -d /tmp/constellation-e2e.XXXXXX)"
daemon_pid=""

cleanup() {
  if test -n "${daemon_pid}"; then
    kill "${daemon_pid}" 2>/dev/null || true
    wait "${daemon_pid}" 2>/dev/null || true
  fi
  case "${e2e_root}" in
    /tmp/constellation-e2e.*) rm -rf -- "${e2e_root}" ;;
    *) echo "refusing unexpected E2E path: ${e2e_root}" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

cargo run --quiet -p constellationd -- \
  --bind "127.0.0.1:${e2e_port}" \
  --database-url "sqlite://${e2e_root}/constellation.db?mode=rwc" \
  --data-dir "${e2e_root}/data" \
  --ephemeral-identity &
daemon_pid=$!
wait "${daemon_pid}"
