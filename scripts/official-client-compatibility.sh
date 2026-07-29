#!/usr/bin/env bash
set -euo pipefail

compat_startup_timeout="${CONSTELLATION_COMPAT_STARTUP_TIMEOUT_SECONDS:-600}"
if [[ ! "${compat_startup_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'CONSTELLATION_COMPAT_STARTUP_TIMEOUT_SECONDS must be a positive integer.\n' >&2
  exit 2
fi

compat_dir="$(mktemp -d /tmp/constellation-compat.XXXXXX)"
compat_port="${CONSTELLATION_COMPAT_PORT:-4320}"
compat_base="http://127.0.0.1:${compat_port}"
compat_log="${compat_dir}/daemon.log"

cargo run --quiet -p constellationd -- \
  --bind "127.0.0.1:${compat_port}" \
  --database-url "sqlite://${compat_dir}/constellation.db?mode=rwc" \
  --data-dir "${compat_dir}/data" \
  --ephemeral-identity \
  >"${compat_log}" 2>&1 &
compat_pid=$!

cleanup() {
  kill "${compat_pid}" 2>/dev/null || true
  wait "${compat_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ready=false
deadline=$((SECONDS + compat_startup_timeout))
while ((SECONDS < deadline)); do
  if curl --fail --silent "${compat_base}/ready" >/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "${compat_pid}" 2>/dev/null; then
    wait "${compat_pid}" || true
    sed -n '1,200p' "${compat_log}"
    printf 'Constellation daemon exited before becoming ready.\n' >&2
    exit 1
  fi
  sleep 0.25
done

if [[ "${ready}" != "true" ]]; then
  sed -n '1,200p' "${compat_log}"
  printf 'Constellation daemon did not become ready within %s seconds.\n' \
    "${compat_startup_timeout}" >&2
  exit 1
fi

export CONSTELLATION_COMPAT_URL="${compat_base}"
pnpm --filter @constellation/openai-compat test
python3 scripts/openai-python-compat.py

printf 'Official OpenAI client compatibility passed.\n'
