#!/usr/bin/env bash
set -euo pipefail

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

for _attempt in $(seq 1 80); do
  if curl --fail --silent "${compat_base}/ready" >/dev/null; then
    break
  fi
  sleep 0.25
done

if ! curl --fail --silent "${compat_base}/ready" >/dev/null; then
  sed -n '1,200p' "${compat_log}"
  exit 1
fi

export CONSTELLATION_COMPAT_URL="${compat_base}"
pnpm --filter @constellation/openai-compat test
python3 scripts/openai-python-compat.py

printf 'Official OpenAI client compatibility passed.\n'
