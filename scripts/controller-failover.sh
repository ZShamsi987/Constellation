#!/usr/bin/env bash
set -euo pipefail

failover_dir="$(mktemp -d /tmp/constellation-failover.XXXXXX)"
primary_port="${CONSTELLATION_PRIMARY_PORT:-4321}"
standby_port="${CONSTELLATION_STANDBY_PORT:-4322}"
primary_base="http://127.0.0.1:${primary_port}"
standby_base="http://127.0.0.1:${standby_port}"
database_url="sqlite://${failover_dir}/constellation.db?mode=rwc"

start_controller() {
  local port="$1"
  local data="$2"
  local log="$3"
  cargo run --quiet -p constellationd -- \
    --bind "127.0.0.1:${port}" \
    --database-url "${database_url}" \
    --data-dir "${data}" \
    --ephemeral-identity \
    >"${log}" 2>&1 &
  echo "$!"
}

primary_pid="$(start_controller "${primary_port}" "${failover_dir}/primary" "${failover_dir}/primary.log")"
standby_pid=""

cleanup() {
  if test -n "${standby_pid}"; then
    kill "${standby_pid}" 2>/dev/null || true
    wait "${standby_pid}" 2>/dev/null || true
  fi
  kill "${primary_pid}" 2>/dev/null || true
  wait "${primary_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for _attempt in $(seq 1 80); do
  curl --fail --silent "${primary_base}/ready" >/dev/null && break
  sleep 0.25
done
curl --fail --silent "${primary_base}/ready" >/dev/null

standby_pid="$(start_controller "${standby_port}" "${failover_dir}/standby" "${failover_dir}/standby.log")"
for _attempt in $(seq 1 80); do
  curl --fail --silent "${standby_base}/health" >/dev/null && break
  sleep 0.25
done
curl --fail --silent "${standby_base}/health" >/dev/null
if curl --fail --silent "${standby_base}/ready" >/dev/null; then
  echo 'Standby reported ready before it owned the fencing lease' >&2
  exit 1
fi
if curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d '{"model":"constellation/mock","messages":[{"role":"user","content":"must be fenced"}]}' \
  "${standby_base}/v1/chat/completions" >/dev/null; then
  echo 'Standby accepted a write before takeover' >&2
  exit 1
fi

kill "${primary_pid}"
wait "${primary_pid}" 2>/dev/null || true
for _attempt in $(seq 1 100); do
  curl --fail --silent "${standby_base}/ready" >/dev/null && break
  sleep 0.25
done
curl --fail --silent "${standby_base}/ready" >/dev/null || {
  sed -n '1,200p' "${failover_dir}/standby.log"
  exit 1
}
curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d '{"model":"constellation/mock","messages":[{"role":"user","content":"takeover verified"}]}' \
  "${standby_base}/v1/chat/completions" \
  >"${failover_dir}/completion.json"
grep -q 'takeover verified' "${failover_dir}/completion.json"

printf 'Controller fencing and takeover passed.\n'
