#!/usr/bin/env bash
set -euo pipefail

primary_port="${CONSTELLATION_PRIMARY_PORT:-4321}"
standby_port="${CONSTELLATION_STANDBY_PORT:-4322}"
controller_startup_timeout="${CONSTELLATION_CONTROLLER_STARTUP_TIMEOUT_SECONDS:-600}"
controller_failover_timeout="${CONSTELLATION_CONTROLLER_FAILOVER_TIMEOUT_SECONDS:-60}"

if ! [[ "${controller_startup_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  echo 'CONSTELLATION_CONTROLLER_STARTUP_TIMEOUT_SECONDS must be a positive integer.' >&2
  exit 2
fi
if ! [[ "${controller_failover_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  echo 'CONSTELLATION_CONTROLLER_FAILOVER_TIMEOUT_SECONDS must be a positive integer.' >&2
  exit 2
fi

failover_dir="$(mktemp -d /tmp/constellation-failover.XXXXXX)"
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

wait_for_endpoint() {
  local pid="$1"
  local endpoint="$2"
  local timeout="$3"
  local log="$4"
  local description="$5"
  local deadline=$((SECONDS + timeout))

  while (( SECONDS < deadline )); do
    if curl --fail --silent "${endpoint}" >/dev/null; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      echo "${description} exited before becoming available." >&2
      sed -n '1,200p' "${log}"
      return 1
    fi
    sleep 0.25
  done

  echo "${description} was not available within ${timeout} seconds." >&2
  sed -n '1,200p' "${log}"
  return 1
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

wait_for_endpoint \
  "${primary_pid}" "${primary_base}/ready" "${controller_startup_timeout}" \
  "${failover_dir}/primary.log" 'Primary controller'

standby_pid="$(start_controller "${standby_port}" "${failover_dir}/standby" "${failover_dir}/standby.log")"
wait_for_endpoint \
  "${standby_pid}" "${standby_base}/health" "${controller_startup_timeout}" \
  "${failover_dir}/standby.log" 'Standby controller'
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
wait_for_endpoint \
  "${standby_pid}" "${standby_base}/ready" "${controller_failover_timeout}" \
  "${failover_dir}/standby.log" 'Standby controller takeover'
curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d '{"model":"constellation/mock","messages":[{"role":"user","content":"takeover verified"}]}' \
  "${standby_base}/v1/chat/completions" \
  >"${failover_dir}/completion.json"
grep -q 'takeover verified' "${failover_dir}/completion.json"

printf 'Controller fencing and takeover passed.\n'
