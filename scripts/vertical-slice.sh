#!/usr/bin/env bash
set -euo pipefail

slice_port="${CONSTELLATION_TEST_PORT:-4318}"
slice_startup_timeout="${CONSTELLATION_SLICE_STARTUP_TIMEOUT_SECONDS:-600}"
enrollment_pid=""
worker_pid=""

if ! [[ "${slice_startup_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  echo 'CONSTELLATION_SLICE_STARTUP_TIMEOUT_SECONDS must be a positive integer.' >&2
  exit 2
fi

slice_dir="$(mktemp -d /tmp/constellation-slice.XXXXXX)"
slice_base="http://127.0.0.1:${slice_port}"
slice_log="${slice_dir}/daemon.log"

cargo run -p constellationd -- \
  --bind "127.0.0.1:${slice_port}" \
  --database-url "sqlite://${slice_dir}/constellation.db?mode=rwc" \
  --data-dir "${slice_dir}/data" \
  --ephemeral-identity \
  >"${slice_log}" 2>&1 &
slice_pid=$!

cleanup() {
  if test -n "${enrollment_pid}"; then
    kill "${enrollment_pid}" 2>/dev/null || true
    wait "${enrollment_pid}" 2>/dev/null || true
  fi
  if test -n "${worker_pid}"; then
    kill "${worker_pid}" 2>/dev/null || true
    wait "${worker_pid}" 2>/dev/null || true
  fi
  kill "${slice_pid}" 2>/dev/null || true
  wait "${slice_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

slice_deadline=$((SECONDS + slice_startup_timeout))
slice_ready=false
while (( SECONDS < slice_deadline )); do
  if curl --fail --silent "${slice_base}/ready" >/dev/null; then
    slice_ready=true
    break
  fi
  if ! kill -0 "${slice_pid}" 2>/dev/null; then
    echo 'Constellation daemon exited before the vertical slice became ready.' >&2
    sed -n '1,200p' "${slice_log}"
    exit 1
  fi
  sleep 0.25
done

if test "${slice_ready}" != true; then
  echo "Constellation daemon was not ready within ${slice_startup_timeout} seconds." >&2
  sed -n '1,200p' "${slice_log}"
  exit 1
fi

cargo run -p constellation-node-simulator -- \
  --controller "${slice_base}" \
  >"${slice_dir}/scenario.json"

grep -q '"failover_plan"' "${slice_dir}/scenario.json"
grep -q '"independent_routing"' "${slice_dir}/scenario.json"

curl --fail --silent --no-buffer \
  -H 'Content-Type: application/json' \
  -d '{"model":"constellation/mock","messages":[{"role":"user","content":"stream verification"}],"stream":true}' \
  "${slice_base}/v1/chat/completions" \
  >"${slice_dir}/stream.txt"

grep -q 'Constellation ' "${slice_dir}/stream.txt"
grep -q 'response:' "${slice_dir}/stream.txt"
grep -q '\[DONE\]' "${slice_dir}/stream.txt"

curl --fail --silent "${slice_base}/constellation/v1/cluster" \
  >"${slice_dir}/cluster.json"
grep -q '"ready_nodes":4' "${slice_dir}/cluster.json"

model_path="${slice_dir}/tiny.gguf"
printf 'GGUFsynthetic model cache fixture' >"${model_path}"
curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d "{\"path\":\"${model_path}\",\"alias\":\"fixture/tiny\",\"format\":\"gguf\",\"license_id\":\"Apache-2.0\",\"license_accepted\":true}" \
  "${slice_base}/constellation/v1/models/import" \
  >"${slice_dir}/model-import.json"
grep -q '"alias":"fixture/tiny"' "${slice_dir}/model-import.json"
curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d '{"alias":"fixture/tiny"}' \
  "${slice_base}/constellation/v1/models/verify" \
  >"${slice_dir}/model-verify.json"
grep -q '"chunk_size_bytes":4194304' "${slice_dir}/model-verify.json"
curl --fail --silent \
  -X PATCH \
  -H 'Content-Type: application/json' \
  -d '{"alias":"fixture/tiny","pinned":true}' \
  "${slice_base}/constellation/v1/models/pin" \
  >"${slice_dir}/model-pin.json"
grep -q '"pinned":true' "${slice_dir}/model-pin.json"

curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d '{"title":"Encrypted integration chat","temporary":false}' \
  "${slice_base}/constellation/v1/chat/conversations" \
  >"${slice_dir}/conversation.json"
conversation_id="$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "${slice_dir}/conversation.json")"
test -n "${conversation_id}"
private_message='private vertical slice content 7d22'
curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d "{\"role\":\"user\",\"content\":\"${private_message}\"}" \
  "${slice_base}/constellation/v1/chat/conversations/${conversation_id}/messages" \
  >"${slice_dir}/message.json"
curl --fail --silent \
  "${slice_base}/constellation/v1/chat/conversations/${conversation_id}/messages" \
  >"${slice_dir}/messages.json"
grep -q "${private_message}" "${slice_dir}/messages.json"
if grep -a -q "${private_message}" "${slice_dir}/constellation.db" "${slice_dir}/constellation.db-wal" 2>/dev/null; then
  echo 'Private chat content was found in SQLite plaintext' >&2
  exit 1
fi
curl --fail --silent -X DELETE \
  "${slice_base}/constellation/v1/chat/conversations/${conversation_id}"

cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" diagnostics \
  >"${slice_dir}/diagnostics.json"
grep -q '"content_included": false' "${slice_dir}/diagnostics.json"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" chat --model constellation/mock 'CLI verification' \
  >"${slice_dir}/cli-chat.txt"
grep -q 'Constellation mock response: CLI verification' "${slice_dir}/cli-chat.txt"

cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" invitation create \
  >"${slice_dir}/invitation.json"
invitation_id="$(sed -n 's/^[[:space:]]*"id": "\([^"]*\)",*$/\1/p' "${slice_dir}/invitation.json")"
short_code="$(sed -n 's/^[[:space:]]*"short_code": "\([^"]*\)",*$/\1/p' "${slice_dir}/invitation.json")"
test -n "${invitation_id}"
test -n "${short_code}"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" enroll "${invitation_id}" "${short_code}" \
  --name 'Enrolled integration node' --wait-seconds 30 --ephemeral-device-identity \
  >"${slice_dir}/enrollment.json" &
enrollment_pid=$!
for _attempt in $(seq 1 40); do
  if cargo run --quiet -p constellation-cli -- \
    --controller "${slice_base}" invitation list \
    >"${slice_dir}/invitation-status.json" && \
    grep -q '"consumed": true' "${slice_dir}/invitation-status.json"; then
    break
  fi
  sleep 0.25
done
grep -q '"consumed": true' "${slice_dir}/invitation-status.json"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" invitation approve "${invitation_id}" \
  >"${slice_dir}/approval.json"
wait "${enrollment_pid}"
grep -q '"status": "approved"' "${slice_dir}/enrollment.json"
grep -q 'Enrolled integration node' <(
  cargo run --quiet -p constellation-cli -- \
    --controller "${slice_base}" inventory
)
enrolled_node_id="$(sed -n 's/^[[:space:]]*"device_id": "\([^"]*\)",*$/\1/p' "${slice_dir}/approval.json")"
test -n "${enrolled_node_id}"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" heartbeat "${enrolled_node_id}" \
  --credential "${slice_dir}/approval.json" \
  >"${slice_dir}/heartbeat.json"
grep -q '"status": "ready"' "${slice_dir}/heartbeat.json"
cargo run --quiet -p constellationd -- \
  --role worker \
  --controller "${slice_base}" \
  --credential "${slice_dir}/approval.json" \
  --data-dir "${slice_dir}/worker-data" \
  >"${slice_dir}/worker.log" 2>&1 &
worker_pid=$!
for _attempt in $(seq 1 40); do
  if curl --fail --silent "${slice_base}/constellation/v1/benchmarks" \
    >"${slice_dir}/worker-benchmarks.json" && \
    grep -q "${enrolled_node_id}" "${slice_dir}/worker-benchmarks.json"; then
    sleep 1
    break
  fi
  sleep 0.25
done
grep -q "${enrolled_node_id}" "${slice_dir}/worker-benchmarks.json"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" report "${slice_dir}/benchmark-report.json"
grep -q '"content_included": false' "${slice_dir}/benchmark-report.json"
grep -q "${enrolled_node_id}" "${slice_dir}/benchmark-report.json"
remote_private_prompt='remote private lease content c814'
curl --fail --silent \
  -H 'Content-Type: application/json' \
  -d "{\"model\":\"constellation/mock\",\"messages\":[{\"role\":\"user\",\"content\":\"${remote_private_prompt}\"}],\"stream\":false}" \
  "${slice_base}/v1/chat/completions" \
  >"${slice_dir}/remote-chat.json"
grep -q 'Constellation mock response:' "${slice_dir}/remote-chat.json"
grep -q "${enrolled_node_id}" "${slice_dir}/remote-chat.json"
if grep -a -q "${remote_private_prompt}" "${slice_dir}/constellation.db" "${slice_dir}/constellation.db-wal" 2>/dev/null; then
  echo 'Remote lease input was found in SQLite plaintext' >&2
  exit 1
fi
kill "${worker_pid}" 2>/dev/null || true
wait "${worker_pid}" 2>/dev/null || true
worker_pid=""
chunk_sha256="$(grep -o '"sha256":"[a-f0-9]\{64\}"' "${slice_dir}/model-import.json" | sed -n '2s/.*:"\([a-f0-9]*\)"/\1/p')"
test -n "${chunk_sha256}"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" model transfer-chunk \
  --alias fixture/tiny --chunk-sha256 "${chunk_sha256}" \
  --destination-node "${enrolled_node_id}" \
  --credential "${slice_dir}/approval.json" \
  --output "${slice_dir}/transferred.chunk" \
  >"${slice_dir}/model-transfer.json"
cmp "${model_path}" "${slice_dir}/transferred.chunk"
grep -q '"status": "verified"' "${slice_dir}/model-transfer.json"
cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" revoke "${enrolled_node_id}" \
  >"${slice_dir}/revocation.json"
grep -q '"status": "revoked"' "${slice_dir}/revocation.json"
if cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" heartbeat "${enrolled_node_id}" \
  --credential "${slice_dir}/approval.json" \
  >"${slice_dir}/revoked-heartbeat.json" 2>&1; then
  echo 'Revoked membership unexpectedly sent a heartbeat' >&2
  exit 1
fi

cargo run --quiet -p constellation-cli -- \
  --controller "${slice_base}" backup "${slice_dir}/backup.db"
test "$(head -c 15 "${slice_dir}/backup.db")" = 'SQLite format 3'

printf 'Vertical slice passed. Artifacts: %s\n' "${slice_dir}"
