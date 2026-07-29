#!/usr/bin/env bash
set -euo pipefail

if test "$#" -ne 1; then
  echo "usage: $0 /absolute/path/to/constellationd" >&2
  exit 2
fi

source_binary="$1"
if test ! -x "${source_binary}"; then
  echo "constellationd executable not found: ${source_binary}" >&2
  exit 2
fi

install_root="${HOME}/.local/bin"
data_root="${HOME}/.local/share/constellation"
mkdir -p "${install_root}" "${data_root}"
install -m 0755 "${source_binary}" "${install_root}/constellationd"

case "$(uname -s)" in
  Linux)
    unit_root="${HOME}/.config/systemd/user"
    mkdir -p "${unit_root}"
    install -m 0644 "$(dirname "$0")/linux/constellationd.service" "${unit_root}/constellationd.service"
    systemctl --user daemon-reload
    systemctl --user enable --now constellationd.service
    ;;
  Darwin)
    agent_root="${HOME}/Library/LaunchAgents"
    agent_path="${agent_root}/com.constellation.daemon.plist"
    mkdir -p "${agent_root}"
    escaped_binary="${install_root}/constellationd"
    escaped_data="${data_root}"
    sed -e "s|@@BINARY@@|${escaped_binary}|g" -e "s|@@DATA@@|${escaped_data}|g" \
      "$(dirname "$0")/macos/com.constellation.daemon.plist" >"${agent_path}"
    chmod 0644 "${agent_path}"
    launchctl bootout "gui/$(id -u)/com.constellation.daemon" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "${agent_path}"
    ;;
  *)
    echo "unsupported platform; use the Windows installer scripts on Windows" >&2
    exit 2
    ;;
esac

echo "Constellation service installed. Private data: ${data_root}"
