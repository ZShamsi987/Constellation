#!/usr/bin/env bash
set -euo pipefail

remove_data=false
if test "${1:-}" = "--remove-data"; then
  remove_data=true
elif test "$#" -ne 0; then
  echo "usage: $0 [--remove-data]" >&2
  exit 2
fi

case "$(uname -s)" in
  Linux)
    systemctl --user disable --now constellationd.service 2>/dev/null || true
    rm -f "${HOME}/.config/systemd/user/constellationd.service"
    systemctl --user daemon-reload
    ;;
  Darwin)
    launchctl bootout "gui/$(id -u)/com.constellation.daemon" 2>/dev/null || true
    rm -f "${HOME}/Library/LaunchAgents/com.constellation.daemon.plist"
    ;;
  *)
    echo "unsupported platform; use the Windows uninstaller on Windows" >&2
    exit 2
    ;;
esac

rm -f "${HOME}/.local/bin/constellationd"
if ${remove_data}; then
  data_root="${HOME}/.local/share/constellation"
  if test "${data_root}" != "${HOME}/.local/share/constellation"; then
    echo "refusing unexpected data path" >&2
    exit 1
  fi
  rm -rf -- "${data_root}"
  echo "Constellation service and private data removed. OS credential entries may require manual removal."
else
  echo "Constellation service removed; private data was preserved."
fi
