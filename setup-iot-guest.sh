#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: setup-iot-guest

Interactively configure the existing Home Guest IoT WLAN with zyxelctl.
The default network name is the configured IoT network name; zyxelctl securely prompts twice
for the Wi-Fi password and confirms the backed-up change before writing.
EOF
}

if (($# > 0)); then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${ZYXELCTL_BIN:-}" ]]; then
  zyxelctl_bin="$ZYXELCTL_BIN"
elif command -v zyxelctl >/dev/null 2>&1; then
  zyxelctl_bin="$(command -v zyxelctl)"
elif [[ -x "$script_dir/zyxelctl" ]]; then
  zyxelctl_bin="$script_dir/zyxelctl"
elif [[ -x "$script_dir/build/zyxelctl" ]]; then
  zyxelctl_bin="$script_dir/build/zyxelctl"
else
  echo "setup-iot-guest: zyxelctl was not found; run 'make build' or 'make install' first" >&2
  exit 1
fi

exec "$zyxelctl_bin" iot configure
