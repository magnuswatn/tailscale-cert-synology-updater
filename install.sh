#!/bin/bash
set -Eeuo pipefail

main() {
  if ! command -v python3 &> /dev/null; then
    echo "python3 not found. Please install via Synology Package Center"
    exit 1
  fi

  python3 -m venv "/volume1/@tailscale-cert-synology-updater/venv"
  curl "https://raw.githubusercontent.com/magnuswatn/tailscale-cert-synology-updater/main/requirements.txt" \
    -o "/volume1/@tailscale-cert-synology-updater/requirements.txt"

  "/volume1/@tailscale-cert-synology-updater/venv/bin/pip" install pip --upgrade
  "/volume1/@tailscale-cert-synology-updater/venv/bin/pip" install -r "/volume1/@tailscale-cert-synology-updater/requirements.txt"

  curl "https://raw.githubusercontent.com/magnuswatn/tailscale-cert-synology-updater/main/tailscale_cert_synology_updater.py" \
    -o "/volume1/@tailscale-cert-synology-updater/tailscale_cert_synology_updater.py"
}

main "$@"
