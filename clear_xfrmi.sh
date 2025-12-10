#!/usr/bin/env bash
set -euo pipefail

# Removes the specified XFRM interface (defaults to xfrmi-default) if it exists.

IFACE_NAME="${1:-xfrmi-default}"

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "The 'ip' command is required but not found." >&2
  exit 1
fi

if ip link show "$IFACE_NAME" >/dev/null 2>&1; then
  echo "Found XFRM interface '$IFACE_NAME'. Deleting..."
  ip link del "$IFACE_NAME"
  echo "Interface '$IFACE_NAME' removed."
else
  echo "XFRM interface '$IFACE_NAME' not present. Nothing to do."
fi
