#!/bin/sh

# Ensure routing inside the container always prefers the privnet interface
# to reach the core, while the macvlan interface only serves the Wi-Fi subnet.

set -e

PRIV_SUBNET_PREFIX="10.100.200."
WIFI_SUBNET_PREFIX="192.168.11."
CORE_SUBNET="192.168.17.0/24"
WIFI_SUBNET="192.168.11.0/24"
PRIV_GATEWAY="10.100.200.1"
WIFI_GATEWAY="192.168.11.1"

priv_if="$(ip -o -4 addr show | awk -v prefix="$PRIV_SUBNET_PREFIX" '$4 ~ "^"prefix {print $2; exit}')"
wifi_if="$(ip -o -4 addr show | awk -v prefix="$WIFI_SUBNET_PREFIX" '$4 ~ "^"prefix {print $2; exit}')"

if [ -n "$wifi_if" ]; then
    ip route replace "$WIFI_SUBNET" dev "$wifi_if"
    ip route del default via "$WIFI_GATEWAY" dev "$wifi_if" 2>/dev/null || true
fi

if [ -n "$priv_if" ]; then
    ip route replace default via "$PRIV_GATEWAY" dev "$priv_if"
    ip route replace "$CORE_SUBNET" via "$PRIV_GATEWAY" dev "$priv_if"
fi
