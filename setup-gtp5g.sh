#!/usr/bin/env bash
set -euo pipefail

# Uso: ./setup-gtp5g.sh [/percorso/al/repo/gtp5g]
GTP5G_DIR="${1:-../gtp5g}"

is_loaded() {
  lsmod | awk '{print $1}' | grep -qx gtp5g || [[ -d /sys/module/gtp5g ]]
}

try_modprobe() {
  sudo modprobe gtp5g 2>/dev/null || return 1
}

if is_loaded; then
  echo "[OK] gtp5g è già attivo."
  exit 0
fi

echo "[..] gtp5g non è attivo: provo a caricarlo..."
if try_modprobe; then
  echo "[OK] gtp5g caricato via modprobe."
  exit 0
fi

echo "[..] Compilo e installo gtp5g (richiede directory: $GTP5G_DIR)"
export DEBIAN_FRONTEND=noninteractive
sudo apt -y update
sudo apt -y install gcc g++ cmake autoconf libtool pkg-config libmnl-dev libyaml-dev

if [[ ! -d "$GTP5G_DIR" ]]; then
  echo "[ERR] La cartella '$GTP5G_DIR' non esiste. Clona il repo gtp5g o passa il percorso corretto come argomento."
  exit 1
fi

cd "$GTP5G_DIR"
make clean || true
make 
sudo make install

echo "[..] Carico il modulo gtp5g appena installato..."
if try_modprobe; then
  echo "[OK] gtp5g caricato con successo."
  modinfo gtp5g | grep -E 'filename|version' || true
  exit 0
else
  echo "[ERR] Impossibile caricare il modulo gtp5g dopo l'installazione."
  dmesg | tail -n 50 || true
  exit 2
fi
