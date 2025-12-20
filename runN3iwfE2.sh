#!/bin/bash

# Default values
DO_BUILD=false
PARAM_AVVIO=""

# Parsing input
for arg in "$@"; do
    case "$arg" in
        -build)
            DO_BUILD=true
            ;;
        -e)
            echo "Voglio solo E2 Node"
            PARAM_AVVIO="free5gc-e2node"
            ;;
        -n)
            echo "Voglio solo N3IWF"
            PARAM_AVVIO="free5gc-n3iwf"
            ;;
        -ne)
            echo "Voglio N3IWF e E2 Node"
            PARAM_AVVIO="free5gc-e2node free5gc-n3iwf"
            ;;
        *)
            echo "Argomento sconosciuto: $arg"
            ;;
    esac
done

sudo ./setup-gtp5g.sh
#sudo git reset --hard origin/main 
git pull

# Se build richiesto
if [ "$DO_BUILD" = true ]; then
    sudo ./buildN3iwf_E2.sh
fi

# Se nessun parametro passato per l'avvio -> default
if [ -z "$PARAM_AVVIO" ]; then
    echo "Nessun argomento passato: uso default (tutti i servizi)"
    PARAM_AVVIO=""
fi

#pullo tutte le immagini
docker pull zhria/e2node:latest
docker pull zhria/n3iwfcustom:latest
# Run con docker compose
sudo docker compose -f dcb.yaml up $PARAM_AVVIO

