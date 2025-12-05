#!/bin/sh

set -e

if [ -x ./n3iwf-ipsec.sh ]; then
    ./n3iwf-ipsec.sh
fi

if [ -x ./n3iwf-route.sh ]; then
    ./n3iwf-route.sh
fi

exec ./n3iwf -c ./config/n3iwfcfg.yaml
