#!/bin/bash

set -e
set -o pipefail

SWTPM_STATE_DIR=/trusted-platform/volume/swtpm

mkdir -p $SWTPM_STATE_DIR
chmod 777 $SWTPM_STATE_DIR

swtpm socket \
  --tpmstate dir=$SWTPM_STATE_DIR \
  --tpm2 \
  --server type=unixio,path=$SWTPM_STATE_DIR/swtpm.sock \
  --ctrl type=unixio,path=$SWTPM_STATE_DIR/swtpm.sock.ctrl \
  --flags not-need-init,startup-clear \
  --log file=$SWTPM_STATE_DIR/swtpm.log,level=20 \
  --daemon

exec "$@"
