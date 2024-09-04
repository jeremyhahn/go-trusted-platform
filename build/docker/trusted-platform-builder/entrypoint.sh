#!/bin/bash

set -e
set -o pipefail

export TPM2TOOLS_TCTI=mssim:host=localhost,port=2321

echo "Starting TPM 2.0 Simulator"
tpm_server > tpm.log &
tpm2_startup -c

echo "starting pcscd in backgroud"
## Debug: pcscd -dfa
pcscd --debug --apdu
pcscd --hotplug

"$@"