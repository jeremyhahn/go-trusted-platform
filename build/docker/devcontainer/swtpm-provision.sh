# shellcheck shell=bash
#
# Provisions a swtpm state directory the way a TPM leaves its manufacturer:
# with an endorsement key (EK) and an EK certificate. swtpm_setup persists
# the RSA 2048 EK at 0x81010001 and writes its certificate to NV index
# 0x01C00002 (TCG EK Credential Profile). Real hardware never reaches the
# platform without an EK, so the integration harness must not either:
# platformd treats a TPM with no EK as uninitialized and goes down its
# recovery path (CA m390).
#
# The EK certificate is signed by a swtpm_localca CA that is created on
# first use in <state-dir>/localca, so the run needs no writable system
# directory and leaves nothing behind outside the TPM state.
#
# Sourced by entrypoint.sh and run-integration-tests.sh.

# provision_swtpm_state <state-dir>
#
# Creates a fresh TPM 2.0 state with a SHA-256 PCR bank, an EK and an EK
# certificate. Returns non-zero, with the reason on stderr, when swtpm_setup
# or swtpm_localca is missing or swtpm_setup fails.
provision_swtpm_state() {
    local state_dir="$1"
    local localca_dir="${state_dir}/localca"

    if ! command -v swtpm_setup > /dev/null 2>&1; then
        echo "swtpm_setup not found: install swtpm-tools to provision the harness TPM" >&2
        return 1
    fi

    local localca_tool
    if ! localca_tool="$(command -v swtpm_localca)"; then
        echo "swtpm_localca not found: install swtpm-tools to issue the EK certificate" >&2
        return 1
    fi

    rm -rf "$localca_dir"
    mkdir -p "$localca_dir" || return 1

    printf '%s\n' \
        "statedir = ${localca_dir}" \
        "signingkey = ${localca_dir}/signkey.pem" \
        "issuercert = ${localca_dir}/issuercert.pem" \
        "certserial = ${localca_dir}/certserial" \
        > "${localca_dir}/swtpm-localca.conf" || return 1

    printf '%s\n' \
        "create_certs_tool = ${localca_tool}" \
        "create_certs_tool_config = ${localca_dir}/swtpm-localca.conf" \
        > "${localca_dir}/swtpm_setup.conf" || return 1

    if ! swtpm_setup --tpm2 \
        --tpmstate "$state_dir" \
        --config "${localca_dir}/swtpm_setup.conf" \
        --overwrite \
        --pcr-banks sha256 \
        --createek \
        --create-ek-cert; then
        echo "swtpm_setup failed to create the EK and EK certificate in ${state_dir}" >&2
        return 1
    fi
}
