# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.
#
# Remote-access VPN posture policy (docs/vpn/engineering.md §4). The input is
# the client's posture report beside its attestation verdict summary:
#
#   input.posture.secure_boot.{enabled,setup_mode,available}
#   input.posture.ima.{available,enabled,policy_loaded,log_digest}
#   input.posture.fde.root_encrypted
#   input.posture.{agent_version,os_release,kernel_release,collected_at}
#   input.verdict.{passed,cryptographic,profile_id}
#
# Every violation names its rule so the refusal can list rule names without
# the policy text. Tenants override this policy through the posture-policy
# API; a policy that cannot be loaded is a refusal, never an allow.

package vpn.posture

import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

violations contains {"rule": "verdict-required", "message": "attestation verdict missing"} if {
	not input.verdict
}

violations contains {"rule": "verdict-passed", "message": "attestation verdict did not pass"} if {
	input.verdict
	not input.verdict.passed
}

violations contains {"rule": "verdict-cryptographic", "message": "attestation verdict is not cryptographic"} if {
	input.verdict
	not input.verdict.cryptographic
}

violations contains {"rule": "posture-required", "message": "posture report missing"} if {
	not input.posture
}

violations contains {"rule": "secure-boot-enabled", "message": "Secure Boot is not enabled"} if {
	input.posture
	not input.posture.secure_boot.enabled
}

violations contains {"rule": "secure-boot-setup-mode", "message": "firmware is in Secure Boot setup mode"} if {
	input.posture
	input.posture.secure_boot.setup_mode
}

violations contains {"rule": "fde-root-encrypted", "message": "root volume is not encrypted"} if {
	input.posture
	not input.posture.fde.root_encrypted
}

violations contains {"rule": "ima-enabled", "message": "IMA is not enabled"} if {
	input.posture
	not input.posture.ima.enabled
}

violations contains {"rule": "ima-policy-loaded", "message": "IMA policy is not loaded"} if {
	input.posture
	not input.posture.ima.policy_loaded
}

violations contains {"rule": "agent-version", "message": "agent version missing"} if {
	input.posture
	not input.posture.agent_version
}
