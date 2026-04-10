# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.

package attestation.vm

import rego.v1

# Default deny
default allow := false

# Allow if VM attestation requirements are met
allow if {
	valid_vm_identity
	valid_launch_measurement
	valid_runtime_measurement
}

# Validate VM identity
valid_vm_identity if {
	input.vm_id
	input.vm_name
}

# Validate launch measurement
valid_launch_measurement if {
	not data.expected_launch_measurement
}

valid_launch_measurement if {
	input.launch_measurement
	data.expected_launch_measurement
	input.launch_measurement == data.expected_launch_measurement
}

# Validate runtime measurement
valid_runtime_measurement if {
	not data.expected_runtime_measurement
}

valid_runtime_measurement if {
	input.runtime_measurement
	data.expected_runtime_measurement
	input.runtime_measurement == data.expected_runtime_measurement
}

# Check confidential computing features
confidential_vm if {
	input.sev_enabled == true
}

confidential_vm if {
	input.tdx_enabled == true
}

# Validate memory encryption
memory_encrypted if {
	input.memory_encryption == true
}

# Collect violations
violations contains msg if {
	not input.vm_id
	msg := "VM ID not provided"
}

violations contains msg if {
	not input.vm_name
	msg := "VM name not provided"
}

violations contains msg if {
	data.expected_launch_measurement
	not input.launch_measurement
	msg := "Launch measurement not provided"
}

violations contains msg if {
	data.expected_launch_measurement
	input.launch_measurement
	input.launch_measurement != data.expected_launch_measurement
	msg := sprintf("Launch measurement mismatch: expected %v, got %v", [data.expected_launch_measurement, input.launch_measurement])
}

violations contains msg if {
	data.expected_runtime_measurement
	not input.runtime_measurement
	msg := "Runtime measurement not provided"
}

violations contains msg if {
	data.expected_runtime_measurement
	input.runtime_measurement
	input.runtime_measurement != data.expected_runtime_measurement
	msg := sprintf("Runtime measurement mismatch: expected %v, got %v", [data.expected_runtime_measurement, input.runtime_measurement])
}

violations contains msg if {
	data.require_confidential_vm == true
	not confidential_vm
	msg := "Confidential VM (SEV/TDX) is required but not enabled"
}

violations contains msg if {
	data.require_memory_encryption == true
	not memory_encrypted
	msg := "Memory encryption is required but not enabled"
}
