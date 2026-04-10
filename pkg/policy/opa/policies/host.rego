# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.

package attestation.host

import rego.v1

# Default deny
default allow := false

# Allow if all PCR values match expected golden measurements
allow if {
	input.pcr_values
	valid_pcrs
	valid_firmware
}

# Validate PCR values against golden measurements
valid_pcrs if {
	golden := data.golden_pcrs
	every pcr, value in input.pcr_values {
		golden[pcr] == value
	}
}

# Validate PCR values when no golden measurements are provided
valid_pcrs if {
	not data.golden_pcrs
	input.pcr_values
}

# Validate firmware measurements
valid_firmware if {
	not data.firmware_requirements
}

valid_firmware if {
	data.firmware_requirements
	input.firmware_version
	semver.compare(input.firmware_version, data.firmware_requirements.min_version) >= 0
}

# Collect violations
violations contains msg if {
	not valid_pcrs
	msg := "PCR values do not match expected golden measurements"
}

violations contains msg if {
	data.golden_pcrs
	some pcr, value in input.pcr_values
	expected := data.golden_pcrs[pcr]
	expected != value
	msg := sprintf("PCR %v mismatch: expected %v, got %v", [pcr, expected, value])
}

violations contains msg if {
	not input.pcr_values
	msg := "No PCR values provided in attestation"
}

violations contains msg if {
	data.firmware_requirements
	not input.firmware_version
	msg := "Firmware version not provided"
}

violations contains msg if {
	data.firmware_requirements
	input.firmware_version
	semver.compare(input.firmware_version, data.firmware_requirements.min_version) < 0
	msg := sprintf("Firmware version %v is below minimum required %v", [input.firmware_version, data.firmware_requirements.min_version])
}
