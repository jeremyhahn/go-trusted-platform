# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.

package attestation.image

import rego.v1

# Default deny
default allow := false

# Allow if image attestation requirements are met
allow if {
	valid_image_identity
	valid_signature
	valid_sbom
	not vulnerability_violation
}

# Validate image identity
valid_image_identity if {
	input.digest
	input.repository
}

# Validate image signature
valid_signature if {
	not data.require_signature
}

valid_signature if {
	data.require_signature == true
	input.signature
	input.signature.verified == true
	trusted_signer
}

# Check if signer is trusted
trusted_signer if {
	not data.trusted_signers
}

trusted_signer if {
	data.trusted_signers
	input.signature.signer
	input.signature.signer in data.trusted_signers
}

# Validate SBOM (Software Bill of Materials)
valid_sbom if {
	not data.require_sbom
}

valid_sbom if {
	data.require_sbom == true
	input.sbom
	input.sbom.present == true
}

# Check for vulnerability violations
vulnerability_violation if {
	data.max_critical_vulnerabilities
	input.vulnerabilities.critical > data.max_critical_vulnerabilities
}

vulnerability_violation if {
	data.max_high_vulnerabilities
	input.vulnerabilities.high > data.max_high_vulnerabilities
}

vulnerability_violation if {
	data.deny_fixable_vulnerabilities == true
	input.vulnerabilities.fixable > 0
}

# Check image age
image_too_old if {
	data.max_image_age_days
	input.created_at
	age_days := (time.now_ns() - time.parse_rfc3339_ns(input.created_at)) / (24 * 60 * 60 * 1000000000)
	age_days > data.max_image_age_days
}

# Check base image
valid_base_image if {
	not data.allowed_base_images
}

valid_base_image if {
	data.allowed_base_images
	input.base_image
	some allowed in data.allowed_base_images
	startswith(input.base_image, allowed)
}

# Collect violations
violations contains msg if {
	not input.digest
	msg := "Image digest not provided"
}

violations contains msg if {
	not input.repository
	msg := "Image repository not provided"
}

violations contains msg if {
	data.require_signature == true
	not input.signature
	msg := "Image signature not provided"
}

violations contains msg if {
	data.require_signature == true
	input.signature
	input.signature.verified != true
	msg := "Image signature verification failed"
}

violations contains msg if {
	data.trusted_signers
	input.signature.signer
	not input.signature.signer in data.trusted_signers
	msg := sprintf("Image signer %v is not trusted", [input.signature.signer])
}

violations contains msg if {
	data.require_sbom == true
	not input.sbom
	msg := "Software Bill of Materials (SBOM) not provided"
}

violations contains msg if {
	data.require_sbom == true
	input.sbom
	input.sbom.present != true
	msg := "Software Bill of Materials (SBOM) is not present"
}

violations contains msg if {
	data.max_critical_vulnerabilities
	input.vulnerabilities.critical > data.max_critical_vulnerabilities
	msg := sprintf("Image has %v critical vulnerabilities, maximum allowed is %v", [input.vulnerabilities.critical, data.max_critical_vulnerabilities])
}

violations contains msg if {
	data.max_high_vulnerabilities
	input.vulnerabilities.high > data.max_high_vulnerabilities
	msg := sprintf("Image has %v high vulnerabilities, maximum allowed is %v", [input.vulnerabilities.high, data.max_high_vulnerabilities])
}

violations contains msg if {
	data.deny_fixable_vulnerabilities == true
	input.vulnerabilities.fixable > 0
	msg := sprintf("Image has %v fixable vulnerabilities that must be addressed", [input.vulnerabilities.fixable])
}

violations contains msg if {
	image_too_old
	msg := sprintf("Image is older than %v days", [data.max_image_age_days])
}

violations contains msg if {
	data.allowed_base_images
	not valid_base_image
	msg := sprintf("Base image %v is not in allowed list", [input.base_image])
}
