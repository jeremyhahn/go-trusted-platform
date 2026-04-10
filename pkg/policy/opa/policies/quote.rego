# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.

package attestation.quote

import rego.v1

# Default deny
default allow := false

# Allow if TPM quote verification requirements are met
allow if {
	valid_quote_structure
	valid_signature
	valid_nonce
	valid_pcr_selection
	not replay_attack
}

# Validate quote structure
valid_quote_structure if {
	input.quote
	input.quote.magic == 0xff544347  # TPM2_GENERATED_VALUE
	input.quote.type == 0x8018       # TPM2_ST_ATTEST_QUOTE
}

# Validate quote signature
valid_signature if {
	input.signature
	input.signature.verified == true
}

# Validate signature algorithm
valid_signature_algorithm if {
	not data.allowed_signature_algorithms
}

valid_signature_algorithm if {
	data.allowed_signature_algorithms
	input.signature.algorithm
	input.signature.algorithm in data.allowed_signature_algorithms
}

# Validate nonce to prevent replay attacks
valid_nonce if {
	input.nonce
	input.expected_nonce
	input.nonce == input.expected_nonce
}

valid_nonce if {
	not input.expected_nonce
	input.nonce
}

# Validate PCR selection
valid_pcr_selection if {
	input.pcr_selection
	count(input.pcr_selection) > 0
}

# Check required PCRs are included
required_pcrs_included if {
	not data.required_pcrs
}

required_pcrs_included if {
	data.required_pcrs
	every pcr in data.required_pcrs {
		pcr in input.pcr_selection
	}
}

# Check for replay attack (quote timestamp too old)
replay_attack if {
	data.max_quote_age_seconds
	input.quote.timestamp
	age := (time.now_ns() / 1000000000) - input.quote.timestamp
	age > data.max_quote_age_seconds
}

# Validate AK (Attestation Key) certificate
valid_ak_certificate if {
	not data.require_ak_certificate
}

valid_ak_certificate if {
	data.require_ak_certificate == true
	input.ak_certificate
	input.ak_certificate.valid == true
}

# Validate EK (Endorsement Key) certificate
valid_ek_certificate if {
	not data.require_ek_certificate
}

valid_ek_certificate if {
	data.require_ek_certificate == true
	input.ek_certificate
	input.ek_certificate.valid == true
	trusted_ek_issuer
}

# Check if EK issuer is trusted
trusted_ek_issuer if {
	not data.trusted_ek_issuers
}

trusted_ek_issuer if {
	data.trusted_ek_issuers
	input.ek_certificate.issuer
	input.ek_certificate.issuer in data.trusted_ek_issuers
}

# Collect violations
violations contains msg if {
	not input.quote
	msg := "TPM quote not provided"
}

violations contains msg if {
	input.quote
	input.quote.magic != 0xff544347
	msg := "Invalid TPM quote magic value"
}

violations contains msg if {
	input.quote
	input.quote.type != 0x8018
	msg := "Invalid TPM quote type (expected TPM2_ST_ATTEST_QUOTE)"
}

violations contains msg if {
	not input.signature
	msg := "Quote signature not provided"
}

violations contains msg if {
	input.signature
	input.signature.verified != true
	msg := "Quote signature verification failed"
}

violations contains msg if {
	data.allowed_signature_algorithms
	input.signature.algorithm
	not input.signature.algorithm in data.allowed_signature_algorithms
	msg := sprintf("Signature algorithm %v is not allowed", [input.signature.algorithm])
}

violations contains msg if {
	input.expected_nonce
	input.nonce != input.expected_nonce
	msg := "Nonce mismatch - possible replay attack"
}

violations contains msg if {
	not input.nonce
	msg := "Nonce not provided"
}

violations contains msg if {
	not input.pcr_selection
	msg := "PCR selection not provided"
}

violations contains msg if {
	input.pcr_selection
	count(input.pcr_selection) == 0
	msg := "PCR selection is empty"
}

violations contains msg if {
	data.required_pcrs
	some pcr in data.required_pcrs
	not pcr in input.pcr_selection
	msg := sprintf("Required PCR %v is not included in selection", [pcr])
}

violations contains msg if {
	replay_attack
	msg := sprintf("Quote is older than %v seconds - possible replay attack", [data.max_quote_age_seconds])
}

violations contains msg if {
	data.require_ak_certificate == true
	not input.ak_certificate
	msg := "AK certificate not provided"
}

violations contains msg if {
	data.require_ak_certificate == true
	input.ak_certificate
	input.ak_certificate.valid != true
	msg := "AK certificate is not valid"
}

violations contains msg if {
	data.require_ek_certificate == true
	not input.ek_certificate
	msg := "EK certificate not provided"
}

violations contains msg if {
	data.require_ek_certificate == true
	input.ek_certificate
	input.ek_certificate.valid != true
	msg := "EK certificate is not valid"
}

violations contains msg if {
	data.trusted_ek_issuers
	input.ek_certificate.issuer
	not input.ek_certificate.issuer in data.trusted_ek_issuers
	msg := sprintf("EK certificate issuer %v is not trusted", [input.ek_certificate.issuer])
}
