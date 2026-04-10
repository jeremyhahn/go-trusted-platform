# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.

package attestation.container

import rego.v1

# Default deny
default allow := false

# Allow if container attestation requirements are met
allow if {
	valid_container_identity
	valid_image
	valid_runtime
	not privileged_violation
}

# Validate container identity
valid_container_identity if {
	input.container_id
}

# Validate image
valid_image if {
	input.image_digest
	trusted_image
}

# Check if image is from a trusted registry
trusted_image if {
	not data.trusted_registries
}

trusted_image if {
	data.trusted_registries
	some registry in data.trusted_registries
	startswith(input.image_ref, registry)
}

# Validate runtime configuration
valid_runtime if {
	not data.allowed_runtimes
}

valid_runtime if {
	data.allowed_runtimes
	input.runtime
	input.runtime in data.allowed_runtimes
}

# Check for privileged mode violation
privileged_violation if {
	data.deny_privileged == true
	input.privileged == true
}

# Check for root user violation
root_violation if {
	data.deny_root == true
	input.user == "root"
}

root_violation if {
	data.deny_root == true
	input.uid == 0
}

# Validate namespace isolation
namespace_isolated if {
	input.pid_namespace != "host"
	input.network_namespace != "host"
	input.ipc_namespace != "host"
}

# Collect violations
violations contains msg if {
	not input.container_id
	msg := "Container ID not provided"
}

violations contains msg if {
	not input.image_digest
	msg := "Image digest not provided"
}

violations contains msg if {
	data.trusted_registries
	not trusted_image
	msg := sprintf("Image %v is not from a trusted registry", [input.image_ref])
}

violations contains msg if {
	data.allowed_runtimes
	input.runtime
	not input.runtime in data.allowed_runtimes
	msg := sprintf("Container runtime %v is not allowed, permitted: %v", [input.runtime, data.allowed_runtimes])
}

violations contains msg if {
	privileged_violation
	msg := "Privileged containers are not allowed"
}

violations contains msg if {
	root_violation
	msg := "Running as root is not allowed"
}

violations contains msg if {
	data.require_namespace_isolation == true
	not namespace_isolated
	msg := "Container must use isolated namespaces (not host)"
}

violations contains msg if {
	data.allowed_capabilities
	some cap in input.capabilities
	not cap in data.allowed_capabilities
	msg := sprintf("Capability %v is not allowed", [cap])
}

violations contains msg if {
	data.denied_capabilities
	some cap in input.capabilities
	cap in data.denied_capabilities
	msg := sprintf("Capability %v is explicitly denied", [cap])
}
