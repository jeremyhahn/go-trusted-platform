# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.
#
# go-trusted-platform is dual-licensed:
#
# 1. GNU Affero General Public License v3.0 (AGPL-3.0)
#    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
#
# 2. Commercial License
#    Contact licensing@automatethethings.com for commercial licensing options.

# Package container.builtin.privileged enforces privileged container restrictions.
package container.builtin.privileged

import rego.v1

# deny privileged containers without explicit approval
deny contains msg if {
    input.container.privileged == true
    not privileged_allowed
    msg := "privileged containers not allowed without explicit approval"
}

# deny privileged containers when device profile disallows them
deny contains msg if {
    input.container.privileged == true
    input.device_profile != null
    input.device_profile.allow_privileged == false
    msg := "privileged containers are disabled by device profile"
}

# warn about privileged containers even when allowed
warn contains msg if {
    input.container.privileged == true
    privileged_allowed
    msg := "container is running in privileged mode"
}

# deny dangerous capabilities without privileged mode
deny contains msg if {
    dangerous_capability_requested
    not input.container.privileged
    not input.container.allow_privileged
    msg := sprintf("dangerous capability %s requires explicit approval", [dangerous_cap])
}

# Helper rule to check if privileged mode is explicitly allowed
privileged_allowed if {
    input.container.allow_privileged == true
}

privileged_allowed if {
    input.device_profile != null
    input.device_profile.allow_privileged == true
}

# Dangerous capabilities that require explicit approval
dangerous_capabilities := {
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "SYS_MODULE",
    "NET_ADMIN",
    "NET_RAW",
    "DAC_OVERRIDE",
    "SETUID",
    "SETGID"
}

# Check if any dangerous capability is requested
dangerous_capability_requested if {
    some cap in input.container.capabilities.add
    dangerous_capabilities[cap]
}

# Get the first dangerous capability for error message
dangerous_cap := cap if {
    some cap in input.container.capabilities.add
    dangerous_capabilities[cap]
}
