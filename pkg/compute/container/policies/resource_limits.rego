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

# Package container.builtin.resource_limits enforces resource limit requirements.
package container.builtin.resource_limits

import rego.v1

# Default resource limits (in bytes for memory, cores for CPU)
default_max_memory_bytes := 8589934592  # 8GB
default_max_cpu_cores := 4.0

# deny if no memory limit is set
deny contains msg if {
    not input.container.resources.has_memory_limit
    msg := "container must have a memory limit configured"
}

# deny if no CPU limit is set
deny contains msg if {
    not input.container.resources.has_cpu_limit
    msg := "container must have a CPU limit configured"
}

# deny if memory limit exceeds device profile maximum
deny contains msg if {
    input.container.resources.has_memory_limit
    input.device_profile != null
    input.device_profile.max_memory_limit > 0
    input.container.resources.memory_limit > input.device_profile.max_memory_limit
    msg := sprintf("memory limit %d bytes exceeds maximum %d bytes", [
        input.container.resources.memory_limit,
        input.device_profile.max_memory_limit
    ])
}

# deny if CPU limit exceeds device profile maximum
deny contains msg if {
    input.container.resources.has_cpu_limit
    input.device_profile != null
    input.device_profile.max_cpu_limit > 0
    input.container.resources.cpu_limit > input.device_profile.max_cpu_limit
    msg := sprintf("CPU limit %.2f cores exceeds maximum %.2f cores", [
        input.container.resources.cpu_limit,
        input.device_profile.max_cpu_limit
    ])
}

# deny if memory limit exceeds default maximum (when no device profile)
deny contains msg if {
    input.container.resources.has_memory_limit
    input.device_profile == null
    input.container.resources.memory_limit > default_max_memory_bytes
    msg := sprintf("memory limit %d bytes exceeds default maximum %d bytes", [
        input.container.resources.memory_limit,
        default_max_memory_bytes
    ])
}

# deny if CPU limit exceeds default maximum (when no device profile)
deny contains msg if {
    input.container.resources.has_cpu_limit
    input.device_profile == null
    input.container.resources.cpu_limit > default_max_cpu_cores
    msg := sprintf("CPU limit %.2f cores exceeds default maximum %.2f cores", [
        input.container.resources.cpu_limit,
        default_max_cpu_cores
    ])
}

# warn if pids limit is very high
warn contains msg if {
    input.container.resources.pids_limit > 10000
    msg := sprintf("pids limit %d is unusually high", [input.container.resources.pids_limit])
}

# warn if memory limit is very low (potential OOM issues)
warn contains msg if {
    input.container.resources.has_memory_limit
    input.container.resources.memory_limit < 67108864  # 64MB
    msg := "memory limit is below 64MB which may cause out-of-memory issues"
}
