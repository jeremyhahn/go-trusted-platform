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

# Package container.builtin.image_signature enforces image signature requirements.
package container.builtin.image_signature

import rego.v1

# deny if image signature is required by device profile but not verified
deny contains msg if {
    input.device_profile.require_signed_images == true
    not image_signature_verified
    msg := "container image must be signed and verified"
}

# deny if signature is present but not verified
deny contains msg if {
    input.image.signature != null
    input.image.signature.verified == false
    msg := "container image signature verification failed"
}

# warn if no signature is present (when not strictly required)
warn contains msg if {
    not input.device_profile.require_signed_images
    input.image.signature == null
    msg := "container image is not signed"
}

# Helper rule to check if image signature is verified
image_signature_verified if {
    input.image.signature != null
    input.image.signature.verified == true
}
