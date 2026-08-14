# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-trusted-platform.
#
# Proxy authorization policy evaluated by the trusted authenticating proxy
# for routes that set Auth.OPAPolicy. Input document:
#
#   {
#     "client":  {"id": "...", "zone": "...", "roles": [...], "attested": bool},
#     "route":   {"id": "...", "allowed_methods": [...]},
#     "request": {"method": "...", "path": "..."}
#   }

package proxy.authz

import rego.v1

# Default deny: a request is allowed only when it carries an authenticated
# client zone, targets a known route, and violates no rule.
default allow := false

allow if {
	input.client.zone != ""
	input.route.id != ""
	count(violations) == 0
}

# Quarantined clients are always denied.
violations contains msg if {
	input.client.zone == "quarantine"
	msg := "client zone is quarantined"
}

# When the route declares an allowed-method list, the request method must be
# in it.
violations contains msg if {
	count(input.route.allowed_methods) > 0
	not input.request.method in input.route.allowed_methods
	msg := sprintf("method %s not allowed for route %s", [input.request.method, input.route.id])
}
