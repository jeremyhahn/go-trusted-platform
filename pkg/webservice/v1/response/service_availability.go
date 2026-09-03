// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package response

import "net/http"

// ReasonServiceNotConfigured is the stable, machine-readable
// discriminator carried by the `reason` field of every 503 answered
// because a surface is dark on this node. Clients decide "this node
// deliberately does not host the service" from THIS value and the 503
// status — never from the human-readable `error` text, which is
// operator-facing prose and is explicitly not part of the contract.
//
// A live service answering 503 for a transient outage (or because it is
// configured but stopped) does not carry this reason, so callers can
// tell an absent surface apart from a broken or idle one.
//
// It lives here, beside the response writer, because two independent
// producers emit it: the REST service registry's catch-all stub in
// pkg/webservice/v1, and the per-service handlers that reach a
// configured router with an unconfigured backend
// (pkg/webservice/v1/rest/internal/protorest). The daemon's gRPC
// services carry the same value in an ErrorInfo detail so the
// discriminator survives every transport, not just REST.
const ReasonServiceNotConfigured = "SERVICE_NOT_CONFIGURED"

// ErrorInfoDomain is the domain reported on the google.rpc.ErrorInfo
// detail the daemon attaches to not-configured statuses. It scopes
// ReasonServiceNotConfigured to this platform so a client never
// confuses it with an identically named reason from another API.
const ErrorInfoDomain = "go-trusted-platform"

// ServiceUnavailableResponse is the body written for a request that
// lands on a dark surface. It mirrors the platform error envelope's
// leading fields (code/error/success) and adds the two machine-readable
// fields a client needs: which service is absent, and why.
type ServiceUnavailableResponse struct {
	Code    int    `yaml:"code" json:"code"`
	Error   string `yaml:"error" json:"error"`
	Success bool   `yaml:"success" json:"success"`
	Service string `yaml:"service" json:"service"`
	Reason  string `yaml:"reason" json:"reason"`
}

// NewServiceUnavailableResponse builds the canonical 503 body for a
// service that is not configured on this node.
func NewServiceUnavailableResponse(service, message string) ServiceUnavailableResponse {
	return ServiceUnavailableResponse{
		Code:    http.StatusServiceUnavailable,
		Error:   message,
		Success: false,
		Service: service,
		Reason:  ReasonServiceNotConfigured,
	}
}
