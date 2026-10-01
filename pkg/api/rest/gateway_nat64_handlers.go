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

package rest

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// ErrNAT64NotConfigured is returned when the translator section is not
// running: either it is absent from this gateway's configuration, or it was
// refused at start. Both mean the same thing to a caller — there is no
// translator to report on — and the reason is in the message.
type ErrNAT64NotConfigured struct{}

// Error implements the error interface.
func (e ErrNAT64NotConfigured) Error() string {
	return "nat64 translator service is not configured"
}

// ErrNAT64ModuleUnavailable reports a kernel that cannot carry the
// translator. It is a failed precondition on the host (412), not a daemon
// fault: no retry helps until someone loads the module, which is what
// gRPC's FailedPrecondition says on the other transports.
type ErrNAT64ModuleUnavailable struct {
	// Detail is the kernel's own reason, which the operator needs.
	Detail string
}

// Error implements the error interface.
func (e ErrNAT64ModuleUnavailable) Error() string {
	return "nat64 translator module unavailable: " + e.Detail
}

// NAT64StatusResponse is the NAT64 translator's health over REST. Every
// field except the identity pair is what the kernel reported, not what the
// configuration asked for: a started service whose instance has gone
// reports instance_present false.
type NAT64StatusResponse struct {
	Active          bool      `json:"active"`
	InstancePresent bool      `json:"instance_present"`
	Prefix          string    `json:"prefix"`
	Instance        string    `json:"instance"`
	Sessions        uint64    `json:"sessions"`
	Pool4Used       uint64    `json:"pool4_used"`
	ModuleVersion   string    `json:"module_version,omitempty"`
	FlowCount       int       `json:"flow_count"`
	LastReconcile   time.Time `json:"last_reconcile,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// =============================================================================
// NAT64 Handlers
// =============================================================================

// registerNAT64Routes registers the NAT64 routes on the router.
func (h *GatewayHandlers) registerNAT64Routes(router *mux.Router) {
	router.HandleFunc("/api/v1/sdn/gateway/nat64/status", h.handleGetNAT64Status).Methods(http.MethodGet)
}

// handleGetNAT64Status handles GET /api/v1/sdn/gateway/nat64/status
func (h *GatewayHandlers) handleGetNAT64Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.gatewayService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrGatewayServiceNotAvailable{})
		return
	}

	status, err := h.gatewayService.GetNAT64Status(ctx)
	if err != nil {
		h.logger.Error("Failed to get NAT64 status", "error", err)
		h.writeGatewayError(w, "get_nat64_status", err)
		return
	}

	status.Timestamp = time.Now().UTC()
	h.writeJSON(w, http.StatusOK, status)
}
