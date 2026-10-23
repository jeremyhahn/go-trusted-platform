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

package switchapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const requestTimeout = 30 * time.Second

// setVLANRequest is the JSON body for the SetPortVLAN endpoint.
type setVLANRequest struct {
	VLANID uint16 `json:"vlan_id"`
}

// Handlers provides REST handlers for physical switch management.
type Handlers struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	switchService  device.SwitchServiceProvider
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	logger *logging.Logger,
	rw response.HttpWriter,
	svc device.SwitchServiceProvider,
) *Handlers {
	return &Handlers{
		logger:         logger,
		responseWriter: rw,
		switchService:  svc,
	}
}

// ListPorts handles GET /api/v1/switches/{switch}/ports.
// It returns the status of all physical ports on the named switch.
func (h *Handlers) ListPorts(w http.ResponseWriter, r *http.Request) {
	switchName := decodeVar(mux.Vars(r)["switch"])
	if switchName == "" {
		h.responseWriter.Error400(w, r, ErrMissingSwitchName{})
		return
	}

	mgr, err := h.switchService.Manager(switchName)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrSwitchNotFound{Name: switchName})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		h.logger.Errorf("switchapi: list ports failed: switch=%s error=%v", switchName, err)
		h.responseWriter.Error500(w, r, ErrListPortsFailed{Switch: switchName, Cause: err})
		return
	}

	h.responseWriter.Success200(w, r, ports)
}

// GetPortStatus handles GET /api/v1/switches/{switch}/ports/{port}.
// It returns the full observable state of a single port.
func (h *Handlers) GetPortStatus(w http.ResponseWriter, r *http.Request) {
	switchName, portName, ok := h.extractSwitchAndPort(w, r)
	if !ok {
		return
	}

	mgr, err := h.switchService.Manager(switchName)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrSwitchNotFound{Name: switchName})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	status, err := mgr.GetPortStatus(ctx, portName)
	if err != nil {
		h.logger.Errorf("switchapi: get port status failed: switch=%s port=%s error=%v",
			switchName, portName, err)
		h.handlePortError(w, r, switchName, portName, "get port status", err)
		return
	}

	h.responseWriter.Success200(w, r, status)
}

// SetPortVLAN handles POST /api/v1/switches/{switch}/ports/{port}/vlan.
// It moves an access-mode port to the specified VLAN.
func (h *Handlers) SetPortVLAN(w http.ResponseWriter, r *http.Request) {
	switchName, portName, ok := h.extractSwitchAndPort(w, r)
	if !ok {
		return
	}

	var req setVLANRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.VLANID == 0 {
		h.responseWriter.Error400(w, r, ErrMissingVLANID{})
		return
	}

	if req.VLANID > 4094 {
		h.responseWriter.Error400(w, r, ErrInvalidVLANID{Value: req.VLANID})
		return
	}

	mgr, err := h.switchService.Manager(switchName)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrSwitchNotFound{Name: switchName})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	if err := mgr.SetPortVLAN(ctx, portName, req.VLANID); err != nil {
		h.logger.Errorf("switchapi: set port vlan failed: switch=%s port=%s vlan=%d error=%v",
			switchName, portName, req.VLANID, err)
		h.handlePortError(w, r, switchName, portName, "set vlan", err)
		return
	}

	h.responseWriter.Success200(w, r, map[string]interface{}{
		"switch":  switchName,
		"port":    portName,
		"vlan_id": req.VLANID,
		"status":  "ok",
	})
}

// EnablePort handles POST /api/v1/switches/{switch}/ports/{port}/enable.
// It administratively enables a port.
func (h *Handlers) EnablePort(w http.ResponseWriter, r *http.Request) {
	h.portAdminAction(w, r, "enable", func(mgr switchmgmt.Manager, ctx context.Context, port string) error {
		return mgr.EnablePort(ctx, port)
	})
}

// DisablePort handles POST /api/v1/switches/{switch}/ports/{port}/disable.
// It administratively shuts down a port.
func (h *Handlers) DisablePort(w http.ResponseWriter, r *http.Request) {
	h.portAdminAction(w, r, "disable", func(mgr switchmgmt.Manager, ctx context.Context, port string) error {
		return mgr.DisablePort(ctx, port)
	})
}

// portAdminAction is a helper that executes an administrative port action
// (enable or disable) with common request validation and error handling.
func (h *Handlers) portAdminAction(
	w http.ResponseWriter,
	r *http.Request,
	action string,
	fn func(switchmgmt.Manager, context.Context, string) error,
) {
	switchName, portName, ok := h.extractSwitchAndPort(w, r)
	if !ok {
		return
	}

	mgr, err := h.switchService.Manager(switchName)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrSwitchNotFound{Name: switchName})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	if err := fn(mgr, ctx, portName); err != nil {
		h.logger.Errorf("switchapi: %s port failed: switch=%s port=%s error=%v",
			action, switchName, portName, err)
		h.handlePortError(w, r, switchName, portName, action, err)
		return
	}

	h.responseWriter.Success200(w, r, map[string]interface{}{
		"switch": switchName,
		"port":   portName,
		"action": action,
		"status": "ok",
	})
}

// extractSwitchAndPort extracts and validates the switch and port path parameters.
// Path variables are URL-decoded because the router uses UseEncodedPath to handle
// port names containing slashes (e.g., "Eth1/3" encoded as "Eth1%2F3").
// Returns false if validation failed and an error response was already written.
func (h *Handlers) extractSwitchAndPort(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	vars := mux.Vars(r)
	switchName := decodeVar(vars["switch"])
	portName := decodeVar(vars["port"])

	if switchName == "" {
		h.responseWriter.Error400(w, r, ErrMissingSwitchName{})
		return "", "", false
	}
	if portName == "" {
		h.responseWriter.Error400(w, r, ErrMissingPortName{})
		return "", "", false
	}

	return switchName, portName, true
}

// decodeVar URL-decodes a path variable. When UseEncodedPath is active,
// mux.Vars returns percent-encoded values that must be decoded.
func decodeVar(raw string) string {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// handlePortError translates switchmgmt errors to appropriate HTTP responses:
// a port the switch does not have is 404 for every port operation, so the
// SDK sees NotFound whether it reads or changes the port (#452).
func (h *Handlers) handlePortError(w http.ResponseWriter, r *http.Request, switchName, portName, operation string, err error) {
	var notFound switchmgmt.ErrPortNotFound
	if errors.As(err, &notFound) {
		h.responseWriter.Error404(w, r, ErrPortOperationFailed{
			Operation: operation,
			Switch:    switchName,
			Port:      portName,
			Cause:     err,
		})
		return
	}
	h.responseWriter.Error500(w, r, ErrPortOperationFailed{
		Operation: operation,
		Switch:    switchName,
		Port:      portName,
		Cause:     err,
	})
}
