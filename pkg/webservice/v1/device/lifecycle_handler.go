// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package device

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// LifecycleHandler serves the operator Enable/Disable Device flow:
// POST /api/v1/devices/{id}/disable and POST /api/v1/devices/{id}/enable.
type LifecycleHandler interface {
	HandleDisable(w http.ResponseWriter, r *http.Request)
	HandleEnable(w http.ResponseWriter, r *http.Request)
}

// maxLifecycleBodyBytes bounds the optional disable body, which carries a
// reason of at most 256 bytes.
const maxLifecycleBodyBytes = 4096

// DisableDeviceRequest is the optional disable body. An empty body or
// reason is recorded as "disabled".
type DisableDeviceRequest struct {
	Reason string `json:"reason"`
}

// DeviceLifecycleResponse mirrors platform.v1 DeviceLifecycleResponse field
// for field, with proto JSON names, so the SDK's REST transport decodes it
// into the pb reply.
type DeviceLifecycleResponse struct {
	DeviceID      uint64 `json:"device_id,string"`
	State         string `json:"state"`
	PreviousState string `json:"previous_state"`
	StateReason   string `json:"state_reason,omitempty"`
	// ReattestationRequested is true when an enable queued an immediate
	// re-attestation.
	ReattestationRequested bool `json:"reattestation_requested"`
}

type lifecycleHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	deviceService  platformv1.DeviceServiceServer
}

// NewLifecycleHandler creates the REST handler. It delegates to the
// in-process DeviceService gRPC implementation so REST enforces exactly what
// gRPC, Unix, QUIC and MCP enforce. A nil service yields a nil handler and
// the routes are not registered.
func NewLifecycleHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	deviceService platformv1.DeviceServiceServer,
) LifecycleHandler {
	if deviceService == nil {
		return nil
	}
	return &lifecycleHandler{
		logger:         logger,
		responseWriter: responseWriter,
		deviceService:  deviceService,
	}
}

// HandleDisable handles POST /api/v1/devices/{id}/disable.
func (h *lifecycleHandler) HandleDisable(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["id"]
	if deviceID == "" {
		h.responseWriter.Error400(w, r, ErrDeviceIDRequired{})
		return
	}
	var req DisableDeviceRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLifecycleBodyBytes))
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	resp, err := h.deviceService.DisableDevice(r.Context(), &platformv1.DisableDeviceRequest{
		DeviceId: deviceID,
		Reason:   req.Reason,
	})
	if err != nil {
		h.logger.Errorf("device: disable refused: device_id=%s error=%v", deviceID, err)
		writeGRPCStatusError(h.responseWriter, w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, lifecycleResponseBody(resp))
}

// HandleEnable handles POST /api/v1/devices/{id}/enable.
func (h *lifecycleHandler) HandleEnable(w http.ResponseWriter, r *http.Request) {
	deviceID := mux.Vars(r)["id"]
	if deviceID == "" {
		h.responseWriter.Error400(w, r, ErrDeviceIDRequired{})
		return
	}
	resp, err := h.deviceService.EnableDevice(r.Context(), &platformv1.EnableDeviceRequest{DeviceId: deviceID})
	if err != nil {
		h.logger.Errorf("device: enable refused: device_id=%s error=%v", deviceID, err)
		writeGRPCStatusError(h.responseWriter, w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, lifecycleResponseBody(resp))
}

func lifecycleResponseBody(resp *platformv1.DeviceLifecycleResponse) *DeviceLifecycleResponse {
	return &DeviceLifecycleResponse{
		DeviceID:               resp.GetDeviceId(),
		State:                  resp.GetState(),
		PreviousState:          resp.GetPreviousState(),
		StateReason:            resp.GetStateReason(),
		ReattestationRequested: resp.GetReattestationRequested(),
	}
}
