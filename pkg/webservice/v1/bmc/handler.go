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

package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// powerActionHandler is the function signature for power action dispatch.
type powerActionHandler func(ctx context.Context, profileID uint64) error

// privilegeByName maps the canonical lowercase string form of a BMC
// privilege (matching bmcpkg.Privilege.String()) to its enum value.
// Used for O(1) parsing of the REST request body's privilege field.
var privilegeByName = map[string]bmcpkg.Privilege{
	"no-access":     bmcpkg.PrivilegeNoAccess,
	"callback":      bmcpkg.PrivilegeCallback,
	"user":          bmcpkg.PrivilegeUser,
	"operator":      bmcpkg.PrivilegeOperator,
	"administrator": bmcpkg.PrivilegeAdministrator,
}

// HandlerParams contains the dependencies for creating a BMC handler.
type HandlerParams struct {
	Logger           *logging.Logger
	BMCService       BMCServicer
	BaremetalService BaremetalServicer
	ResponseWriter   response.HttpWriter
}

// handler implements the RestHandler interface.
type handler struct {
	logger           *logging.Logger
	bmcService       BMCServicer
	baremetalService BaremetalServicer
	responseWriter   response.HttpWriter
	powerActions     map[string]powerActionHandler
	enrollDeps       enrollDeps
	restoreDeps      restoreDeps
}

// NewHandler creates a new BMC REST handler with the given parameters.
func NewHandler(params HandlerParams) (RestHandler, error) {
	if params.Logger == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingLogger{}}
	}
	if params.BMCService == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingBMCService{}}
	}
	if params.ResponseWriter == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingResponseWriter{}}
	}

	h := &handler{
		logger:           params.Logger,
		bmcService:       params.BMCService,
		baremetalService: params.BaremetalService,
		responseWriter:   params.ResponseWriter,
	}

	// Map-based dispatch for power actions (O(1) lookup).
	h.powerActions = map[string]powerActionHandler{
		"on":    h.bmcService.PowerOn,
		"off":   h.bmcService.PowerOff,
		"reset": h.bmcService.PowerReset,
		"cycle": h.bmcService.PowerCycle,
	}

	return h, nil
}

// parseProfileID extracts and validates the profileID path parameter.
func (h *handler) parseProfileID(r *http.Request) (uint64, error) {
	vars := mux.Vars(r)
	idStr := vars["profileID"]
	if idStr == "" {
		return 0, ErrInvalidProfileID{}
	}
	profileID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, ErrInvalidProfileID{ID: idStr}
	}
	return profileID, nil
}

// parseSlot extracts and validates the slot path parameter as a uint8.
func (h *handler) parseSlot(r *http.Request) (uint8, error) {
	vars := mux.Vars(r)
	slotStr := vars["slot"]
	if slotStr == "" {
		return 0, ErrInvalidUserSlot{}
	}
	slot, err := strconv.ParseUint(slotStr, 10, 8)
	if err != nil {
		return 0, ErrInvalidUserSlot{Slot: slotStr}
	}
	return uint8(slot), nil
}

// parsePrivilege resolves a privilege name from the REST wire format
// to a bmcpkg.Privilege value. Returns ErrInvalidPrivilege when the
// name is not recognized.
func parsePrivilege(name string) (bmcpkg.Privilege, error) {
	priv, ok := privilegeByName[name]
	if !ok {
		return 0, ErrInvalidPrivilege{Privilege: name}
	}
	return priv, nil
}

// PowerAction executes a power action (on, off, reset, cycle) on the BMC.
// POST /api/v1/bmc/{profileID}/power
func (h *handler) PowerAction(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: power action request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req PowerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Action == "" {
		h.responseWriter.Error400(w, r, ErrMissingAction{})
		return
	}

	actionFn, ok := h.powerActions[req.Action]
	if !ok {
		h.responseWriter.Error400(w, r, ErrInvalidAction(req))
		return
	}

	if err := actionFn(r.Context(), profileID); err != nil {
		h.writeBMCError(w, r, profileID, "power "+req.Action, err)
		return
	}

	h.logger.Info("bmc: power action completed",
		slog.Uint64("profile_id", profileID),
		slog.String("action", req.Action))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
		"action": req.Action,
	})
}

// PowerStatus returns the power state of the system.
// GET /api/v1/bmc/{profileID}/power
func (h *handler) PowerStatus(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: power status request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	state, err := h.bmcService.PowerStatus(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "power status", err)
		return
	}

	h.logger.Debug("bmc: power status retrieved",
		slog.Uint64("profile_id", profileID),
		slog.String("state", string(state)))

	h.responseWriter.Success200(w, r, PowerStatusResponse{
		State: string(state),
	})
}

// SetBootDevice sets the boot device for the system.
// POST /api/v1/bmc/{profileID}/boot-device
func (h *handler) SetBootDevice(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: set boot device request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req SetBootDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Device == "" {
		h.responseWriter.Error400(w, r, ErrMissingBootDevice{})
		return
	}

	device := bmcpkg.BootDevice(req.Device)
	if !device.IsValid() {
		h.responseWriter.Error400(w, r, ErrInvalidBootDevice{Device: req.Device})
		return
	}

	if err := h.bmcService.SetBootDevice(r.Context(), profileID, device, req.Persistent); err != nil {
		h.writeBMCError(w, r, profileID, "set boot device", err)
		return
	}

	h.logger.Info("bmc: boot device set",
		slog.Uint64("profile_id", profileID),
		slog.String("device", req.Device),
		slog.Bool("persistent", req.Persistent))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
		"device": req.Device,
	})
}

// GetBootDevice returns the current boot device override.
// GET /api/v1/bmc/{profileID}/boot-device
func (h *handler) GetBootDevice(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: get boot device request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	device, err := h.bmcService.GetBootDevice(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "get boot device", err)
		return
	}

	h.logger.Debug("bmc: boot device retrieved",
		slog.Uint64("profile_id", profileID),
		slog.String("device", string(device)))

	h.responseWriter.Success200(w, r, BootDeviceResponse{
		Device: string(device),
	})
}

// MountISO mounts an ISO image via virtual media.
// POST /api/v1/bmc/{profileID}/virtual-media
func (h *handler) MountISO(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: mount ISO request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req MountISORequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ISOURL == "" {
		h.responseWriter.Error400(w, r, ErrMissingISOURL{})
		return
	}

	if err := h.bmcService.MountISO(r.Context(), profileID, req.ISOURL); err != nil {
		h.writeBMCError(w, r, profileID, "mount ISO", err)
		return
	}

	h.logger.Info("bmc: ISO mounted",
		slog.Uint64("profile_id", profileID),
		slog.String("iso_url", req.ISOURL))

	h.responseWriter.Success200(w, r, map[string]string{
		"status":  "ok",
		"iso_url": req.ISOURL,
	})
}

// UnmountISO unmounts the currently mounted ISO virtual media.
// DELETE /api/v1/bmc/{profileID}/virtual-media
func (h *handler) UnmountISO(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: unmount ISO request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if err := h.bmcService.UnmountISO(r.Context(), profileID); err != nil {
		h.writeBMCError(w, r, profileID, "unmount ISO", err)
		return
	}

	h.logger.Info("bmc: ISO unmounted",
		slog.Uint64("profile_id", profileID))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
	})
}

// VirtualMediaStatus returns the current virtual media state.
// GET /api/v1/bmc/{profileID}/virtual-media
func (h *handler) VirtualMediaStatus(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: virtual media status request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	info, err := h.bmcService.VirtualMediaStatus(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "virtual media status", err)
		return
	}

	h.logger.Debug("bmc: virtual media status retrieved",
		slog.Uint64("profile_id", profileID),
		slog.Bool("mounted", info.Mounted))

	h.responseWriter.Success200(w, r, info)
}

// GetSensors returns sensor readings from the BMC.
// GET /api/v1/bmc/{profileID}/sensors
func (h *handler) GetSensors(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: get sensors request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	sensors, err := h.bmcService.GetSensors(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "get sensors", err)
		return
	}

	h.logger.Debug("bmc: sensors retrieved",
		slog.Uint64("profile_id", profileID),
		slog.Int("count", len(sensors)))

	h.responseWriter.Success200(w, r, sensors)
}

// GetSystemInfo returns system identification information from the BMC.
// GET /api/v1/bmc/{profileID}/system-info
func (h *handler) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: get system info request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	info, err := h.bmcService.GetSystemInfo(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "get system info", err)
		return
	}

	h.logger.Debug("bmc: system info retrieved",
		slog.Uint64("profile_id", profileID))

	h.responseWriter.Success200(w, r, info)
}

// Provision triggers a bare metal provisioning workflow.
// POST /api/v1/bmc/{profileID}/provision
func (h *handler) Provision(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: provision request received")

	if h.baremetalService == nil {
		h.responseWriter.Error503(w, r, ErrBaremetalServiceNotAvailable{})
		return
	}

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	provReq := baremetal.ProvisionRequest{
		ProfileID: profileID,
		ISOURL:    req.ISOURL,
	}

	result, err := h.baremetalService.Provision(r.Context(), provReq)
	if err != nil {
		h.writeProvisionError(w, r, profileID, err)
		return
	}

	h.logger.Info("bmc: provisioning started",
		slog.Uint64("profile_id", profileID),
		slog.String("provision_id", result.ProvisionID))

	h.responseWriter.Success201(w, r, result)
}

// ProvisionStatus returns the status of a provisioning workflow.
// GET /api/v1/bmc/{profileID}/provision
func (h *handler) ProvisionStatus(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: provision status request received")

	if h.baremetalService == nil {
		h.responseWriter.Error503(w, r, ErrBaremetalServiceNotAvailable{})
		return
	}

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	result, err := h.baremetalService.Status(r.Context(), profileID)
	if err != nil {
		h.writeProvisionStatusError(w, r, profileID, err)
		return
	}

	h.logger.Debug("bmc: provision status retrieved",
		slog.Uint64("profile_id", profileID),
		slog.String("status", string(result.Status)))

	h.responseWriter.Success200(w, r, result)
}

// GetWebCertificate returns the metadata of the BMC's current web
// server TLS certificate.
// GET /api/v1/bmc/{profileID}/cert
func (h *handler) GetWebCertificate(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: get web certificate request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	info, err := h.bmcService.GetWebCertificate(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "get web certificate", err)
		return
	}

	h.logger.Debug("bmc: web certificate retrieved",
		slog.Uint64("profile_id", profileID))

	h.responseWriter.Success200(w, r, info)
}

// ReplaceWebCertificate uploads a new web server TLS certificate and
// private key to the BMC.
// PUT /api/v1/bmc/{profileID}/cert
func (h *handler) ReplaceWebCertificate(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: replace web certificate request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req ReplaceWebCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.CertPEM == "" {
		h.responseWriter.Error400(w, r, ErrMissingCertPEM{})
		return
	}
	if req.KeyPEM == "" {
		h.responseWriter.Error400(w, r, ErrMissingKeyPEM{})
		return
	}

	if err := h.bmcService.ReplaceWebCertificate(r.Context(), profileID, []byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		h.writeBMCError(w, r, profileID, "replace web certificate", err)
		return
	}

	h.logger.Info("bmc: web certificate replaced",
		slog.Uint64("profile_id", profileID))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
	})
}

// ListUsers returns the populated user slots known to the BMC.
// GET /api/v1/bmc/{profileID}/users
func (h *handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: list users request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	users, err := h.bmcService.ListUsers(r.Context(), profileID)
	if err != nil {
		h.writeBMCError(w, r, profileID, "list users", err)
		return
	}

	h.logger.Debug("bmc: users listed",
		slog.Uint64("profile_id", profileID),
		slog.Int("count", len(users)))

	h.responseWriter.Success200(w, r, users)
}

// CreateUser creates a new BMC user account.
// POST /api/v1/bmc/{profileID}/users
func (h *handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: create user request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Username == "" {
		h.responseWriter.Error400(w, r, ErrMissingUsername{})
		return
	}
	if req.Password == "" {
		h.responseWriter.Error400(w, r, ErrMissingPassword{})
		return
	}
	if req.Privilege == "" {
		h.responseWriter.Error400(w, r, ErrMissingPrivilege{})
		return
	}
	priv, err := parsePrivilege(req.Privilege)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	user := bmcpkg.User{
		Slot:      req.Slot,
		Username:  req.Username,
		Enabled:   req.Enabled,
		Privilege: priv,
		Channel:   req.Channel,
	}

	if err := h.bmcService.CreateUser(r.Context(), profileID, user, req.Password); err != nil {
		h.writeBMCError(w, r, profileID, "create user", err)
		return
	}

	h.logger.Info("bmc: user created",
		slog.Uint64("profile_id", profileID),
		slog.String("username", req.Username),
		slog.Uint64("slot", uint64(req.Slot)))

	h.responseWriter.Success201(w, r, user)
}

// DeleteUser deletes the BMC user occupying the given slot.
// DELETE /api/v1/bmc/{profileID}/users/{slot}
func (h *handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: delete user request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	slot, err := h.parseSlot(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if err := h.bmcService.DeleteUser(r.Context(), profileID, slot); err != nil {
		h.writeBMCError(w, r, profileID, "delete user", err)
		return
	}

	h.logger.Info("bmc: user deleted",
		slog.Uint64("profile_id", profileID),
		slog.Uint64("slot", uint64(slot)))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
	})
}

// SetUserPassword updates the password for an existing BMC user slot.
// PUT /api/v1/bmc/{profileID}/users/{slot}/password
func (h *handler) SetUserPassword(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: set user password request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	slot, err := h.parseSlot(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req SetUserPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Password == "" {
		h.responseWriter.Error400(w, r, ErrMissingPassword{})
		return
	}

	if err := h.bmcService.SetUserPassword(r.Context(), profileID, slot, req.Password); err != nil {
		h.writeBMCError(w, r, profileID, "set user password", err)
		return
	}

	h.logger.Info("bmc: user password updated",
		slog.Uint64("profile_id", profileID),
		slog.Uint64("slot", uint64(slot)))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
	})
}

// SetUserPrivilege updates the channel privilege level for an existing
// BMC user slot.
// PUT /api/v1/bmc/{profileID}/users/{slot}/privilege
func (h *handler) SetUserPrivilege(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("bmc: set user privilege request received")

	profileID, err := h.parseProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	slot, err := h.parseSlot(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var req SetUserPrivilegeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("bmc: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Privilege == "" {
		h.responseWriter.Error400(w, r, ErrMissingPrivilege{})
		return
	}
	priv, err := parsePrivilege(req.Privilege)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if err := h.bmcService.SetUserPrivilege(r.Context(), profileID, slot, req.Channel, priv); err != nil {
		h.writeBMCError(w, r, profileID, "set user privilege", err)
		return
	}

	h.logger.Info("bmc: user privilege updated",
		slog.Uint64("profile_id", profileID),
		slog.Uint64("slot", uint64(slot)),
		slog.String("privilege", req.Privilege))

	h.responseWriter.Success200(w, r, map[string]string{
		"status": "ok",
	})
}

// writeBMCError writes an appropriate error response for BMC operation errors.
func (h *handler) writeBMCError(w http.ResponseWriter, r *http.Request, profileID uint64, operation string, err error) {
	var profileNotFound bmcpkg.ErrProfileNotFound
	if errors.As(err, &profileNotFound) {
		h.responseWriter.Error404(w, r, profileNotFound)
		return
	}

	h.logger.Errorf("bmc: %s failed for profile_id=%d: %v", operation, profileID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: operation, Cause: err})
}

// writeProvisionError writes an appropriate error response for provision errors.
func (h *handler) writeProvisionError(w http.ResponseWriter, r *http.Request, profileID uint64, err error) {
	var inProgress baremetal.ErrProvisionInProgress
	if errors.As(err, &inProgress) {
		h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   inProgress.Error(),
			Success: false,
		})
		return
	}

	var invalidReq baremetal.ErrInvalidProvisionRequest
	if errors.As(err, &invalidReq) {
		h.responseWriter.Error400(w, r, invalidReq)
		return
	}

	var profileNoBMC baremetal.ErrProfileNoBMC
	if errors.As(err, &profileNoBMC) {
		h.responseWriter.Error400(w, r, profileNoBMC)
		return
	}

	h.logger.Errorf("bmc: provision failed for profile_id=%d: %v", profileID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "provision", Cause: err})
}

// writeProvisionStatusError writes an appropriate error response for provision status errors.
func (h *handler) writeProvisionStatusError(w http.ResponseWriter, r *http.Request, profileID uint64, err error) {
	var notFound baremetal.ErrProvisionNotFound
	if errors.As(err, &notFound) {
		h.responseWriter.Error404(w, r, notFound)
		return
	}

	h.logger.Errorf("bmc: provision status failed for profile_id=%d: %v", profileID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "provision status", Cause: err})
}

// Ensure handler implements RestHandler interface.
var _ RestHandler = (*handler)(nil)
