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

package daemon

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// fido2RESTHandlers is the REST adapter for FIDO2Service.
type fido2RESTHandlers struct {
	service *FIDO2Service
}

// newFIDO2RESTHandlers constructs a FIDO2 REST handler.
func newFIDO2RESTHandlers(svc *FIDO2Service) *fido2RESTHandlers {
	return &fido2RESTHandlers{service: svc}
}

// registerFIDO2Routes mounts FIDO2 endpoints under /fido2 on the supplied router.
func (h *fido2RESTHandlers) registerFIDO2Routes(router *mux.Router) {
	r := router.PathPrefix("/fido2").Subrouter()
	r.HandleFunc("/devices", h.listDevices).Methods(http.MethodGet)
	r.HandleFunc("/devices/wait", h.waitDevice).Methods(http.MethodGet)
	r.HandleFunc("/devices/{device}", h.info).Methods(http.MethodGet)
	r.HandleFunc("/register", h.register).Methods(http.MethodPost)
	r.HandleFunc("/authenticate", h.authenticate).Methods(http.MethodPost)
}

func fido2ErrorToHTTP(err error) int {
	switch {
	case errors.Is(err, ErrFIDO2NotConfigured):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrFIDO2DeviceRequired),
		errors.Is(err, ErrFIDO2UsernameRequired),
		errors.Is(err, ErrFIDO2CredentialRequired):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (h *fido2RESTHandlers) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.service.ListDevices(r.Context())
	if err != nil {
		writeRESTJSON(w, fido2ErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
}

func (h *fido2RESTHandlers) waitDevice(w http.ResponseWriter, r *http.Request) {
	var timeout time.Duration
	if v := r.URL.Query().Get("timeout_seconds"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			timeout = d
		}
	}
	dev, err := h.service.WaitDevice(r.Context(), timeout)
	if err != nil {
		writeRESTJSON(w, fido2ErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, dev)
}

func (h *fido2RESTHandlers) info(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.Info(r.Context(), mux.Vars(r)["device"])
	if err != nil {
		writeRESTJSON(w, fido2ErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *fido2RESTHandlers) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username   string `json:"username"`
		Role       string `json:"role,omitempty"`
		RequirePIN bool   `json:"require_pin"`
		RequireUV  bool   `json:"require_uv"`
		RPID       string `json:"rp_id,omitempty"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.Register(r.Context(), &FIDO2RegisterRequest{
		Username: in.Username, Role: FIDO2Role(in.Role),
		RequirePIN: in.RequirePIN, RequireUV: in.RequireUV, RPID: in.RPID,
	})
	if err != nil {
		writeRESTJSON(w, fido2ErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *fido2RESTHandlers) authenticate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CredentialID string `json:"credential_id"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.Authenticate(r.Context(), in.CredentialID)
	if err != nil {
		writeRESTJSON(w, fido2ErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}
