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

	"github.com/gorilla/mux"
)

// luksRESTHandlers is the REST adapter for LUKSService.
type luksRESTHandlers struct {
	service *LUKSService
}

// newLUKSRESTHandlers constructs a LUKS REST handler.
func newLUKSRESTHandlers(svc *LUKSService) *luksRESTHandlers {
	return &luksRESTHandlers{service: svc}
}

// registerLUKSRoutes mounts LUKS endpoints under /luks on the supplied router.
func (h *luksRESTHandlers) registerLUKSRoutes(router *mux.Router) {
	r := router.PathPrefix("/luks").Subrouter()
	r.HandleFunc("/status", h.status).Methods(http.MethodGet)
	r.HandleFunc("/slots", h.listSlots).Methods(http.MethodGet)
	r.HandleFunc("/info", h.info).Methods(http.MethodGet)
	r.HandleFunc("/enroll/passphrase", h.enrollPassphrase).Methods(http.MethodPost)
	r.HandleFunc("/enroll/fido2", h.enrollFIDO2).Methods(http.MethodPost)
	r.HandleFunc("/enroll/tpm", h.enrollTPM).Methods(http.MethodPost)
	r.HandleFunc("/enroll/recovery", h.enrollRecovery).Methods(http.MethodPost)
	r.HandleFunc("/keys/remove", h.removeKey).Methods(http.MethodPost)
	r.HandleFunc("/keys/test-unlock", h.testUnlock).Methods(http.MethodPost)
	r.HandleFunc("/passphrase/change", h.changePassphrase).Methods(http.MethodPost)
}

func luksErrorToHTTP(err error) int {
	switch {
	case errors.Is(err, ErrLUKSNotConfigured):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrLUKSRootRequired):
		return http.StatusForbidden
	case errors.Is(err, ErrLUKSDeviceRequired),
		errors.Is(err, ErrLUKSPassphraseRequired),
		errors.Is(err, ErrLUKSNewPassphraseRequired),
		errors.Is(err, ErrLUKSCredentialIDRequired),
		errors.Is(err, ErrLUKSSlotRequired):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (h *luksRESTHandlers) status(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.Status(r.Context(), r.URL.Query().Get("device"))
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) listSlots(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.ListSlots(r.Context(), r.URL.Query().Get("device"))
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) info(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.Info(r.Context(), r.URL.Query().Get("device"))
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) enrollPassphrase(w http.ResponseWriter, r *http.Request) {
	var in LUKSEnrollPassphraseRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.EnrollPassphrase(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) enrollFIDO2(w http.ResponseWriter, r *http.Request) {
	var in LUKSEnrollFIDO2Request
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.EnrollFIDO2(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) enrollTPM(w http.ResponseWriter, r *http.Request) {
	var in LUKSEnrollTPMRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.EnrollTPM(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) enrollRecovery(w http.ResponseWriter, r *http.Request) {
	var in LUKSEnrollRecoveryRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.EnrollRecovery(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *luksRESTHandlers) removeKey(w http.ResponseWriter, r *http.Request) {
	var in LUKSRemoveKeyRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.service.RemoveKey(r.Context(), &in); err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

func (h *luksRESTHandlers) testUnlock(w http.ResponseWriter, r *http.Request) {
	var in LUKSTestUnlockRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ok, err := h.service.TestUnlock(r.Context(), &in)
	if err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]bool{"unlocked": ok})
}

func (h *luksRESTHandlers) changePassphrase(w http.ResponseWriter, r *http.Request) {
	var in LUKSChangePassphraseRequest
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.service.ChangePassphrase(r.Context(), &in); err != nil {
		writeRESTJSON(w, luksErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]bool{"changed": true})
}
