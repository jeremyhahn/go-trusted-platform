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

// pivRESTHandlers is the REST adapter for PIVService.
type pivRESTHandlers struct {
	service *PIVService
}

// newPIVRESTHandlers constructs a PIV REST handler.
func newPIVRESTHandlers(svc *PIVService) *pivRESTHandlers {
	return &pivRESTHandlers{service: svc}
}

// registerPIVRoutes mounts PIV endpoints under /piv on the supplied router.
func (h *pivRESTHandlers) registerPIVRoutes(router *mux.Router) {
	r := router.PathPrefix("/piv").Subrouter()
	r.HandleFunc("/devices", h.listDevices).Methods(http.MethodGet)
	r.HandleFunc("/devices/{device}/slots", h.listSlots).Methods(http.MethodGet)
	r.HandleFunc("/slots/{slot}", h.slotInfo).Methods(http.MethodGet)
	r.HandleFunc("/slots/{slot}/generate", h.generate).Methods(http.MethodPost)
	r.HandleFunc("/slots/{slot}/import", h.doImport).Methods(http.MethodPost)
	r.HandleFunc("/slots/{slot}/sign", h.sign).Methods(http.MethodPost)
	r.HandleFunc("/slots/{slot}/attest", h.attest).Methods(http.MethodPost)
	r.HandleFunc("/devices/{device}/reset", h.reset).Methods(http.MethodPost)
}

func pivErrorToHTTP(err error) int {
	switch {
	case errors.Is(err, ErrPIVNotConfigured):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrPIVSlotRequired),
		errors.Is(err, ErrPIVDeviceRequired),
		errors.Is(err, ErrPIVPayloadRequired),
		errors.Is(err, ErrPIVPrivateKeyRequired):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (h *pivRESTHandlers) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.service.ListDevices(r.Context())
	if err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
}

func (h *pivRESTHandlers) listSlots(w http.ResponseWriter, r *http.Request) {
	slots, err := h.service.ListSlots(r.Context(), mux.Vars(r)["device"])
	if err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]interface{}{"slots": slots})
}

func (h *pivRESTHandlers) slotInfo(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.SlotInfo(r.Context(), r.URL.Query().Get("device"), mux.Vars(r)["slot"])
	if err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, out)
}

func (h *pivRESTHandlers) generate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Algorithm string `json:"algorithm"`
		PIN       string `json:"pin"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.Generate(r.Context(), &PIVGenerateRequest{
		Slot: mux.Vars(r)["slot"], Algorithm: PIVAlgorithm(in.Algorithm), PIN: in.PIN,
	})
	if err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]string{"public_key_pem": out.PublicKeyPEM})
}

func (h *pivRESTHandlers) doImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PrivateKeyPEM string `json:"private_key_pem"`
		PIN           string `json:"pin"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.service.Import(r.Context(), &PIVImportRequest{
		Slot: mux.Vars(r)["slot"], PrivateKeyPEM: in.PrivateKeyPEM, PIN: in.PIN,
	}); err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]bool{"imported": true})
}

func (h *pivRESTHandlers) sign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Payload []byte `json:"payload"`
		PIN     string `json:"pin"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	sig, err := h.service.Sign(r.Context(), &PIVSignRequest{
		Slot: mux.Vars(r)["slot"], Payload: in.Payload, PIN: in.PIN,
	})
	if err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string][]byte{"signature": sig})
}

func (h *pivRESTHandlers) attest(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.Attest(r.Context(), mux.Vars(r)["slot"])
	if err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]string{
		"attestation_cert_pem":  out.AttestationCertPEM,
		"attestation_chain_pem": out.AttestationChainPEM,
	})
}

func (h *pivRESTHandlers) reset(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Reset(r.Context(), mux.Vars(r)["device"]); err != nil {
		writeRESTJSON(w, pivErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]bool{"reset": true})
}
