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
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
)

// ceremonyRESTHandlers is the REST adapter for CeremonyService.
type ceremonyRESTHandlers struct {
	service *CeremonyService
}

// newCeremonyRESTHandlers constructs a ceremony REST handler.
func newCeremonyRESTHandlers(svc *CeremonyService) *ceremonyRESTHandlers {
	return &ceremonyRESTHandlers{service: svc}
}

// registerCeremonyRoutes mounts ceremony endpoints under /ceremony on the
// supplied router.
func (h *ceremonyRESTHandlers) registerCeremonyRoutes(router *mux.Router) {
	r := router.PathPrefix("/ceremony").Subrouter()
	r.HandleFunc("/init", h.init).Methods(http.MethodPost)
	r.HandleFunc("/status", h.status).Methods(http.MethodGet)
	r.HandleFunc("/claim-cert/begin", h.claimCertBegin).Methods(http.MethodPost)
	r.HandleFunc("/claim-cert/complete", h.claimCertComplete).Methods(http.MethodPost)
	r.HandleFunc("/claim-share", h.claimShare).Methods(http.MethodPost)
	r.HandleFunc("/sign-csr", h.signCSR).Methods(http.MethodPost)
}

func writeRESTJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func decodeRESTBody(r *http.Request, out interface{}) error {
	if r.Body == nil {
		return nil
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func ceremonyErrorToHTTP(err error) int {
	switch {
	case errors.Is(err, ErrCeremonyNotConfigured):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrCeremonyOfficerRequired),
		errors.Is(err, ErrCeremonyChallengeRequired),
		errors.Is(err, ErrCeremonyCSRRequired):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (h *ceremonyRESTHandlers) init(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SOPIN                  string   `json:"so_pin,omitempty"`
		UserPIN                string   `json:"user_pin,omitempty"`
		Threshold              string   `json:"threshold,omitempty"`
		Hostname               string   `json:"hostname,omitempty"`
		SANs                   []string `json:"sans,omitempty"`
		CredentialSealStrategy string   `json:"credential_seal_strategy,omitempty"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.Init(r.Context(), &CeremonyInitRequest{
		SOPIN: in.SOPIN, UserPIN: in.UserPIN, Threshold: in.Threshold, Hostname: in.Hostname, SANs: in.SANs,
		CredentialSealStrategy: in.CredentialSealStrategy,
	})
	if err != nil {
		writeRESTJSON(w, ceremonyErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	payload := map[string]interface{}{
		"ceremony_id": out.CeremonyID,
		"state":       string(out.State),
	}
	if !out.InitializedAt.IsZero() {
		payload["initialized_at"] = out.InitializedAt
	}
	writeRESTJSON(w, http.StatusOK, payload)
}

func (h *ceremonyRESTHandlers) status(w http.ResponseWriter, r *http.Request) {
	out, err := h.service.Status(r.Context())
	if err != nil {
		writeRESTJSON(w, ceremonyErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	payload := map[string]interface{}{
		"ceremony_id":       out.CeremonyID,
		"state":             string(out.State),
		"threshold":         out.Threshold,
		"officers_enrolled": out.OfficersEnrolled,
		"officers_required": out.OfficersRequired,
	}
	if !out.InitializedAt.IsZero() {
		payload["initialized_at"] = out.InitializedAt
	}
	writeRESTJSON(w, http.StatusOK, payload)
}

func (h *ceremonyRESTHandlers) claimCertBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username          string `json:"username"`
		AuthenticatorType string `json:"authenticator_type,omitempty"`
		Slot              string `json:"slot,omitempty"`
		CredentialID      string `json:"credential_id,omitempty"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.ClaimCertBegin(r.Context(), &CeremonyClaimCertBeginRequest{
		Username:          in.Username,
		AuthenticatorType: CeremonyAuthenticatorType(in.AuthenticatorType),
		Slot:              in.Slot,
		CredentialID:      in.CredentialID,
	})
	if err != nil {
		writeRESTJSON(w, ceremonyErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	payload := map[string]interface{}{"nonce": out.Nonce, "challenge_id": out.ChallengeID}
	if !out.ExpiresAt.IsZero() {
		payload["expires_at"] = out.ExpiresAt
	}
	writeRESTJSON(w, http.StatusOK, payload)
}

func (h *ceremonyRESTHandlers) claimCertComplete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username  string `json:"username"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.ClaimCertComplete(r.Context(), &CeremonyClaimCertCompleteRequest{
		Username: in.Username, Nonce: in.Nonce, Signature: in.Signature,
	})
	if err != nil {
		writeRESTJSON(w, ceremonyErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]string{
		"certificate_pem": out.CertificatePEM, "chain_pem": out.ChainPEM,
	})
}

func (h *ceremonyRESTHandlers) claimShare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.ClaimShare(r.Context(), in.Username)
	if err != nil {
		writeRESTJSON(w, ceremonyErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]interface{}{"share": out.Share, "index": out.Index})
}

func (h *ceremonyRESTHandlers) signCSR(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		SOPIN    string `json:"so_pin"`
		CSRPEM   string `json:"csr_pem"`
		Role     string `json:"role"`
	}
	if err := decodeRESTBody(r, &in); err != nil {
		writeRESTJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out, err := h.service.SignCSR(r.Context(), &CeremonySignCSRRequest{
		Username: in.Username, SOPIN: in.SOPIN, CSRPEM: in.CSRPEM, Role: CeremonyOfficerRole(in.Role),
	})
	if err != nil {
		writeRESTJSON(w, ceremonyErrorToHTTP(err), map[string]string{"error": err.Error()})
		return
	}
	writeRESTJSON(w, http.StatusOK, map[string]string{
		"certificate_pem": out.CertificatePEM, "chain_pem": out.ChainPEM,
	})
}
