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

package adminclaim

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

const (
	// basePath is the claim ceremony's mount point under /api/v1.
	basePath = "/admin/claim"

	// ClaimTokenHeader carries the single-use claim token through the
	// passkey ceremony. It is a header rather than a bearer so it can
	// never be mistaken for — or replayed as — a session token.
	ClaimTokenHeader = "X-Admin-Claim"

	// SessionIDHeader carries the SDK ceremony session id back from the
	// browser on finish, matching the WebAuthn handler's convention.
	SessionIDHeader = "X-Session-Id"

	// maxBodyBytes caps a pre-auth request body. The largest legitimate
	// one is a PEM certificate plus a signature.
	maxBodyBytes = 64 << 10
)

// RestHandler binds the claim ceremony to HTTP. It holds no ceremony
// logic: every decision belongs to Service.
type RestHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	service        *Service
}

// NewRestHandler constructs the HTTP binding for the claim ceremony.
func NewRestHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	svc *Service,
) (*RestHandler, error) {

	if logger == nil {
		return nil, ErrDependencyRequired{Name: "logger"}
	}
	if responseWriter == nil {
		return nil, ErrDependencyRequired{Name: "response writer"}
	}
	if svc == nil {
		return nil, ErrDependencyRequired{Name: "claim service"}
	}
	return &RestHandler{logger: logger, responseWriter: responseWriter, service: svc}, nil
}

// RegisterRoutes mounts the claim ceremony.
//
// Every route is deliberately PRE-AUTH: the whole point of the ceremony is
// that no session exists yet. What protects it is the certificate proof,
// the single-use short-lived secrets, and the fact that the flow closes
// permanently once an authenticator is enrolled.
func (h *RestHandler) RegisterRoutes(router *mux.Router) {
	claimRouter := router.PathPrefix(basePath).Subrouter()
	claimRouter.HandleFunc("/status", h.Status).Methods(http.MethodGet)
	claimRouter.HandleFunc("/challenge", h.Challenge).Methods(http.MethodPost)
	claimRouter.HandleFunc("/verify", h.Verify).Methods(http.MethodPost)
	claimRouter.HandleFunc("/passkey/begin", h.BeginPasskey).Methods(http.MethodPost)
	claimRouter.HandleFunc("/passkey/finish", h.FinishPasskey).Methods(http.MethodPost)
}

// StatusResponse reports whether the node's admin identity is claimed.
type StatusResponse struct {
	Claimed  bool   `json:"claimed"`
	Username string `json:"username"`
	TenantID string `json:"tenant_id"`
}

// ChallengeResponse carries a possession nonce.
type ChallengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// VerifyResponse carries the single-use claim token.
type VerifyResponse struct {
	ClaimToken string    `json:"claim_token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// FinishResponse carries the console bearer minted on a completed claim.
type FinishResponse struct {
	Token    string `json:"token"`
	TenantID string `json:"tenant_id"`
}

// Status reports whether the system admin identity has been claimed. It
// discloses no secret — only whether the one-time flow is still open — so
// the console can route a fresh node to the setup page.
func (h *RestHandler) Status(w http.ResponseWriter, r *http.Request) {
	claimed, err := h.service.Claimed(r.Context())
	if err != nil {
		h.logger.Error(err, "adminclaim: cannot determine claim status")
		h.responseWriter.Error500(w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, StatusResponse{
		Claimed:  claimed,
		Username: h.service.adminUsername,
		TenantID: h.service.tenantID,
	})
}

// Challenge issues a nonce for the operator to sign with admin.key.
func (h *RestHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	challenge, expiresAt, err := h.service.Challenge(r.Context())
	if err != nil {
		h.writeClaimError(w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, ChallengeResponse{
		Challenge: challenge,
		ExpiresAt: expiresAt,
	})
}

// Verify validates possession of the firstboot admin credential and opens
// a single-use claim.
//
// The body is OPTIONAL. When the TLS handshake already presented the admin
// certificate the handshake IS the proof, and Service.Prove checks the peer
// certificate before it looks at the request at all — so an mTLS caller
// sends nothing (docs/auth/api.md §POST /api/v1/admin/claim/verify).
// Requiring a body here made that documented path unreachable: the request
// died on EOF with a 400 before Prove ever saw the certificate.
func (h *RestHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req ProveRequest
	if err := decodeOptionalBody(r, &req); err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	token, expiresAt, err := h.service.Prove(r.Context(), req, PeerCertificates(r))
	if err != nil {
		h.writeClaimError(w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, VerifyResponse{ClaimToken: token, ExpiresAt: expiresAt})
}

// BeginPasskey starts WebAuthn registration for the admin identity.
func (h *RestHandler) BeginPasskey(w http.ResponseWriter, r *http.Request) {
	options, err := h.service.BeginPasskey(r.Context(), r.Header.Get(ClaimTokenHeader))
	if err != nil {
		h.writeClaimError(w, r, err)
		return
	}
	// The browser consumes the parsed CredentialCreation object; the SDK
	// session id rides the payload and comes back on the finish header.
	// The platform persists no ceremony state.
	creation, err := parseCreationOptions(options.OptionsJSON)
	if err != nil {
		h.logger.Error(err, "adminclaim: sdk BeginRegistration returned unparseable options")
		h.responseWriter.Error500(w, r, err)
		return
	}
	creation["session_id"] = options.SessionID
	h.responseWriter.Write(w, r, http.StatusOK, creation)
}

// FinishPasskey completes WebAuthn registration and returns a console
// bearer for the now-claimed system admin.
func (h *RestHandler) FinishPasskey(w http.ResponseWriter, r *http.Request) {
	attestation, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Cause: err})
		return
	}
	token, err := h.service.FinishPasskey(r.Context(), r.Header.Get(ClaimTokenHeader),
		&quicbaassdk.FIDO2FinishRegistrationRequest{
			SessionID:       r.Header.Get(SessionIDHeader),
			AttestationJSON: string(attestation),
		})
	if err != nil {
		h.writeClaimError(w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, FinishResponse{Token: token, TenantID: h.service.tenantID})
}

// writeClaimError maps the ceremony's typed errors onto status codes.
// Every rejection of a proof is a 403 with a generic reason: telling a
// caller which check failed would let them probe the anchor, the identity
// rule and the challenge store separately.
func (h *RestHandler) writeClaimError(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case ErrAlreadyClaimed:
		h.responseWriter.Error403(w, r, err, nil)
	case ErrChallengeUnknown, ErrClaimTokenInvalid,
		ErrCertificateInvalid, ErrIdentityMismatch, ErrProofInvalid:
		h.logger.Debugf("adminclaim: proof rejected: %v", err)
		h.responseWriter.Error403(w, r, ErrProofRejected{}, nil)
	case ErrCeremonyRejected:
		h.responseWriter.Error400(w, r, err)
	case ErrMultiInstanceUnsupported:
		// 501, not 500. This deployment shape is deliberately not served
		// (see the type's own doc and #170); that is a statement about
		// what this server implements, not a fault in handling the
		// request. A 500 told operators to look for a bug and buried the
		// typed explanation in a generic failure.
		h.responseWriter.Write(w, r, http.StatusNotImplemented, restwire.WebServiceResponse{
			Code:    http.StatusNotImplemented,
			Error:   err.Error(),
			Success: false,
		})
	case ErrTooManyOutstanding:
		h.responseWriter.Write(w, r, http.StatusTooManyRequests, restwire.WebServiceResponse{
			Code:    http.StatusTooManyRequests,
			Error:   err.Error(),
			Success: false,
		})
	default:
		h.logger.Error(err, "adminclaim: request failed")
		h.responseWriter.Error500(w, r, err)
	}
}

// decodeOptionalBody reads a size-capped JSON body that the caller may
// omit entirely, leaving target at its zero value.
//
// Only a COMPLETELY absent body is tolerated: json.Decoder reports that as
// io.EOF, and a body that starts and then stops as io.ErrUnexpectedEOF,
// which stays an error. A truncated or corrupt request is still a 400 — the
// tolerance is for "said nothing", never for "said something broken".
func decodeOptionalBody(r *http.Request, target any) error {
	err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(target)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return ErrInvalidRequestBody{Cause: err}
	}
	return nil
}

// parseCreationOptions unwraps the SDK's marshaled CredentialCreation so
// the browser receives publicKey at the top level, matching what
// navigator.credentials.create() expects.
func parseCreationOptions(optionsJSON string) (map[string]interface{}, error) {
	var creation map[string]interface{}
	if err := json.Unmarshal([]byte(optionsJSON), &creation); err != nil {
		return nil, ErrInvalidRequestBody{Cause: err}
	}
	return creation, nil
}
