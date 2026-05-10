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

// init_handlers.go implements the platformd "minimal" REST surface that is
// bound BEFORE the barrier is unsealed. Per docs/08-bootstrap-auth-architecture.md
// §7 and §8 #6, when the barrier is uninitialized or sealed the daemon must
// only expose:
//
//   - GET  /healthz   reports the current barrier state for orchestrators.
//   - POST /init      one-shot ceremony bootstrap (only valid in Uninitialized).
//   - POST /unseal    submit a single secret/share toward the unseal threshold.
//
// All other transports (gRPC TCP, REST business endpoints, QUIC, MCP) MUST NOT
// be bound until the barrier is unsealed.

package rest

import (
	"context"
	"encoding/json"

	"io"
	"net/http"
	"time"
)

// =============================================================================
// State enumeration (canonical strings reported on /healthz)
// =============================================================================

// PlatformState is the textual state reported on the /healthz endpoint and
// embedded in /init and /unseal responses.
type PlatformState string

const (
	// PlatformStateUninitialized indicates the barrier has never been
	// initialized; only POST /init is accepted.
	PlatformStateUninitialized PlatformState = "uninitialized"

	// PlatformStateSealed indicates the barrier is initialized but sealed;
	// only POST /unseal is accepted.
	PlatformStateSealed PlatformState = "sealed"

	// PlatformStateUnsealing indicates a multi-share unseal is in progress.
	PlatformStateUnsealing PlatformState = "unsealing"

	// PlatformStateUnsealed indicates the barrier is operational; remote
	// transports (gRPC TCP, full REST, QUIC, MCP) are bound.
	PlatformStateUnsealed PlatformState = "unsealed"
)

// =============================================================================
// Service contracts (interfaces consumed by the handlers)
// =============================================================================

// BarrierInitService bootstraps a fresh platform via the qrdb ceremony state
// machine. Implementations delegate to the quicbaas SDK Security().Ceremony()
// surface.
type BarrierInitService interface {
	// Initialize runs the canonical ceremony bootstrap. Returns the ceremony
	// state and any data the operator must capture (admin bundle, SPKI pin).
	Initialize(ctx context.Context, req *BarrierInitRequest) (*BarrierInitResponse, error)
}

// BarrierUnsealService submits secrets or shares toward the unseal threshold.
// The underlying barrier manager is responsible for tracking quorum progress.
type BarrierUnsealService interface {
	// Unseal submits a secret or Shamir share. Progress is reported in the
	// returned response so multi-share workflows can iterate.
	Unseal(ctx context.Context, req *BarrierUnsealRequest) (*BarrierUnsealResponse, error)
}

// PlatformStateProvider returns the current platform state. The provider is
// queried on every /healthz request; implementations must be safe for
// concurrent use.
type PlatformStateProvider interface {
	// State returns the current platform state.
	State(ctx context.Context) PlatformState
}

// =============================================================================
// Request/response types
// =============================================================================

// BarrierInitRequest is the JSON body accepted by POST /init.
type BarrierInitRequest struct {
	SOPIN                  string   `json:"so_pin,omitempty"`
	UserPIN                string   `json:"user_pin,omitempty"`
	BarrierStrategy        string   `json:"barrier_strategy,omitempty"`
	Shares                 int      `json:"shares,omitempty"`
	Threshold              int      `json:"threshold,omitempty"`
	Hostname               string   `json:"hostname,omitempty"`
	SANs                   []string `json:"sans,omitempty"`
	CredentialSealStrategy string   `json:"credential_seal_strategy,omitempty"`
}

// BarrierInitResponse is the JSON body returned by POST /init.
type BarrierInitResponse struct {
	CeremonyID    string        `json:"ceremony_id,omitempty"`
	State         PlatformState `json:"state"`
	InitializedAt time.Time     `json:"initialized_at,omitempty"`
	SPKIPin       string        `json:"spki_pin,omitempty"`
	AdminCertPEM  string        `json:"admin_cert_pem,omitempty"`
	AdminKeyPEM   string        `json:"admin_key_pem,omitempty"`
}

// BarrierUnsealRequest is the JSON body accepted by POST /unseal.
type BarrierUnsealRequest struct {
	// Secret is the master secret for software-strategy unseals.
	Secret string `json:"secret,omitempty"`
	// Share is a single Shamir share (mutually exclusive with Secret).
	Share string `json:"share,omitempty"`
}

// BarrierUnsealResponse is the JSON body returned by POST /unseal.
type BarrierUnsealResponse struct {
	State          PlatformState `json:"state"`
	SharesProvided int           `json:"shares_provided"`
	Required       int           `json:"required"`
	Sealed         bool          `json:"sealed"`
}

// BarrierHealthResponse is the JSON body returned by GET /healthz.
type BarrierHealthResponse struct {
	State PlatformState `json:"state"`
	Ready bool          `json:"ready"`
}

// =============================================================================
// Typed errors
// =============================================================================

// ErrInitNotPermitted indicates POST /init was rejected because the barrier
// is already initialized.
type ErrInitNotPermitted struct {
	Current PlatformState
}

// Error returns a human-readable description of the error.
func (e *ErrInitNotPermitted) Error() string {
	return "init not permitted: current state is " + string(e.Current)
}

// ErrUnsealNotPermitted indicates POST /unseal was rejected because the
// barrier is not in a sealed state.
type ErrUnsealNotPermitted struct {
	Current PlatformState
}

// Error returns a human-readable description of the error.
func (e *ErrUnsealNotPermitted) Error() string {
	return "unseal not permitted: current state is " + string(e.Current)
}

// ErrBarrierInitServiceUnavailable indicates the init service backend is not
// wired.
type ErrBarrierInitServiceUnavailable struct{}

// Error returns a human-readable description of the error.
func (e *ErrBarrierInitServiceUnavailable) Error() string {
	return "init service unavailable"
}

// ErrBarrierUnsealServiceUnavailable indicates the unseal service backend is
// not wired.
type ErrBarrierUnsealServiceUnavailable struct{}

// Error returns a human-readable description of the error.
func (e *ErrBarrierUnsealServiceUnavailable) Error() string {
	return "unseal service unavailable"
}

// =============================================================================
// InitHandlers wires HTTP routes for the minimal pre-unseal surface.
// =============================================================================

// InitHandlers groups the init/unseal/healthz HTTP handlers. It is safe for
// concurrent use; service references are read-only after construction.
type InitHandlers struct {
	state   PlatformStateProvider
	init    BarrierInitService
	unseal  BarrierUnsealService
	maxBody int64
}

// InitHandlersConfig configures InitHandlers.
type InitHandlersConfig struct {
	// State reports the current platform state. Required.
	State PlatformStateProvider
	// Init delegates POST /init to a ceremony backend. Optional: when nil
	// /init returns 503 ErrBarrierInitServiceUnavailable.
	Init BarrierInitService
	// Unseal delegates POST /unseal to a barrier backend. Optional: when
	// nil /unseal returns 503 ErrBarrierUnsealServiceUnavailable.
	Unseal BarrierUnsealService
	// MaxBodyBytes caps the size of accepted request bodies. Defaults to
	// 64 KiB which is more than enough for any init/unseal payload.
	MaxBodyBytes int64
}

// NewInitHandlers constructs an InitHandlers from the given config.
func NewInitHandlers(cfg InitHandlersConfig) *InitHandlers {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 64 * 1024
	}
	return &InitHandlers{
		state:   cfg.State,
		init:    cfg.Init,
		unseal:  cfg.Unseal,
		maxBody: maxBody,
	}
}

// Register attaches the minimal pre-unseal routes to the supplied mux. A
// ServeMux is used (rather than a third-party router) to keep the
// init-only surface dependency-free.
func (h *InitHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.Healthz)
	mux.HandleFunc("/init", h.Init)
	mux.HandleFunc("/unseal", h.Unseal)
}

// Healthz reports the current platform state. It is always callable, even
// in init-only mode, so orchestrators can probe readiness.
func (h *InitHandlers) Healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeInitJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	state := h.currentState(r.Context())
	writeInitJSON(w, http.StatusOK, &BarrierHealthResponse{
		State: state,
		Ready: state == PlatformStateUnsealed,
	})
}

// Init performs the ceremony bootstrap. Returns 409 Conflict when the
// barrier is already initialized.
func (h *InitHandlers) Init(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeInitJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	if h.init == nil {
		writeInitJSON(w, http.StatusServiceUnavailable, errorBody((&ErrBarrierInitServiceUnavailable{}).Error()))
		return
	}
	state := h.currentState(r.Context())
	if state != PlatformStateUninitialized {
		writeInitJSON(w, http.StatusConflict, errorBody((&ErrInitNotPermitted{Current: state}).Error()))
		return
	}
	var body BarrierInitRequest
	if err := decodeInitJSON(r, h.maxBody, &body); err != nil {
		writeInitJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	resp, err := h.init.Initialize(r.Context(), &body)
	if err != nil {
		writeInitJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if resp == nil {
		resp = &BarrierInitResponse{}
	}
	if resp.State == "" {
		resp.State = h.currentState(r.Context())
	}
	writeInitJSON(w, http.StatusOK, resp)
}

// Unseal submits a secret or share toward the unseal threshold. Returns 409
// Conflict when the barrier is not in a sealed state.
func (h *InitHandlers) Unseal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeInitJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	if h.unseal == nil {
		writeInitJSON(w, http.StatusServiceUnavailable, errorBody((&ErrBarrierUnsealServiceUnavailable{}).Error()))
		return
	}
	state := h.currentState(r.Context())
	// Only Sealed and Unsealing accept share submissions; Uninitialized
	// must run /init first, Unsealed has no work for /unseal to do.
	if state != PlatformStateSealed && state != PlatformStateUnsealing {
		writeInitJSON(w, http.StatusConflict, errorBody((&ErrUnsealNotPermitted{Current: state}).Error()))
		return
	}
	var body BarrierUnsealRequest
	if err := decodeInitJSON(r, h.maxBody, &body); err != nil {
		writeInitJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	resp, err := h.unseal.Unseal(r.Context(), &body)
	if err != nil {
		writeInitJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if resp == nil {
		resp = &BarrierUnsealResponse{}
	}
	if resp.State == "" {
		resp.State = h.currentState(r.Context())
	}
	writeInitJSON(w, http.StatusOK, resp)
}

// currentState returns the configured PlatformStateProvider's view, or
// PlatformStateUninitialized when no provider is wired.
func (h *InitHandlers) currentState(ctx context.Context) PlatformState {
	if h.state == nil {
		return PlatformStateUninitialized
	}
	return h.state.State(ctx)
}

// =============================================================================
// helpers
// =============================================================================

// writeInitJSON writes a JSON response, suppressing errors because the
// connection has already been claimed and there is nothing to do on a
// write failure.
func writeInitJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

// errorBody returns a small map suitable for JSON error responses.
func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}

// decodeInitJSON decodes the request body into out, applying a max-bytes
// cap to defend against accidental large uploads on the bootstrap path.
func decodeInitJSON(r *http.Request, max int64, out interface{}) error {
	if r.Body == nil {
		return nil
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return ErrInvalidRequestBody{Reason: err.Error()}
	}
	if int64(len(body)) > max {
		return ErrInvalidRequestBody{Reason: "request body exceeds maximum size"}
	}
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return ErrInvalidRequestBody{Reason: err.Error()}
	}
	return nil
}

// ensureErrorsImported keeps the errors import in case future error
// wrapping is added; gofmt removes unused imports otherwise.
