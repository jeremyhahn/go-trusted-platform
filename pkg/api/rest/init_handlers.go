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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/ratelimit"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
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

// BarrierInitReplayer is implemented by an init service that can return the
// response of an init it already completed. It makes /init retry-safe: when
// the response carrying the one-shot admin bundle is lost after the barrier
// was initialized, an identical request receives the same bundle instead of
// a 409. Replay returns false for any request that does not match the one
// that was issued.
type BarrierInitReplayer interface {
	Replay(ctx context.Context, req *BarrierInitRequest) (*BarrierInitResponse, bool)
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

// BarrierInitRequest is the JSON body accepted by POST /init. The barrier
// seal strategy is not a request field: it comes from the barrier.seal_strategy
// configuration. A shamir init names one Security Officer per share.
type BarrierInitRequest struct {
	SOPIN                  string               `json:"so_pin,omitempty"`
	UserPIN                string               `json:"user_pin,omitempty"`
	Shares                 int                  `json:"shares,omitempty"`
	Threshold              int                  `json:"threshold,omitempty"`
	Hostname               string               `json:"hostname,omitempty"`
	SANs                   []string             `json:"sans,omitempty"`
	CredentialSealStrategy string               `json:"credential_seal_strategy,omitempty"`
	Officers               []BarrierInitOfficer `json:"officers,omitempty"`
}

// BarrierInitOfficer is a Security Officer enrolled by a shamir /init: the
// officer's username and the PEM certificate signing request the ceremony
// signs into its custodian certificate. The officer keeps the private key.
type BarrierInitOfficer struct {
	Username string `json:"username"`
	CSRPEM   string `json:"csr_pem"`
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

// ErrInitAlreadyIssued indicates POST /init was rejected because a different
// init request has already been issued by this daemon.
type ErrInitAlreadyIssued struct{}

// Error returns a human-readable description of the error.
func (e *ErrInitAlreadyIssued) Error() string {
	return "init not permitted: a different init request was already issued"
}

// ErrInitInvalidRequest indicates the init service refused a POST /init body
// before running the ceremony, so nothing was minted. Err names the reason.
type ErrInitInvalidRequest struct {
	Err error
}

// Error returns a human-readable description of the error.
func (e *ErrInitInvalidRequest) Error() string {
	return "init request invalid: " + e.Err.Error()
}

// Unwrap returns the reason the request was refused.
func (e *ErrInitInvalidRequest) Unwrap() error {
	return e.Err
}

// ErrInitBarrierConflict indicates the init service refused a POST /init body
// because the platform barrier cannot honour it as configured — a shamir
// request on a barrier not sealed by the Shamir strategy. It is refused before
// the ceremony runs, so nothing was minted. Err names the reason.
type ErrInitBarrierConflict struct {
	Err error
}

// Error returns a human-readable description of the error.
func (e *ErrInitBarrierConflict) Error() string {
	return "init request conflicts with the platform barrier: " + e.Err.Error()
}

// Unwrap returns the reason the request was refused.
func (e *ErrInitBarrierConflict) Unwrap() error {
	return e.Err
}

// ErrInitRateLimited indicates POST /init was refused because the caller
// exceeded its attempt budget.
type ErrInitRateLimited struct{}

// Error returns a human-readable description of the error.
func (e *ErrInitRateLimited) Error() string {
	return "init rate limited: too many attempts, retry later"
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
	state       PlatformStateProvider
	init        BarrierInitService
	unseal      BarrierUnsealService
	initLimiter ratelimit.Limiter
	maxBody     int64
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
	// InitLimiter budgets POST /init attempts per caller (see
	// initAttemptKey). Optional: when nil /init is not rate limited.
	// InitOnlyServer always supplies one.
	InitLimiter ratelimit.Limiter
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
		state:       cfg.State,
		init:        cfg.Init,
		unseal:      cfg.Unseal,
		initLimiter: cfg.InitLimiter,
		maxBody:     maxBody,
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

// Init performs the ceremony bootstrap. Once the barrier is initialized it
// returns 409 Conflict, unless the init service replays the identical
// request it already issued (see BarrierInitReplayer). Every attempt is
// rate limited, so the PINs cannot be guessed at speed.
func (h *InitHandlers) Init(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeInitJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	if h.initLimiter != nil && !h.initLimiter.Allow(initAttemptKey(r.Context())) {
		writeInitJSON(w, http.StatusTooManyRequests, errorBody((&ErrInitRateLimited{}).Error()))
		return
	}
	if h.init == nil {
		writeInitJSON(w, http.StatusServiceUnavailable, errorBody((&ErrBarrierInitServiceUnavailable{}).Error()))
		return
	}
	state := h.currentState(r.Context())
	if state != PlatformStateUninitialized {
		h.replayOrConflict(w, r, state)
		return
	}
	var body BarrierInitRequest
	if err := decodeInitJSON(r, h.maxBody, &body); err != nil {
		writeInitJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	resp, err := h.init.Initialize(r.Context(), &body)
	if err != nil {
		writeInitJSON(w, serviceErrorStatus(err), errorBody(err.Error()))
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

// replayOrConflict answers /init on an initialized barrier: the issued
// response for an identical request, 409 Conflict for anything else.
func (h *InitHandlers) replayOrConflict(w http.ResponseWriter, r *http.Request, state PlatformState) {
	conflict := errorBody((&ErrInitNotPermitted{Current: state}).Error())
	replayer, ok := h.init.(BarrierInitReplayer)
	if !ok {
		writeInitJSON(w, http.StatusConflict, conflict)
		return
	}
	var body BarrierInitRequest
	if err := decodeInitJSON(r, h.maxBody, &body); err != nil {
		writeInitJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	resp, ok := replayer.Replay(r.Context(), &body)
	if !ok {
		writeInitJSON(w, http.StatusConflict, conflict)
		return
	}
	resp.State = state
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
		writeInitJSON(w, serviceErrorStatus(err), errorBody(err.Error()))
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

// initAttemptKey names the rate-limit bucket of an /init caller. Each peer
// uid on the Unix socket has its own bucket and loopback HTTP shares one, so
// a guesser on one cannot spend the attempts of an operator on another.
func initAttemptKey(ctx context.Context) string {
	if creds, ok := peercred.UnixCredentialsFromContext(ctx); ok {
		return "unix:" + strconv.FormatUint(uint64(creds.UID), 10)
	}
	return "loopback"
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

// serviceErrorStatus maps an init or unseal service error to an HTTP status.
// A service reports a caller mistake with ErrMissingRequiredField,
// ErrInvalidRequestBody or ErrInitInvalidRequest, which answer 400. A
// different init already issued (ErrInitAlreadyIssued) or a request the
// barrier cannot honour as configured (ErrInitBarrierConflict) answers 409.
// Any other error is classified by barrier.Code, the classification the
// barrier gRPC service uses, and answers that code's HTTP status; an unmapped code is 500.
func serviceErrorStatus(err error) int {
	var missing ErrMissingRequiredField
	var invalid ErrInvalidRequestBody
	var invalidInit *ErrInitInvalidRequest
	if errors.As(err, &missing) || errors.As(err, &invalid) || errors.As(err, &invalidInit) {
		return http.StatusBadRequest
	}
	var issued *ErrInitAlreadyIssued
	var conflict *ErrInitBarrierConflict
	if errors.As(err, &issued) || errors.As(err, &conflict) {
		return http.StatusConflict
	}
	if mapped, ok := grpcCodeToHTTPStatus[barrier.Code(err)]; ok {
		return mapped
	}
	return http.StatusInternalServerError
}

// decodeInitJSON decodes the request body into out, applying a max-bytes
// cap to defend against accidental large uploads on the bootstrap path.
// Unknown fields are refused so a client never mistakes an ignored field
// for an honoured one. The server closes the request body.
func decodeInitJSON(r *http.Request, max int64, out interface{}) error {
	if r.Body == nil {
		return nil
	}
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
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return ErrInvalidRequestBody{Reason: err.Error()}
	}
	return nil
}
