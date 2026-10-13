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

package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// TPM REST Handler Errors
// =============================================================================

// ErrTPMInvalidQueryParameter is returned when a TPM request's query string
// names a parameter the request message does not have, or carries a value
// that does not parse as that field's type.
type ErrTPMInvalidQueryParameter struct {
	Name   string
	Value  string
	Reason string
}

func (e ErrTPMInvalidQueryParameter) Error() string {
	return fmt.Sprintf("invalid query parameter %s=%q: %s", e.Name, e.Value, e.Reason)
}

// ErrTPMServiceNotAvailable is returned when the physical TPM service is not
// configured or unavailable.
type ErrTPMServiceNotAvailable struct{}

func (e ErrTPMServiceNotAvailable) Error() string {
	return "TPM service not available"
}

// ErrTPMTokenRequired is returned when a TPM request carries no platform
// bearer token.
type ErrTPMTokenRequired struct {
	Scope string
}

func (e ErrTPMTokenRequired) Error() string {
	return "this TPM operation requires a platform bearer token granting " + e.Scope
}

// ErrTPMForbidden is returned when a TPM request's token does not grant the
// scope its route requires.
type ErrTPMForbidden struct {
	Scope  string
	Reason string
}

func (e ErrTPMForbidden) Error() string {
	return "this TPM operation requires " + e.Scope + ": " + e.Reason
}

// ErrTPMOperationFailed is returned when a TPM operation fails.
type ErrTPMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrTPMOperationFailed) Error() string {
	return fmt.Sprintf("TPM operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrTPMOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// TPM Routes
// =============================================================================

// The scopes a platform token needs for each TPM route, the same tiers the
// gRPC TPMService and the QUIC 0x99 category enforce (docs/tpm/api.md §9).
const (
	tpmScopeRead   = "tpm:read"
	tpmScopeWrite  = "tpm:write"
	tpmScopeDelete = "tpm:delete"
)

// TPMHandlers serves the physical TPM over REST. Every route decodes the
// protobuf JSON request the SDK sends, runs the matching TPMService RPC on
// the daemon's TPM service and answers with its protobuf JSON response, so a
// REST call is the one gRPC, QUIC, MCP and Unix serve. Every route requires a
// platform bearer token granting its scope.
type TPMHandlers struct {
	tpm    platformv1.TPMServiceServer
	tokens TokenAuthorizer
	logger *slog.Logger
}

// tpmRoute is one TPM REST route and the scope it requires.
type tpmRoute struct {
	method  string
	path    string
	scope   string
	handler http.HandlerFunc
}

// NewTPMHandlers creates a new TPMHandlers instance.
func NewTPMHandlers(logger *slog.Logger) *TPMHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &TPMHandlers{
		logger: logger,
	}
}

// WithTPMService sets the TPM service every route delegates to. Without one,
// every route answers 503.
func (h *TPMHandlers) WithTPMService(tpm platformv1.TPMServiceServer) *TPMHandlers {
	h.tpm = tpm
	return h
}

// WithTokenAuthorizer sets the platform-token authorizer that gates every
// route. Without one, every route refuses every request.
func (h *TPMHandlers) WithTokenAuthorizer(tokens TokenAuthorizer) *TPMHandlers {
	h.tokens = tokens
	return h
}

// RegisterRoutes registers all physical TPM routes on the provided router,
// each behind the scope it requires.
func (h *TPMHandlers) RegisterRoutes(router *mux.Router) {
	for _, route := range h.routes() {
		router.Handle(route.path, h.requireScope(route.scope, route.handler)).Methods(route.method)
	}
	h.logger.Info("TPM REST routes registered")
}

// routes is the TPM route table: the paths and verbs the SDK's REST
// transports map TPMService onto, each running that RPC under the scope the
// gRPC method catalog gives it. The Go SDK carries a key handle or NVRAM
// index in the body; the JavaScript SDK puts it in the path ({handle},
// {index}), so both forms are mounted. The device-identity routes (IDevID, IAK info
// and delete, activate-credential) are the daemon's own, in
// pkg/api/daemon/rest_idevid.go.
func (h *TPMHandlers) routes() []tpmRoute {
	return []tpmRoute{
		// TPM info and management
		{http.MethodGet, "/api/v1/tpm/info", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Info)},
		{http.MethodPost, "/api/v1/tpm/provision", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.Provision)},
		{http.MethodPost, "/api/v1/tpm/clear", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.Clear)},

		// Endorsement key
		{http.MethodGet, "/api/v1/tpm/ek", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetEK)},
		{http.MethodPost, "/api/v1/tpm/ek", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.CreateEK)},
		{http.MethodDelete, "/api/v1/tpm/ek", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteEK)},
		{http.MethodDelete, "/api/v1/tpm/ek/{handle}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteEK)},
		{http.MethodGet, "/api/v1/tpm/ek/certificate", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetEKCertificate)},
		{http.MethodPost, "/api/v1/tpm/ek/certificate", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.ImportEKCertificate)},

		// Storage root key
		{http.MethodGet, "/api/v1/tpm/srk", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetSRK)},
		{http.MethodPost, "/api/v1/tpm/srk", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.CreateSRK)},
		{http.MethodDelete, "/api/v1/tpm/srk", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteSRK)},
		{http.MethodDelete, "/api/v1/tpm/srk/{handle}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteSRK)},

		// Attestation key
		{http.MethodGet, "/api/v1/tpm/ak", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetAK)},
		{http.MethodPost, "/api/v1/tpm/ak", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.CreateAK)},
		{http.MethodDelete, "/api/v1/tpm/ak", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteAK)},
		{http.MethodDelete, "/api/v1/tpm/ak/{handle}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteAK)},

		// Credential activation (TPM2_MakeCredential)
		{http.MethodPost, "/api/v1/tpm/make-credential", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.MakeCredential)},

		// Quote and attestation
		{http.MethodPost, "/api/v1/tpm/quote", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Quote)},
		{http.MethodPost, "/api/v1/tpm/quote/verify", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.VerifyQuote)},

		// PCRs and the event log. POST /pcrs is the JavaScript SDK's form.
		{http.MethodGet, "/api/v1/tpm/pcrs", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetPCRs)},
		{http.MethodPost, "/api/v1/tpm/pcrs", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetPCRs)},
		{http.MethodGet, "/api/v1/tpm/eventlog", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetEventLog)},

		// NVRAM
		{http.MethodPost, "/api/v1/tpm/nvram", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.DefineNVRAM)},
		{http.MethodGet, "/api/v1/tpm/nvram", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.ReadNVRAM)},
		{http.MethodPut, "/api/v1/tpm/nvram", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.WriteNVRAM)},
		{http.MethodDelete, "/api/v1/tpm/nvram", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.UndefineNVRAM)},
		{http.MethodGet, "/api/v1/tpm/nvram/{index}", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.ReadNVRAM)},
		{http.MethodPut, "/api/v1/tpm/nvram/{index}", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.WriteNVRAM)},
		{http.MethodDelete, "/api/v1/tpm/nvram/{index}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.UndefineNVRAM)},

		// Random, seal and unseal
		{http.MethodPost, "/api/v1/tpm/random", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetRandom)},
		{http.MethodPost, "/api/v1/tpm/seal", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.Seal)},
		{http.MethodPost, "/api/v1/tpm/unseal", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Unseal)},
	}
}

// requireScope serves next only to a request whose platform bearer token
// grants scope. It refuses everything when no authorizer is configured.
func (h *TPMHandlers) requireScope(scope string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code, err := h.authorize(r, scope); err != nil {
			h.writeError(w, code, err)
			return
		}
		next(w, r)
	})
}

// authorize requires a platform bearer token granting scope. It returns the
// HTTP status to refuse the request with.
func (h *TPMHandlers) authorize(r *http.Request, scope string) (int, error) {
	if h.tokens == nil {
		return http.StatusForbidden, ErrTPMForbidden{Scope: scope, Reason: "no platform-token validator is configured"}
	}
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || strings.TrimSpace(token) == "" {
		return http.StatusUnauthorized, ErrTPMTokenRequired{Scope: scope}
	}
	authCtx, err := h.tokens.AuthorizeToken(r.Context(), token, scope, r.Header.Get("DPoP"), r.Method, requestURL(r))
	if err != nil {
		return http.StatusForbidden, ErrTPMForbidden{Scope: scope, Reason: err.Error()}
	}
	if authCtx == nil {
		return http.StatusForbidden, ErrTPMForbidden{Scope: scope, Reason: "the token authorized no context"}
	}
	if err := authCtx.RequireScope(scope); err != nil {
		return http.StatusForbidden, ErrTPMForbidden{Scope: scope, Reason: err.Error()}
	}
	return http.StatusOK, nil
}

// =============================================================================
// TPMService RPC Handlers
// =============================================================================

// tpmRPC serves one TPMService RPC. The request message is read from the
// protobuf JSON body, then from the path variables and the query string; a
// field the message does not have is refused, never dropped. The RPC runs
// with the TLS state of the connection the request arrived on, which a quote
// binds to (#482).
func tpmRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](h *TPMHandlers, rpc func(platformv1.TPMServiceServer, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.tpm == nil {
			h.writeError(w, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})
			return
		}
		req := PReq(new(Req))
		if !h.decodeProto(w, r, req) {
			return
		}
		params := r.URL.Query()
		for name, value := range mux.Vars(r) {
			params.Set(name, value)
		}
		if err := decodeTPMParams(params, req.ProtoReflect()); err != nil {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
		ctx := channelbind.WithConnectionTLS(r.Context(), channelbind.TransportREST, r.TLS)
		resp, err := rpc(h.tpm, ctx, req)
		if err != nil {
			h.writeStatusError(w, err)
			return
		}
		h.writeProto(w, http.StatusOK, resp)
	}
}

// decodeTPMParams sets the request fields that URL parameters name. A
// parameter is a scalar field's proto name or JSON name (num_bytes or
// numBytes); a repeated field takes the parameter once per element.
func decodeTPMParams(params url.Values, msg protoreflect.Message) error {
	fields := msg.Descriptor().Fields()
	for name, values := range params {
		field := fields.ByName(protoreflect.Name(name))
		if field == nil {
			field = fields.ByJSONName(name)
		}
		if field == nil || field.IsMap() {
			return ErrTPMInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: "not a field of " + string(msg.Descriptor().FullName())}
		}
		if !field.IsList() && len(values) > 1 {
			return ErrTPMInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: "given more than once"}
		}
		parse, ok := tpmParamParsers[field.Kind()]
		if !ok {
			return ErrTPMInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: "a " + field.Kind().String() + " field cannot be a URL parameter"}
		}
		for _, raw := range values {
			value, ok := parse(field, raw)
			if !ok {
				return ErrTPMInvalidQueryParameter{Name: name, Value: raw, Reason: "not a valid " + field.Kind().String()}
			}
			if field.IsList() {
				msg.Mutable(field).List().Append(value)
			} else {
				msg.Set(field, value)
			}
		}
	}
	return nil
}

// tpmParamParser parses one URL parameter value as a value of field.
type tpmParamParser func(field protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool)

// tpmParamParsers parses each scalar kind a TPM request field has. A
// uint32 takes any Go literal base, so ?handle=0x81000002 works; an enum
// takes its name or its number.
var tpmParamParsers = map[protoreflect.Kind]tpmParamParser{
	protoreflect.BoolKind:   parseBoolParam,
	protoreflect.StringKind: parseStringParam,
	protoreflect.EnumKind:   parseEnumParam,
	protoreflect.Uint32Kind: parseUint32Param,
}

func parseBoolParam(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool) {
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return protoreflect.Value{}, false
	}
	return protoreflect.ValueOfBool(b), true
}

func parseStringParam(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool) {
	return protoreflect.ValueOfString(raw), true
}

func parseEnumParam(field protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool) {
	values := field.Enum().Values()
	if value := values.ByName(protoreflect.Name(raw)); value != nil {
		return protoreflect.ValueOfEnum(value.Number()), true
	}
	n, err := strconv.ParseInt(raw, 0, 32)
	if err != nil || values.ByNumber(protoreflect.EnumNumber(n)) == nil {
		return protoreflect.Value{}, false
	}
	return protoreflect.ValueOfEnum(protoreflect.EnumNumber(n)), true
}

func parseUint32Param(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool) {
	n, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		return protoreflect.Value{}, false
	}
	return protoreflect.ValueOfUint32(uint32(n)), true
}

// =============================================================================
// Helper Methods
// =============================================================================

// writeJSON writes a JSON response with the given status code.
func (h *TPMHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response with the given status code.
func (h *TPMHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// tpmMarshalOptions encodes the TPM service's protobuf responses the way the
// web service's /api/v1/tpm routes do, so the SDK decodes either listener.
var tpmMarshalOptions = protojson.MarshalOptions{
	EmitUnpopulated: true,
}

// tpmUnmarshalOptions decodes protobuf TPM request bodies. An unknown field
// is an error: a misspelled field must never become a silent default.
var tpmUnmarshalOptions = protojson.UnmarshalOptions{
	DiscardUnknown: false,
}

// decodeProto reads a protojson request body into msg. An empty body leaves
// msg at its zero value. It writes a 400 and reports false when the body
// cannot be read or decoded.
func (h *TPMHandlers) decodeProto(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return false
	}
	if len(data) == 0 {
		return true
	}
	if err := tpmUnmarshalOptions.Unmarshal(data, msg); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return false
	}
	return true
}

// writeProto writes msg as protojson with the given HTTP status.
func (h *TPMHandlers) writeProto(w http.ResponseWriter, statusCode int, msg proto.Message) {
	payload, err := tpmMarshalOptions.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to encode TPM response", "error", err)
		h.writeError(w, http.StatusInternalServerError, ErrTPMOperationFailed{Operation: "encode_response", Cause: err})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(payload); err != nil {
		h.logger.Error("Failed to write TPM response", "error", err)
	}
}

// writeStatusError answers with the HTTP equivalent of the TPM service's gRPC
// status error.
func (h *TPMHandlers) writeStatusError(w http.ResponseWriter, err error) {
	code, ok := protorestHTTPStatus[status.Code(err)]
	if !ok {
		code = http.StatusInternalServerError
	}
	h.logger.Error("TPM request failed", "error", err, "http_status", code)
	h.writeError(w, code, err)
}
