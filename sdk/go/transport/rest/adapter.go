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

// Package rest provides the REST transport adapter for the platform SDK.
// It wraps HTTP/HTTPS communication with the REST API and provides a
// gRPC-compatible interface for service clients.
package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolREST, Connect)
}

// Adapter implements the transport.Adapter interface for REST over HTTP/HTTPS.
type Adapter struct {
	httpClient *http.Client
	baseURL    string
	connected  atomic.Bool
	closed     atomic.Bool
	tlsConfig  *tls.Config
	token      atomic.Value // stores auth token as string
}

// Connect establishes a REST connection to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	if opts.RESTAddr == "" {
		return nil, platform.ErrEmptyAddress
	}

	// The daemon's REST server only listens on TLS (#32), so a plaintext
	// address can never reach it and would expose the bearer token.
	if strings.HasPrefix(opts.RESTAddr, "http://") {
		return nil, platform.ErrInsecureTransport{
			Protocol: platform.ProtocolREST,
			Target:   opts.RESTAddr,
			Reason:   "the REST server only offers TLS; use https://",
		}
	}

	timeout := opts.GetTimeout()

	baseURL := opts.RESTAddr
	if !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	// The Go HTTP transport defaults ServerName from the Host header,
	// which is the dialed address — TLSServerName lets a CLI talk to
	// the daemon by IP while still verifying the cert's CN/SAN.
	tlsConfig := opts.ClientTLSConfig()

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   timeout,
	}

	a := &Adapter{
		httpClient: httpClient,
		baseURL:    baseURL,
		tlsConfig:  tlsConfig,
	}
	a.connected.Store(true)
	if opts.BearerToken != "" {
		a.SetToken(opts.BearerToken)
	}

	// Verify the daemon answers before handing the adapter out, so a dead or
	// untrusted endpoint fails here and auto-detect moves on.
	start := time.Now()
	if err := a.probeHealth(ctx, timeout); err != nil {
		if transport.IsTimeout(err) {
			err = platform.ErrTimeout{Operation: "REST health probe", Elapsed: time.Since(start), Err: err}
		}
		closeErr := a.Close()
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolREST,
			Target:   opts.RESTAddr,
			Err:      errors.Join(err, closeErr),
		}
	}

	return a, nil
}

// probeHealth issues GET /health and succeeds only on a 2xx answer. The
// daemon serves /health unauthenticated on every REST listener.
func (a *Adapter) probeHealth(ctx context.Context, timeout time.Duration) error {
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, a.baseURL+"/health", nil)
	if err != nil {
		return err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ErrHTTPStatus{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

// Connection returns a gRPC-compatible client connection interface.
// This wraps the REST adapter to provide a unified interface for service clients.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return &restClientConn{adapter: a}
}

// Close closes the REST client connection.
func (a *Adapter) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	a.connected.Store(false)

	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}

	return nil
}

// IsConnected returns true if the adapter is connected.
func (a *Adapter) IsConnected() bool {
	return a.connected.Load() && !a.closed.Load()
}

// Target returns the REST API base URL.
func (a *Adapter) Target() string {
	return a.baseURL
}

// SetToken sets the authentication token for requests.
func (a *Adapter) SetToken(token string) {
	a.token.Store(token)
}

// GetToken returns the current authentication token.
func (a *Adapter) GetToken() string {
	if v := a.token.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// DoRequest performs an HTTP request to the REST API.
func (a *Adapter) DoRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	if a.closed.Load() {
		return ErrClientClosed{}
	}

	url := a.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return ErrMarshalFailed{Err: err}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return ErrRequestFailed{Method: method, Path: path, Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if token := a.GetToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return ErrRequestFailed{Method: method, Path: path, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRequestFailed{Method: method, Path: path, Err: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrHTTPStatus{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(respBody),
		}
	}

	if result != nil && len(respBody) > 0 {
		// All /api/v1/* responses from the platformd webserver are
		// wrapped in the standard envelope:
		//
		//   {"code":200,"error":"","success":true,"payload":<actual>}
		//
		// (see sdk/go/wire/restwire.WebServiceResponse). The
		// SDK gRPC clients want the inner `<actual>` decoded directly
		// into their proto / domain types — so we attempt envelope
		// unwrap first, then fall back to direct unmarshal for any
		// endpoint that doesn't use the wrapper. A response that
		// doesn't have a `payload` field will land as `null` in the
		// envelope's Payload; we detect that and fall back.
		var envelope struct {
			Code    int             `json:"code"`
			Error   string          `json:"error"`
			Success bool            `json:"success"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(respBody, &envelope); err == nil &&
			(envelope.Code != 0 || envelope.Success || envelope.Error != "") &&
			len(envelope.Payload) > 0 && string(envelope.Payload) != "null" {
			// Server-level error: surface the envelope's error string
			// so the caller sees a real diagnosis rather than an
			// unmarshal-into-zero-value.
			if !envelope.Success && envelope.Error != "" {
				return ErrHTTPStatus{
					StatusCode: envelope.Code,
					Status:     envelope.Error,
					Body:       string(respBody),
				}
			}
			if err := decodeJSONResult(envelope.Payload, result); err != nil {
				return ErrUnmarshalFailed{Err: err}
			}
			return nil
		}
		// Non-enveloped response (e.g. /endpoints, /healthz) — decode
		// the body directly into the caller's result struct.
		if err := decodeJSONResult(respBody, result); err != nil {
			return ErrUnmarshalFailed{Err: err}
		}
	}

	return nil
}

// decodeJSONResult unmarshals JSON into result. If result is a proto
// message (e.g. *platformv1.TPMInfoResponse), it uses protojson so
// that enum string forms ("TPM_VERSION_2_0"), camelCase field names
// ("pcrBanks"), and other proto-json conventions match what the
// server emits via protorest.WriteSuccess. For non-proto types
// (domain DTOs, raw maps), regular encoding/json is used.
func decodeJSONResult(data []byte, result interface{}) error {
	if msg, ok := result.(proto.Message); ok {
		opts := protojson.UnmarshalOptions{
			DiscardUnknown: true,
		}
		return opts.Unmarshal(data, msg)
	}
	return json.Unmarshal(data, result)
}

// restClientConn implements grpc.ClientConnInterface for REST transport.
// This allows using REST as a drop-in replacement for gRPC connections.
type restClientConn struct {
	adapter *Adapter
}

// Invoke performs a unary RPC call by translating to REST HTTP requests.
//
// Routes that include {placeholder} segments (BMC, per-tenant barrier)
// have their path params substituted from the request message and
// stripped from the request body so the server never sees the same
// field in both URL and body. Flat routes are passed through untouched.
func (c *restClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	if c.adapter.closed.Load() {
		return status.Error(codes.Unavailable, "connection closed")
	}

	// Methods whose server-side JSON shape does not match the pb reply
	// (domain JSON, flattened oneofs) capture the raw payload and run a
	// custom decoder after the request completes. Everything else decodes
	// straight into the caller's reply.
	decode, hasDecoder := restResponseDecoders[method]
	result := reply
	var raw json.RawMessage
	if hasDecoder {
		result = &raw
	}

	// Templated routes: substitute path params and strip them from the
	// body. The body is sent as a clone of args so the caller's message
	// is not mutated.
	if entry, ok := templatedRouteTable[method]; ok {
		path, body, err := buildTemplatedRequest(entry, args)
		if err != nil {
			return err
		}
		if reqErr := c.adapter.DoRequest(ctx, entry.method, path, body, result); reqErr != nil {
			return translateErrorToGRPC(reqErr)
		}
		return c.finishInvoke(hasDecoder, decode, raw, reply)
	}

	// Flat routes: today's behavior — derive path from the static map
	// (or fall back to the gRPC method-name heuristic).
	path, httpMethod := mapGRPCMethodToREST(method)
	if err := c.adapter.DoRequest(ctx, httpMethod, path, args, result); err != nil {
		return translateErrorToGRPC(err)
	}
	return c.finishInvoke(hasDecoder, decode, raw, reply)
}

// finishInvoke applies the method's custom response decoder, if any, to the
// captured raw payload. Nil replies (fire-and-forget callers) skip decoding.
func (c *restClientConn) finishInvoke(hasDecoder bool, decode restResponseDecoder, raw json.RawMessage, reply interface{}) error {
	if !hasDecoder || reply == nil {
		return nil
	}
	if err := decode(raw, reply); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	return nil
}

// buildTemplatedRequest substitutes path params into a templated route,
// appends any query params, and returns the URL path plus the body to
// send. body is a clone of args with every templated field cleared (so
// the server doesn't see them duplicated). args must be a proto.Message.
func buildTemplatedRequest(route templatedRoute, args interface{}) (path string, body interface{}, err error) {
	msg, ok := args.(proto.Message)
	if !ok {
		return "", nil, status.Errorf(codes.InvalidArgument,
			"templated REST route requires a proto.Message request, got %T", args)
	}

	rm := msg.ProtoReflect()
	resolved := route.path

	for _, p := range route.pathParams {
		fd := rm.Descriptor().Fields().ByName(p.field)
		if fd == nil {
			return "", nil, status.Errorf(codes.Internal,
				"REST adapter: proto field %q missing on %s", p.field, rm.Descriptor().FullName())
		}
		raw, encoded, ok := encodePathField(rm.Get(fd), fd)
		if !ok {
			return "", nil, status.Errorf(codes.InvalidArgument,
				"%s requires non-zero %s for templated REST route", rm.Descriptor().FullName(), p.field)
		}
		_ = raw
		resolved = strings.ReplaceAll(resolved, p.placeholder, encoded)
	}

	if strings.Contains(resolved, "{") {
		return "", nil, status.Errorf(codes.Internal,
			"REST adapter: unresolved placeholder in %q after substitution", resolved)
	}

	// Optional query parameters: zero-valued fields are omitted so
	// "absent" and "no filter" coincide with the server defaults.
	values := url.Values{}
	for _, qp := range route.queryParams {
		encoded, ok, qErr := encodeQueryField(rm, qp.field)
		if qErr != nil {
			return "", nil, qErr
		}
		if ok {
			values.Set(qp.name, encoded)
		}
	}

	// Clone and clear the templated fields so the body matches what the
	// server expects. proto.Clone is shallow-correct for the fields we
	// touch (we only Clear scalar / nested-scalar fields).
	clone := proto.Clone(msg)
	cloneRefl := clone.ProtoReflect()
	for _, p := range route.pathParams {
		fd := cloneRefl.Descriptor().Fields().ByName(p.field)
		if fd != nil {
			cloneRefl.Clear(fd)
		}
	}
	for _, qp := range route.queryParams {
		clearProtoFieldPath(cloneRefl, qp.field)
	}

	if encodedQuery := values.Encode(); encodedQuery != "" {
		resolved += "?" + encodedQuery
	}
	return resolved, clone, nil
}

// encodeQueryField resolves a dot-separated proto field path on a
// request message and renders it as a query parameter value. Returns
// ok=false when the field (or any parent message) is zero-valued so the
// parameter is omitted. Enum fields render as the proto enum value name
// (the servers accept both the full enum name and the short form).
func encodeQueryField(rm protoreflect.Message, fieldPath string) (string, bool, error) {
	segments := strings.Split(fieldPath, ".")
	current := rm
	for _, segment := range segments[:len(segments)-1] {
		fd := current.Descriptor().Fields().ByName(protoreflect.Name(segment))
		if fd == nil || fd.Kind() != protoreflect.MessageKind {
			return "", false, status.Errorf(codes.Internal,
				"REST adapter: query field path %q invalid on %s", fieldPath, rm.Descriptor().FullName())
		}
		if !current.Has(fd) {
			return "", false, nil
		}
		current = current.Get(fd).Message()
	}

	leaf := segments[len(segments)-1]
	fd := current.Descriptor().Fields().ByName(protoreflect.Name(leaf))
	if fd == nil {
		return "", false, status.Errorf(codes.Internal,
			"REST adapter: query field %q missing on %s", fieldPath, current.Descriptor().FullName())
	}

	v := current.Get(fd)
	switch fd.Kind() {
	case protoreflect.BoolKind:
		if !v.Bool() {
			return "", false, nil
		}
		return "true", true, nil
	case protoreflect.EnumKind:
		n := v.Enum()
		if n == 0 {
			return "", false, nil
		}
		if desc := fd.Enum().Values().ByNumber(n); desc != nil {
			return string(desc.Name()), true, nil
		}
		return strconv.FormatInt(int64(n), 10), true, nil
	default:
		// Use the RAW value: url.Values.Encode() applies query escaping,
		// so pre-escaped path encoding would double-escape.
		raw, _, ok := encodePathField(v, fd)
		if !ok {
			return "", false, nil
		}
		return raw, true, nil
	}
}

// clearProtoFieldPath clears a dot-separated proto field path on a
// (mutable) message, stopping silently when any segment is absent.
func clearProtoFieldPath(rm protoreflect.Message, fieldPath string) {
	segments := strings.Split(fieldPath, ".")
	current := rm
	for _, segment := range segments[:len(segments)-1] {
		fd := current.Descriptor().Fields().ByName(protoreflect.Name(segment))
		if fd == nil || fd.Kind() != protoreflect.MessageKind || !current.Has(fd) {
			return
		}
		current = current.Mutable(fd).Message()
	}
	if fd := current.Descriptor().Fields().ByName(protoreflect.Name(segments[len(segments)-1])); fd != nil {
		current.Clear(fd)
	}
}

// encodePathField extracts a path-parameter value from a proto field.
// Returns (rawString, urlEscapedString, ok). ok is false when the field
// is missing or has its zero value, so callers can reject zero IDs as
// InvalidArgument.
func encodePathField(v protoreflect.Value, fd protoreflect.FieldDescriptor) (string, string, bool) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		s := v.String()
		if s == "" {
			return "", "", false
		}
		return s, url.PathEscape(s), true
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		n := v.Uint()
		if n == 0 {
			return "", "", false
		}
		s := strconv.FormatUint(n, 10)
		return s, s, true
	case protoreflect.Int64Kind, protoreflect.Sfixed64Kind, protoreflect.Sint64Kind:
		n := v.Int()
		if n == 0 {
			return "", "", false
		}
		s := strconv.FormatInt(n, 10)
		return s, s, true
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		n := v.Uint()
		if n == 0 {
			return "", "", false
		}
		s := strconv.FormatUint(n, 10)
		return s, s, true
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		n := v.Int()
		if n == 0 {
			return "", "", false
		}
		s := strconv.FormatInt(n, 10)
		return s, s, true
	default:
		// Fallback: render via the protoreflect String form. Empty is treated
		// as zero-value rejection.
		s := fmt.Sprintf("%v", v.Interface())
		if s == "" {
			return "", "", false
		}
		return s, url.PathEscape(s), true
	}
}

// NewStream creates a new stream (not fully supported for REST).
func (c *restClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streaming not supported over REST transport")
}

// pathParam describes a single placeholder substitution in a templated
// REST route. The placeholder is a literal segment in the route's path
// template (e.g. "{profileID}") and field is the proto field name in
// the request message (snake_case, as protoreflect surfaces it).
type pathParam struct {
	placeholder string
	field       protoreflect.Name
}

// queryParam describes a single query-string parameter derived from a
// request field. name is the URL query parameter; field is a
// dot-separated proto field path on the request message (snake_case, as
// protoreflect surfaces it — e.g. "pagination.page"). Zero-valued
// fields are omitted from the URL so "absent" and "no filter" coincide.
type queryParam struct {
	name  string
	field string
}

// templatedRoute describes a REST route whose URL is derived from the
// request message: {placeholder} path segments are substituted from
// pathParams and queryParams are appended as a query string. All
// templated fields are cleared from the request body clone so the
// server never sees the same value twice.
type templatedRoute struct {
	path        string
	method      string
	pathParams  []pathParam
	queryParams []queryParam
}

// templatedRouteTable maps gRPC methods to REST routes whose URLs
// contain {placeholder} segments populated from request fields. Lookup
// in this table happens before the flat grpcMethodToRESTMap, so an
// entry here takes precedence.
//
// All entries here MUST satisfy the invariant: every {placeholder} in
// path is satisfied by exactly one pathParam, and every pathParam
// references a real proto field on the corresponding request message
// type. The substitute helper returns codes.InvalidArgument if a path
// param resolves to its zero value (e.g. profile_id == 0). queryParams
// are optional refinements: zero values are simply omitted.
//
// BMC routes match the server registrations at
// pkg/api/daemon/rest_service.go::SetBMCHandler; per-tenant barrier
// routes match pkg/webservice/v1/rest/tenant/router.go; EAB routes
// match pkg/webservice/v1/rest/eab/router.go.
var templatedRouteTable = map[string]templatedRoute{
	// Gateway perf verification — proto: pkg/api/grpc/proto/gateway.proto.
	// Server registrations live in
	// pkg/api/rest/gateway_perf_handlers.go::registerPerfRoutes. bridge /
	// zone travel as query parameters; zero values are omitted so the
	// server applies its defaults (default bridge / all zones).
	// TPM Service — proto: pkg/api/grpc/proto/tpm.proto
	// GetSRK dispatches on the requested persistent handle: absent or 0
	// is the SSRK, 0x81000002 the PlatformSRK, anything else 404. The
	// handle must travel as a query parameter — this is a GET, and the
	// server never reads a GET body, so sending it there returned the
	// SSRK for every request (#475).
	"/platform.v1.TPMService/GetSRK": {
		path:        "/api/v1/tpm/srk",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "handle", field: "handle"}},
	},

	"/platform.v1.GatewayService/GetPerfDatapath": {
		path:        "/api/v1/sdn/gateway/perf/datapath",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "bridge", field: "bridge"}},
	},
	"/platform.v1.GatewayService/GetPerfConntrack": {
		path:        "/api/v1/sdn/gateway/perf/conntrack",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "zone", field: "zone"}},
	},

	// BMC Service — proto: pkg/api/grpc/proto/bmc.proto
	// Server registrations live in pkg/api/daemon/rest_service.go::SetBMCHandler.
	// PowerOn/Off/Reset/Cycle all hit the same POST endpoint; the server's
	// PowerAction handler reads the action from the request body.
	"/platform.v1.BMCService/PowerOn":            bmcRoute("/api/v1/bmc/{profileID}/power", http.MethodPost),
	"/platform.v1.BMCService/PowerOff":           bmcRoute("/api/v1/bmc/{profileID}/power", http.MethodPost),
	"/platform.v1.BMCService/PowerReset":         bmcRoute("/api/v1/bmc/{profileID}/power", http.MethodPost),
	"/platform.v1.BMCService/PowerCycle":         bmcRoute("/api/v1/bmc/{profileID}/power", http.MethodPost),
	"/platform.v1.BMCService/PowerStatus":        bmcRoute("/api/v1/bmc/{profileID}/power", http.MethodGet),
	"/platform.v1.BMCService/SetBootDevice":      bmcRoute("/api/v1/bmc/{profileID}/boot-device", http.MethodPost),
	"/platform.v1.BMCService/GetBootDevice":      bmcRoute("/api/v1/bmc/{profileID}/boot-device", http.MethodGet),
	"/platform.v1.BMCService/MountISO":           bmcRoute("/api/v1/bmc/{profileID}/virtual-media", http.MethodPost),
	"/platform.v1.BMCService/UnmountISO":         bmcRoute("/api/v1/bmc/{profileID}/virtual-media", http.MethodDelete),
	"/platform.v1.BMCService/VirtualMediaStatus": bmcRoute("/api/v1/bmc/{profileID}/virtual-media", http.MethodGet),
	"/platform.v1.BMCService/GetSensors":         bmcRoute("/api/v1/bmc/{profileID}/sensors", http.MethodGet),
	"/platform.v1.BMCService/GetSystemInfo":      bmcRoute("/api/v1/bmc/{profileID}/system-info", http.MethodGet),
	"/platform.v1.BMCService/Provision":          bmcRoute("/api/v1/bmc/{profileID}/provision", http.MethodPost),
	"/platform.v1.BMCService/ProvisionStatus":    bmcRoute("/api/v1/bmc/{profileID}/provision", http.MethodGet),

	// Per-tenant barrier RPCs on PlatformTenantService — proto:
	// pkg/api/grpc/proto/tenant.proto. Server registrations live in
	// pkg/webservice/v1/rest/tenant/router.go.
	"/platform.v1.TenantService/InitTenantBarrier":      tenantBarrierRoute("/api/v1/tenants/{id}/barrier/init", http.MethodPost),
	"/platform.v1.TenantService/UnsealTenantBarrier":    tenantBarrierRoute("/api/v1/tenants/{id}/barrier/unseal", http.MethodPost),
	"/platform.v1.TenantService/SealTenantBarrier":      tenantBarrierRoute("/api/v1/tenants/{id}/barrier/seal", http.MethodPost),
	"/platform.v1.TenantService/GetTenantBarrierStatus": tenantBarrierRoute("/api/v1/tenants/{id}/barrier", http.MethodGet),

	// Config Delivery (provisioning) session RPCs — proto:
	// pkg/api/grpc/proto/configdelivery.proto. Server registrations live in
	// pkg/api/daemon/rest_service.go::SetConfigDeliveryHandler. The
	// {sessionID} path segment is populated from the request's session_id
	// field; FulfillSession keeps profile_id in the POST body (the server
	// reads sessionID from the URL and the profile from the body).
	"/platform.v1.ConfigDeliveryService/GetSession":     provisioningSessionRoute("/api/v1/provisioning/sessions/{sessionID}", http.MethodGet),
	"/platform.v1.ConfigDeliveryService/PollSession":    provisioningSessionRoute("/api/v1/provisioning/sessions/{sessionID}/poll", http.MethodGet),
	"/platform.v1.ConfigDeliveryService/FulfillSession": provisioningSessionRoute("/api/v1/provisioning/sessions/{sessionID}/fulfill", http.MethodPost),

	// EAB Service — proto: pkg/api/grpc/proto/eab.proto. Server
	// registrations live in pkg/webservice/v1/rest/eab/router.go. The
	// {id}/{key} path segments come from credential_id / key_id; list
	// filters and the qrcode size / enrollment-url path travel as query
	// parameters so GET requests carry no meaningful body.
	// Proxy Service — proto: pkg/api/grpc/proto/proxy.proto. Server
	// registrations live in pkg/api/rest/proxy_handlers.go (wired by
	// pkg/api/daemon/proxy_rest.go::SetProxyService). The {id} path
	// segment comes from the request's id field; UpdateRoute/UpdatePool
	// carry the definition in the PUT body while the server takes the ID
	// from the URL.
	"/platform.v1.ProxyService/GetRoute":    proxyResourceRoute("/api/v1/proxy/routes/{id}", http.MethodGet),
	"/platform.v1.ProxyService/DeleteRoute": proxyResourceRoute("/api/v1/proxy/routes/{id}", http.MethodDelete),
	"/platform.v1.ProxyService/UpdateRoute": proxyResourceRoute("/api/v1/proxy/routes/{id}", http.MethodPut),
	"/platform.v1.ProxyService/GetPool":     proxyResourceRoute("/api/v1/proxy/pools/{id}", http.MethodGet),
	"/platform.v1.ProxyService/DeletePool":  proxyResourceRoute("/api/v1/proxy/pools/{id}", http.MethodDelete),
	"/platform.v1.ProxyService/UpdatePool":  proxyResourceRoute("/api/v1/proxy/pools/{id}", http.MethodPut),

	"/platform.v1.EABService/GetCredential":       eabCredentialRoute("/api/v1/eab/credentials/{id}", http.MethodGet),
	"/platform.v1.EABService/DeleteCredential":    eabCredentialRoute("/api/v1/eab/credentials/{id}", http.MethodDelete),
	"/platform.v1.EABService/RevokeCredential":    eabCredentialRoute("/api/v1/eab/credentials/{id}/revoke", http.MethodPost),
	"/platform.v1.EABService/MarkCredentialUsed":  eabCredentialRoute("/api/v1/eab/credentials/{id}/used", http.MethodPost),
	"/platform.v1.EABService/GetCredentialQRCode": eabCredentialRoute("/api/v1/eab/credentials/{id}/qrcode", http.MethodGet, queryParam{name: "size", field: "size"}),
	"/platform.v1.EABService/GetEnrollmentURL":    eabCredentialRoute("/api/v1/eab/credentials/{id}/url", http.MethodGet, queryParam{name: "path", field: "path"}),
	"/platform.v1.EABService/GetCredentialByKeyID": {
		path:       "/api/v1/eab/credentials/key/{key}",
		method:     http.MethodGet,
		pathParams: []pathParam{{placeholder: "{key}", field: "key_id"}},
	},
	"/platform.v1.EABService/ListCredentials": {
		path:   "/api/v1/eab/credentials",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "tenant_id", field: "tenant_id"},
			{name: "profile_id", field: "profile_id"},
			{name: "active_only", field: "active_only"},
			{name: "status", field: "status_filter"},
			{name: "page", field: "pagination.page"},
			{name: "page_size", field: "pagination.page_size"},
		},
	},

	// Singular accessors whose identifier belongs in the path (#379). Each of
	// these claimed its resource's collection path in the flat table, so the
	// call returned the whole collection instead of the requested object. The
	// server route each one now targets is listed beside it; all ten are in
	// pkg/webservice/v1/testdata/routes.golden.
	//
	// Two singular accessors are NOT here, because the server serves no route
	// for them at all: DNSService/GetRecord (records live only under
	// /api/v1/dns/zones/{zone}/records, and platform_dns.proto has no GetRecord
	// rpc) and PlatformIAMService/GetPermission (the IAM router registers
	// /policies, never /permissions, and iam.proto has only CheckPermission).
	// Inventing a path for either would replace a wrong answer with a 404 that
	// reads as fixed, so they stay in the flat table and are recorded as
	// exemptions in
	// TestRouteClaims_NoSingularAccessorSharesACollectionPathWithItsList.
	//
	// The four IAM getters below ARE here even though
	// pkg/webservice/v1/testdata/routes.golden contains no /api/v1/iam route.
	// The golden is a FIXTURE-built table: Router.iamRoutes() returns early
	// when HandlerRegistry.IAMClients() yields a nil client, which the test
	// registry does. The routes themselves are registered unconditionally by
	// pkg/webservice/v1/rest/iam/router.go and are NORMATIVE in
	// docs/iam/api.md §3-§5. A fixture that builds no route is not a server
	// that serves none.

	// GET /api/v1/ca/certificates/{serial}
	"/platform.v1.CAService/GetCertificate": itemRoute("/api/v1/ca/certificates/{serial}", http.MethodGet, "{serial}", "serial"),

	// GET /api/v1/compute/containers/{id}
	"/platform.v1.ComputeService/GetContainer": itemRoute("/api/v1/compute/containers/{id}", http.MethodGet, "{id}", "id"),

	// GET /api/v1/devices/{id:[0-9]+} -- uint64, rendered decimal.
	//
	// The three routes whose server template carries a :[0-9]+ constraint keep
	// that constraint in the client template, and use it as the placeholder
	// literal, so the claim states exactly the route it claims. The adapter
	// treats a placeholder as an opaque literal for ReplaceAll, so the pattern
	// costs nothing at substitution time; what it buys is that
	// pkg/webservice/v1's resolution walk builds a concrete path the server
	// route actually accepts. Written as a bare {id}, the walk substitutes "x"
	// and reports the claim as unroutable -- correctly, since a client sending
	// a non-numeric id would 404.
	"/platform.v1.DeviceService/GetDevice": itemRoute("/api/v1/devices/{id:[0-9]+}", http.MethodGet, "{id:[0-9]+}", "id"),

	// POST /api/v1/devices/{id:[0-9]+}/attest-cert/record -- the operator
	// verb that records a device's attestation certificate without
	// re-enrolling it (#473). Server registration:
	// pkg/webservice/v1/router/device.go::RegisterRoutes (admin gate). The
	// device_id request field fills the path; the remaining body is
	// {"reissue": bool}.
	"/platform.v1.DeviceService/RecordAttestationCertificate": itemRoute("/api/v1/devices/{id:[0-9]+}/attest-cert/record", http.MethodPost, "{id:[0-9]+}", "device_id"),

	// GET /api/v1/device/profiles/{id:[0-9]+} -- note the singular "device"
	// prefix: the router serves BOTH /api/v1/device/profiles and
	// /api/v1/devices/profiles, and this claim targets the former.
	"/platform.v1.DeviceService/GetProfile": itemRoute("/api/v1/device/profiles/{id:[0-9]+}", http.MethodGet, "{id:[0-9]+}", "id"),

	// GET /api/v1/invitations/{id:[0-9]+} -- proto field is invitation_id.
	"/platform.v1.InvitationService/GetInvitation": itemRoute("/api/v1/invitations/{id:[0-9]+}", http.MethodGet, "{id:[0-9]+}", "invitation_id"),

	// GET /api/v1/kms/keys/{name} -- the server names the segment {name}; the
	// proto field is key_id. The two names describe the same value.
	"/platform.v1.KeyManagementService/GetKey": itemRoute("/api/v1/kms/keys/{name}", http.MethodGet, "{name}", "key_id"),

	// GET /api/v1/overlay/vteps/{nodeId}
	"/platform.v1.OverlayService/GetVTEP": itemRoute("/api/v1/overlay/vteps/{nodeId}", http.MethodGet, "{nodeId}", "node_id"),

	// GET /api/v1/pxe/devices/{id} -- request message is GetPXEDeviceRequest.
	"/platform.v1.PXEService/GetDevice": itemRoute("/api/v1/pxe/devices/{id}", http.MethodGet, "{id}", "device_id"),

	// GET /api/v1/sdn/policies/{id}
	"/platform.v1.SDNService/GetPolicy": itemRoute("/api/v1/sdn/policies/{id}", http.MethodGet, "{id}", "policy_id"),

	// GET /api/v1/tenants/{id}
	"/platform.v1.TenantService/GetTenant": itemRoute("/api/v1/tenants/{id}", http.MethodGet, "{id}", "tenant_id"),

	// GET /api/v1/iam/users/{id} -- pkg/webservice/v1/rest/iam/router.go:127.
	//
	// These four take the UNSCOPED form, which is the tree the flat claim
	// already named; the id segment is the only thing added. The router also
	// serves a tenant-scoped twin (/api/v1/iam/tenants/{tenant}/users/{id}),
	// and GetIAMUserRequest carries tenant_id alongside user_id, so an SDK
	// caller who sets tenant_id still gets whatever tenant the unscoped
	// handler derives from context or the token. That ambiguity is
	// docs/iam/api.md §2's, it predates this change, and choosing the scoped
	// form instead would be a behaviour decision rather than a repair -- so it
	// is raised on #379, not settled here.
	"/platform.v1.PlatformIAMService/GetUser": itemRoute("/api/v1/iam/users/{id}", http.MethodGet, "{id}", "user_id"),

	// GET /api/v1/iam/roles/{id} -- router.go:145.
	"/platform.v1.PlatformIAMService/GetRole": itemRoute("/api/v1/iam/roles/{id}", http.MethodGet, "{id}", "role_id"),

	// GET /api/v1/iam/groups/{id} -- router.go:136.
	"/platform.v1.PlatformIAMService/GetGroup": itemRoute("/api/v1/iam/groups/{id}", http.MethodGet, "{id}", "group_id"),

	// GET /api/v1/iam/tenants/{tenant} -- router.go:208. The server names this
	// segment {tenant}, not {id}, and the request has only tenant_id.
	"/platform.v1.PlatformIAMService/GetTenant": itemRoute("/api/v1/iam/tenants/{tenant}", http.MethodGet, "{tenant}", "tenant_id"),

	// DELETE /api/v1/iam/groups/{id}/members/{user} -- rest/iam/router.go:137.
	// The flat row sent DELETE /api/v1/iam/groups/members, and the server
	// routed that to DELETE /groups/{id} with id="members": a DeleteGroup on
	// whatever group carries that name, not a membership removal (#415).
	// RemoveGroupMemberRequest carries group_id and user_id; both travel in
	// the path.
	"/platform.v1.PlatformIAMService/RemoveGroupMember": nestedItemRoute("/api/v1/iam/groups/{id}/members/{user}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "group_id"}, pathParam{placeholder: "{user}", field: "user_id"}),

	// The seven item operations #416 repairs (#379's shape on the mutating
	// verbs, found by #400's fixture). Each sent a collection path the server
	// does not serve for that verb; the server's routes are the item paths
	// below (pkg/webservice/v1/rest/iam/router.go, flat tree), and the
	// identifiers travel in the path, never the body.
	"/platform.v1.PlatformIAMService/DeleteUser":   itemRoute("/api/v1/iam/users/{id}", http.MethodDelete, "{id}", "user_id"),
	"/platform.v1.PlatformIAMService/DeleteRole":   itemRoute("/api/v1/iam/roles/{id}", http.MethodDelete, "{id}", "role_id"),
	"/platform.v1.PlatformIAMService/DeleteGroup":  itemRoute("/api/v1/iam/groups/{id}", http.MethodDelete, "{id}", "group_id"),
	"/platform.v1.PlatformIAMService/DeleteTenant": itemRoute("/api/v1/iam/tenants/{tenant}", http.MethodDelete, "{tenant}", "tenant_id"),
	"/platform.v1.PlatformIAMService/AssignRole": nestedItemRoute("/api/v1/iam/users/{id}/roles/{role}", http.MethodPost,
		pathParam{placeholder: "{id}", field: "user_id"}, pathParam{placeholder: "{role}", field: "role_id"}),
	// RevokeRole changes verb as well as path: the server revokes with DELETE.
	"/platform.v1.PlatformIAMService/RevokeRole": nestedItemRoute("/api/v1/iam/users/{id}/roles/{role}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "user_id"}, pathParam{placeholder: "{role}", field: "role_id"}),
	"/platform.v1.PlatformIAMService/AddGroupMember": nestedItemRoute("/api/v1/iam/groups/{id}/members/{user}", http.MethodPost,
		pathParam{placeholder: "{id}", field: "group_id"}, pathParam{placeholder: "{user}", field: "user_id"}),
}

// itemRoute constructs a templated route for a singular accessor: the
// identifier travels as a path segment rather than in the request body, so
// the client asks the server for ONE object.
//
// Every entry built here previously lived in the flat table pointed at its
// resource's COLLECTION path -- the same path and verb as its List sibling.
// A flat path is sent verbatim, so those calls issued the collection request
// and returned the collection with a 200, forever (#379). placeholder is the
// literal {segment} in path; field is the snake_case proto field on the
// request message that fills it.
func itemRoute(path, method, placeholder string, field protoreflect.Name) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{{placeholder: placeholder, field: field}},
	}
}

// nestedItemRoute is itemRoute for a route that names TWO identifiers -- a
// parent and a child, e.g. /users/{id}/roles/{role} -- each filled from its
// own request field. Both must be non-zero; a placeholder left unfilled is an
// error, never a shorter path (#415: the collection-path form of
// RemoveGroupMember routed to DeleteGroup with id="members").
func nestedItemRoute(path, method string, parent, child pathParam) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{parent, child},
	}
}

// bmcRoute constructs a templated route that pulls profile_id from a
// BMC request message and substitutes {profileID} in the URL. Server
// path regex is [0-9]+ so we always serialize uint64 as decimal.
func bmcRoute(path, method string) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{{placeholder: "{profileID}", field: "profile_id"}},
	}
}

// tenantBarrierRoute constructs a templated route that pulls tenant_id
// from a per-tenant barrier request message and substitutes {id}.
func tenantBarrierRoute(path, method string) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{{placeholder: "{id}", field: "tenant_id"}},
	}
}

// provisioningSessionRoute constructs a templated route that pulls
// session_id from a config-delivery session request message and substitutes
// {sessionID} in the URL.
func provisioningSessionRoute(path, method string) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{{placeholder: "{sessionID}", field: "session_id"}},
	}
}

// proxyResourceRoute constructs a templated route that pulls id from a
// proxy route/pool request message and substitutes {id} in the URL.
func proxyResourceRoute(path, method string) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{{placeholder: "{id}", field: "id"}},
	}
}

// eabCredentialRoute constructs a templated route that pulls
// credential_id from an EAB request message and substitutes {id} in the
// URL, optionally appending query parameters (e.g. qrcode size).
func eabCredentialRoute(path, method string, queryParams ...queryParam) templatedRoute {
	return templatedRoute{
		path:        path,
		method:      method,
		pathParams:  []pathParam{{placeholder: "{id}", field: "credential_id"}},
		queryParams: queryParams,
	}
}

// grpcMethodToRESTMap provides O(1) lookup for gRPC to REST endpoint mapping.
var grpcMethodToRESTMap = map[string]struct {
	path   string
	method string
}{
	// Platform Daemon
	"/platform.v1.PlatformDaemon/GetVersion": {"/api/v1/version", http.MethodGet},
	"/platform.v1.PlatformDaemon/GetStatus":  {"/api/v1/status", http.MethodGet},

	// Health endpoints
	"/platform.v1.PlatformDaemon/Health":    {"/health", http.MethodGet},
	"/platform.v1.PlatformDaemon/Liveness":  {"/health/live", http.MethodGet},
	"/platform.v1.PlatformDaemon/Readiness": {"/health/ready", http.MethodGet},

	// CA Service
	"/platform.v1.CAService/GetCAInfo":         {"/api/v1/ca/info", http.MethodGet},
	"/platform.v1.CAService/IssueCertificate":  {"/api/v1/ca/certificates", http.MethodPost},
	"/platform.v1.CAService/ListCertificates":  {"/api/v1/ca/certificates", http.MethodGet},
	"/platform.v1.CAService/RevokeCertificate": {"/api/v1/ca/certificates/revoke", http.MethodPost},
	"/platform.v1.CAService/RenewCertificate":  {"/api/v1/ca/certificates/renew", http.MethodPost},
	"/platform.v1.CAService/VerifyCertificate": {"/api/v1/ca/certificates/verify", http.MethodPost},
	"/platform.v1.CAService/GetCRL":            {"/api/v1/ca/crl", http.MethodGet},
	"/platform.v1.CAService/GetCABundle":       {"/api/v1/ca/bundle", http.MethodGet},

	// IAM Service
	"/platform.v1.PlatformIAMService/CreateUser": {"/api/v1/iam/users", http.MethodPost},
	"/platform.v1.PlatformIAMService/ListUsers":  {"/api/v1/iam/users", http.MethodGet},

	"/platform.v1.PlatformIAMService/CreateRole": {"/api/v1/iam/roles", http.MethodPost},
	"/platform.v1.PlatformIAMService/ListRoles":  {"/api/v1/iam/roles", http.MethodGet},

	"/platform.v1.PlatformIAMService/CreateGroup": {"/api/v1/iam/groups", http.MethodPost},
	"/platform.v1.PlatformIAMService/ListGroups":  {"/api/v1/iam/groups", http.MethodGet},

	"/platform.v1.PlatformIAMService/CreateTenant": {"/api/v1/iam/tenants", http.MethodPost},
	"/platform.v1.PlatformIAMService/ListTenants":  {"/api/v1/iam/tenants", http.MethodGet},

	// GetCurrentUser was removed (#415): iam.proto declares no such rpc, and
	// its path /iam/users/current routed to GetUser with id="current".
	"/platform.v1.PlatformIAMService/CheckPermission": {"/api/v1/iam/permissions/check", http.MethodPost},
	"/platform.v1.PlatformIAMService/CreateToken":     {"/api/v1/iam/tokens", http.MethodPost},
	"/platform.v1.PlatformIAMService/RevokeToken":     {"/api/v1/iam/tokens/revoke", http.MethodPost},
	"/platform.v1.PlatformIAMService/VerifyToken":     {"/api/v1/iam/tokens/verify", http.MethodPost},

	// KMS Service
	"/platform.v1.KeyManagementService/GenerateKey":            {"/api/v1/kms/keys", http.MethodPost},
	"/platform.v1.KeyManagementService/DeleteKey":              {"/api/v1/kms/keys", http.MethodDelete},
	"/platform.v1.KeyManagementService/ListKeys":               {"/api/v1/kms/keys", http.MethodGet},
	"/platform.v1.KeyManagementService/RotateKey":              {"/api/v1/kms/keys/rotate", http.MethodPost},
	"/platform.v1.KeyManagementService/Encrypt":                {"/api/v1/kms/encrypt", http.MethodPost},
	"/platform.v1.KeyManagementService/Decrypt":                {"/api/v1/kms/decrypt", http.MethodPost},
	"/platform.v1.KeyManagementService/Sign":                   {"/api/v1/kms/sign", http.MethodPost},
	"/platform.v1.KeyManagementService/Verify":                 {"/api/v1/kms/verify", http.MethodPost},
	"/platform.v1.KeyManagementService/GenerateRandom":         {"/api/v1/kms/random", http.MethodPost},
	"/platform.v1.KeyManagementService/GenerateDataKey":        {"/api/v1/kms/data-keys", http.MethodPost},
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": {"/api/v1/kms/data-keys/wrapped", http.MethodPost},

	// VTPM Service — proto: pkg/api/grpc/proto/vtpm.proto
	// The SDK test suite exercises instance lifecycle through the
	// /platform.v1.VTPMService/* path forms below.
	"/platform.v1.VTPMService/Create":        {"/api/v1/vtpm/instances", http.MethodPost},
	"/platform.v1.VTPMService/Delete":        {"/api/v1/vtpm/instances", http.MethodDelete},
	"/platform.v1.VTPMService/Start":         {"/api/v1/vtpm/instances/start", http.MethodPost},
	"/platform.v1.VTPMService/Stop":          {"/api/v1/vtpm/instances/stop", http.MethodPost},
	"/platform.v1.VTPMService/List":          {"/api/v1/vtpm/instances", http.MethodGet},
	"/platform.v1.VTPMService/GetState":      {"/api/v1/vtpm/instances/state", http.MethodGet},
	"/platform.v1.VTPMService/QuoteVTPM":     {"/api/v1/vtpm/quote", http.MethodPost},
	"/platform.v1.VTPMService/SealVTPM":      {"/api/v1/vtpm/seal", http.MethodPost},
	"/platform.v1.VTPMService/UnsealVTPM":    {"/api/v1/vtpm/unseal", http.MethodPost},
	"/platform.v1.VTPMService/ExtendVTPMPCR": {"/api/v1/vtpm/pcrs/extend", http.MethodPost},
	"/platform.v1.VTPMService/ReadVTPMPCR":   {"/api/v1/vtpm/pcrs", http.MethodGet},

	// Physical TPM Service — proto: pkg/api/grpc/proto/tpm.proto
	// Server registrations live in pkg/webservice/v1/rest/tpm/router.go
	// (RegisterRoutes). Keep this map in lockstep with that file or
	// the CLI gets 404 on /tpm/info etc. (the bug was: SDK called
	// POST /platform.v1.TPMService/Info because no map entry existed,
	// while the server only handles GET /api/v1/tpm/info).
	"/platform.v1.TPMService/Info":                {"/api/v1/tpm/info", http.MethodGet},
	"/platform.v1.TPMService/Provision":           {"/api/v1/tpm/provision", http.MethodPost},
	"/platform.v1.TPMService/Clear":               {"/api/v1/tpm/clear", http.MethodPost},
	"/platform.v1.TPMService/CreateEK":            {"/api/v1/tpm/ek", http.MethodPost},
	"/platform.v1.TPMService/GetEK":               {"/api/v1/tpm/ek", http.MethodGet},
	"/platform.v1.TPMService/DeleteEK":            {"/api/v1/tpm/ek", http.MethodDelete},
	"/platform.v1.TPMService/GetEKCertificate":    {"/api/v1/tpm/ek/certificate", http.MethodGet},
	"/platform.v1.TPMService/ImportEKCertificate": {"/api/v1/tpm/ek/certificate", http.MethodPost},
	"/platform.v1.TPMService/CreateSRK":           {"/api/v1/tpm/srk", http.MethodPost},
	"/platform.v1.TPMService/DeleteSRK":           {"/api/v1/tpm/srk", http.MethodDelete},
	"/platform.v1.TPMService/CreateAK":            {"/api/v1/tpm/ak", http.MethodPost},
	"/platform.v1.TPMService/GetAK":               {"/api/v1/tpm/ak", http.MethodGet},
	"/platform.v1.TPMService/DeleteAK":            {"/api/v1/tpm/ak", http.MethodDelete},
	"/platform.v1.TPMService/Seal":                {"/api/v1/tpm/seal", http.MethodPost},
	"/platform.v1.TPMService/Unseal":              {"/api/v1/tpm/unseal", http.MethodPost},
	"/platform.v1.TPMService/Quote":               {"/api/v1/tpm/quote", http.MethodPost},
	"/platform.v1.TPMService/VerifyQuote":         {"/api/v1/tpm/quote/verify", http.MethodPost},
	"/platform.v1.TPMService/GetEventLog":         {"/api/v1/tpm/eventlog", http.MethodGet},
	"/platform.v1.TPMService/GetPCRs":             {"/api/v1/tpm/pcrs", http.MethodGet},
	"/platform.v1.TPMService/DefineNVRAM":         {"/api/v1/tpm/nvram", http.MethodPost},
	"/platform.v1.TPMService/ReadNVRAM":           {"/api/v1/tpm/nvram", http.MethodGet},
	"/platform.v1.TPMService/WriteNVRAM":          {"/api/v1/tpm/nvram", http.MethodPut},
	"/platform.v1.TPMService/UndefineNVRAM":       {"/api/v1/tpm/nvram", http.MethodDelete},
	"/platform.v1.TPMService/GetRandom":           {"/api/v1/tpm/random", http.MethodPost},

	// Device Service
	"/platform.v1.DeviceService/CreateDevice":            {"/api/v1/devices", http.MethodPost},
	"/platform.v1.DeviceService/DeleteDevice":            {"/api/v1/devices", http.MethodDelete},
	"/platform.v1.DeviceService/ListDevices":             {"/api/v1/devices", http.MethodGet},
	"/platform.v1.DeviceService/UpdateDevice":            {"/api/v1/devices", http.MethodPut},
	"/platform.v1.DeviceService/CountDevices":            {"/api/v1/devices/count", http.MethodGet},
	"/platform.v1.DeviceService/FindDeviceBySerial":      {"/api/v1/devices/by-serial", http.MethodGet},
	"/platform.v1.DeviceService/ActivateDevice":          {"/api/v1/devices/activate", http.MethodPost},
	"/platform.v1.DeviceService/CreateProfile":           {"/api/v1/device/profiles", http.MethodPost},
	"/platform.v1.DeviceService/UpdateProfile":           {"/api/v1/device/profiles", http.MethodPut},
	"/platform.v1.DeviceService/DeleteProfile":           {"/api/v1/device/profiles", http.MethodDelete},
	"/platform.v1.DeviceService/ListProfiles":            {"/api/v1/device/profiles", http.MethodGet},
	"/platform.v1.DeviceService/CountProfiles":           {"/api/v1/device/profiles/count", http.MethodGet},
	"/platform.v1.DeviceService/FindProfileByMACAddress": {"/api/v1/device/profiles/by-mac", http.MethodGet},
	"/platform.v1.DeviceService/FindProfileBySerial":     {"/api/v1/device/profiles/by-serial", http.MethodGet},
	"/platform.v1.DeviceService/FindMatchingProfile":     {"/api/v1/device/profiles/match", http.MethodPost},

	// SDN Service
	"/platform.v1.SDNService/CreateBridge":     {"/api/v1/sdn/bridges", http.MethodPost},
	"/platform.v1.SDNService/DeleteBridge":     {"/api/v1/sdn/bridges", http.MethodDelete},
	"/platform.v1.SDNService/ListBridges":      {"/api/v1/sdn/bridges", http.MethodGet},
	"/platform.v1.SDNService/GetPortState":     {"/api/v1/sdn/ports/state", http.MethodGet},
	"/platform.v1.SDNService/SetPortState":     {"/api/v1/sdn/ports/state", http.MethodPost},
	"/platform.v1.SDNService/AddPort":          {"/api/v1/sdn/ports", http.MethodPost},
	"/platform.v1.SDNService/DeletePort":       {"/api/v1/sdn/ports", http.MethodDelete},
	"/platform.v1.SDNService/AddFlow":          {"/api/v1/sdn/flows", http.MethodPost},
	"/platform.v1.SDNService/DeleteFlow":       {"/api/v1/sdn/flows", http.MethodDelete},
	"/platform.v1.SDNService/ListFlows":        {"/api/v1/sdn/flows", http.MethodGet},
	"/platform.v1.SDNService/ApplyPolicy":      {"/api/v1/sdn/policies/apply", http.MethodPost},
	"/platform.v1.SDNService/ListPolicies":     {"/api/v1/sdn/policies", http.MethodGet},
	"/platform.v1.SDNService/AuthenticatePort": {"/api/v1/sdn/ports/auth", http.MethodPost},
	"/platform.v1.SDNService/RevokePortAuth":   {"/api/v1/sdn/ports/auth", http.MethodDelete},

	// DNS Service
	"/platform.v1.DNSService/AddRecord":    {"/api/v1/dns/records", http.MethodPost},
	"/platform.v1.DNSService/DeleteRecord": {"/api/v1/dns/records", http.MethodDelete},
	"/platform.v1.DNSService/GetRecord":    {"/api/v1/dns/records", http.MethodGet},
	"/platform.v1.DNSService/ListRecords":  {"/api/v1/dns/records", http.MethodGet},
	"/platform.v1.DNSService/Resolve":      {"/api/v1/dns/resolve", http.MethodGet},
	"/platform.v1.DNSService/CreateZone":   {"/api/v1/dns/zones", http.MethodPost},
	"/platform.v1.DNSService/DeleteZone":   {"/api/v1/dns/zones", http.MethodDelete},
	"/platform.v1.DNSService/ListZones":    {"/api/v1/dns/zones", http.MethodGet},

	// Attestation Service
	"/platform.v1.AttestationService/GetQuote":       {"/api/v1/attestation/quote", http.MethodPost},
	"/platform.v1.AttestationService/VerifyQuote":    {"/api/v1/attestation/verify", http.MethodPost},
	"/platform.v1.AttestationService/GetEK":          {"/api/v1/attestation/ek", http.MethodGet},
	"/platform.v1.AttestationService/GetAK":          {"/api/v1/attestation/ak", http.MethodGet},
	"/platform.v1.AttestationService/CreateAK":       {"/api/v1/attestation/ak", http.MethodPost},
	"/platform.v1.AttestationService/ChallengeAK":    {"/api/v1/attestation/challenge", http.MethodPost},
	"/platform.v1.AttestationService/VerifyChalleng": {"/api/v1/attestation/challenge/verify", http.MethodPost},

	// IDevID Service
	"/platform.v1.IDevIDService/Generate":    {"/api/v1/idevid", http.MethodPost},
	"/platform.v1.IDevIDService/GetInfo":     {"/api/v1/idevid/info", http.MethodGet},
	"/platform.v1.IDevIDService/Delete":      {"/api/v1/idevid", http.MethodDelete},
	"/platform.v1.IDevIDService/GetCSR":      {"/api/v1/idevid/csr", http.MethodGet},
	"/platform.v1.IDevIDService/InstallCert": {"/api/v1/idevid/cert", http.MethodPost},
	"/platform.v1.IDevIDService/GetCert":     {"/api/v1/idevid/cert", http.MethodGet},
	"/platform.v1.IDevIDService/Exists":      {"/api/v1/idevid/exists", http.MethodGet},

	// Tenant Service
	"/platform.v1.TenantService/CreateTenant":  {"/api/v1/tenants", http.MethodPost},
	"/platform.v1.TenantService/DeleteTenant":  {"/api/v1/tenants", http.MethodDelete},
	"/platform.v1.TenantService/ListTenants":   {"/api/v1/tenants", http.MethodGet},
	"/platform.v1.TenantService/UpdateTenant":  {"/api/v1/tenants", http.MethodPut},
	"/platform.v1.TenantService/SuspendTenant": {"/api/v1/tenants/suspend", http.MethodPost},
	"/platform.v1.TenantService/ResumeTenant":  {"/api/v1/tenants/resume", http.MethodPost},

	// PXE Service
	"/platform.v1.PXEService/ListDevices":    {"/api/v1/pxe/devices", http.MethodGet},
	"/platform.v1.PXEService/RegisterDevice": {"/api/v1/pxe/devices", http.MethodPost},
	"/platform.v1.PXEService/UpdateState":    {"/api/v1/pxe/devices/state", http.MethodPut},
	"/platform.v1.PXEService/Authorize":      {"/api/v1/pxe/devices/authorize", http.MethodPost},
	"/platform.v1.PXEService/Quarantine":     {"/api/v1/pxe/devices/quarantine", http.MethodPost},
	"/platform.v1.PXEService/GetStatus":      {"/api/v1/pxe/status", http.MethodGet},

	// Switch Service
	"/platform.v1.SwitchService/ListPorts":     {"/api/v1/switches/ports", http.MethodGet},
	"/platform.v1.SwitchService/GetPortStatus": {"/api/v1/switches/ports/status", http.MethodGet},
	"/platform.v1.SwitchService/SetPortVLAN":   {"/api/v1/switches/ports/vlan", http.MethodPost},
	"/platform.v1.SwitchService/EnablePort":    {"/api/v1/switches/ports/enable", http.MethodPost},
	"/platform.v1.SwitchService/DisablePort":   {"/api/v1/switches/ports/disable", http.MethodPost},

	// Compute Service
	"/platform.v1.ComputeService/CreateContainer":  {"/api/v1/compute/containers", http.MethodPost},
	"/platform.v1.ComputeService/DeleteContainer":  {"/api/v1/compute/containers", http.MethodDelete},
	"/platform.v1.ComputeService/StartContainer":   {"/api/v1/compute/containers/start", http.MethodPost},
	"/platform.v1.ComputeService/StopContainer":    {"/api/v1/compute/containers/stop", http.MethodPost},
	"/platform.v1.ComputeService/ListContainers":   {"/api/v1/compute/containers", http.MethodGet},
	"/platform.v1.ComputeService/AttestContainer":  {"/api/v1/compute/containers/attest", http.MethodPost},
	"/platform.v1.ComputeService/GetContainerLogs": {"/api/v1/compute/containers/logs", http.MethodGet},

	// Ceremony Service — proto: pkg/api/grpc/proto/ceremony.proto
	// Server registrations live in pkg/api/daemon/ceremony_rest.go.
	"/platform.v1.CeremonyService/Init":               {"/api/v1/ceremony/init", http.MethodPost},
	"/platform.v1.CeremonyService/Status":             {"/api/v1/ceremony/status", http.MethodGet},
	"/platform.v1.CeremonyService/ClaimCertBegin":     {"/api/v1/ceremony/claim-cert/begin", http.MethodPost},
	"/platform.v1.CeremonyService/ClaimCertComplete":  {"/api/v1/ceremony/claim-cert/complete", http.MethodPost},
	"/platform.v1.CeremonyService/ClaimShareBegin":    {"/api/v1/ceremony/claim-share/begin", http.MethodPost},
	"/platform.v1.CeremonyService/ClaimShareComplete": {"/api/v1/ceremony/claim-share/complete", http.MethodPost},
	"/platform.v1.CeremonyService/SignCSR":            {"/api/v1/ceremony/sign-csr", http.MethodPost},

	// EAB Service — proto: pkg/api/grpc/proto/eab.proto
	// Server registrations live in pkg/webservice/v1/rest/eab/router.go.
	// CRUD methods that operate on a specific credential ID/key
	// resolve the ID from the request body — the SDK adapter posts
	// the body and the server router extracts {id}/{key}.
	// Credential-ID / key-ID scoped EAB routes carry their identifiers in
	// the URL and live in templatedRouteTable above; only the body-driven
	// operations remain flat.
	"/platform.v1.EABService/CreateCredential":          {"/api/v1/eab/credentials", http.MethodPost},
	"/platform.v1.EABService/ValidateCredential":        {"/api/v1/eab/credentials/validate", http.MethodPost},
	"/platform.v1.EABService/CleanupExpiredCredentials": {"/api/v1/eab/credentials/cleanup", http.MethodPost},

	// FIDO2 Service — proto: pkg/api/grpc/proto/fido2.proto
	"/platform.v1.FIDO2Service/ListDevices":  {"/api/v1/fido2/devices", http.MethodGet},
	"/platform.v1.FIDO2Service/WaitDevice":   {"/api/v1/fido2/devices/wait", http.MethodPost},
	"/platform.v1.FIDO2Service/Info":         {"/api/v1/fido2/info", http.MethodGet},
	"/platform.v1.FIDO2Service/Register":     {"/api/v1/fido2/register", http.MethodPost},
	"/platform.v1.FIDO2Service/Authenticate": {"/api/v1/fido2/authenticate", http.MethodPost},

	// Gateway Service — proto: pkg/api/grpc/proto/gateway.proto
	// Server registrations live in pkg/webservice/v1/rest/gateway/.
	// Proxy Service — flat collection/config routes; the per-resource
	// {id} routes are templated (see templatedRouteTable).
	"/platform.v1.ProxyService/CreateRoute":       {"/api/v1/proxy/routes", http.MethodPost},
	"/platform.v1.ProxyService/ListRoutes":        {"/api/v1/proxy/routes", http.MethodGet},
	"/platform.v1.ProxyService/CreatePool":        {"/api/v1/proxy/pools", http.MethodPost},
	"/platform.v1.ProxyService/ListPools":         {"/api/v1/proxy/pools", http.MethodGet},
	"/platform.v1.ProxyService/GetProxyConfig":    {"/api/v1/proxy/config", http.MethodGet},
	"/platform.v1.ProxyService/GetProxyStatus":    {"/api/v1/proxy/status", http.MethodGet},
	"/platform.v1.ProxyService/ReloadProxyConfig": {"/api/v1/proxy/reload", http.MethodPost},
	"/platform.v1.ProxyService/GetZoneMatrix":     {"/api/v1/proxy/zone-matrix", http.MethodGet},

	"/platform.v1.GatewayService/GetGatewayStatus":      {"/api/v1/gateway/status", http.MethodGet},
	"/platform.v1.GatewayService/SetGatewayMode":        {"/api/v1/gateway/mode", http.MethodPost},
	"/platform.v1.GatewayService/GetBGPStatus":          {"/api/v1/gateway/bgp/status", http.MethodGet},
	"/platform.v1.GatewayService/ListBGPPeers":          {"/api/v1/gateway/bgp/peers", http.MethodGet},
	"/platform.v1.GatewayService/AnnouncePrefix":        {"/api/v1/gateway/bgp/prefixes", http.MethodPost},
	"/platform.v1.GatewayService/WithdrawPrefix":        {"/api/v1/gateway/bgp/prefixes", http.MethodDelete},
	"/platform.v1.GatewayService/ListAnnouncedPrefixes": {"/api/v1/gateway/bgp/prefixes", http.MethodGet},
	"/platform.v1.GatewayService/ListIPAMPools":         {"/api/v1/gateway/ipam/pools", http.MethodGet},
	"/platform.v1.GatewayService/AllocateIP":            {"/api/v1/gateway/ipam/allocations", http.MethodPost},
	"/platform.v1.GatewayService/ReleaseIP":             {"/api/v1/gateway/ipam/allocations", http.MethodDelete},
	"/platform.v1.GatewayService/ListAllocations":       {"/api/v1/gateway/ipam/allocations", http.MethodGet},

	// Gateway perf verification — server registrations live in
	// pkg/api/rest/gateway_perf_handlers.go::registerPerfRoutes.
	// GetPerfFlows POSTs its parameters as the JSON body; the two GET
	// counters are templated routes so bridge / zone travel as query
	// parameters (see templatedRouteTable).
	"/platform.v1.GatewayService/GetPerfFlows": {"/api/v1/sdn/gateway/perf/flows", http.MethodPost},

	// NAT64 translator status — server registration lives in
	// pkg/api/rest/gateway_nat64_handlers.go::registerNAT64Routes. It is on
	// the /sdn/gateway prefix, not /gateway, so it must be mapped explicitly:
	// the fallback would derive POST /api/v1/gateway/getnat64status, which
	// nothing routes, and the 404 is indistinguishable from a gateway with
	// no translator configured (#601).
	"/platform.v1.GatewayService/GetNAT64Status": {"/api/v1/sdn/gateway/nat64/status", http.MethodGet},

	// Invitation Service — proto: pkg/api/grpc/proto/invitation.proto
	// Server registrations live in pkg/webservice/v1/rest/invitation/.
	// Detail/revoke routes carry {id}/{token} in the URL; the SDK
	// adapter posts the body and the server extracts vars.
	"/platform.v1.InvitationService/CreateInvitation":     {"/api/v1/invitations", http.MethodPost},
	"/platform.v1.InvitationService/GetInvitationByToken": {"/api/v1/invitations/by-token", http.MethodGet},
	"/platform.v1.InvitationService/ListInvitations":      {"/api/v1/invitations", http.MethodGet},
	"/platform.v1.InvitationService/RevokeInvitation":     {"/api/v1/invitations/revoke", http.MethodPost},
	"/platform.v1.InvitationService/AcceptInvitation":     {"/api/v1/invitations/accept", http.MethodPost},
	"/platform.v1.InvitationService/DeleteInvitation":     {"/api/v1/invitations", http.MethodDelete},

	// LUKS Service — proto: pkg/api/grpc/proto/luks.proto
	// Server registrations live in pkg/api/daemon/luks_rest_handlers.go.
	"/platform.v1.LUKSService/Status":           {"/api/v1/luks/status", http.MethodGet},
	"/platform.v1.LUKSService/ListSlots":        {"/api/v1/luks/slots", http.MethodGet},
	"/platform.v1.LUKSService/Info":             {"/api/v1/luks/info", http.MethodGet},
	"/platform.v1.LUKSService/EnrollPassphrase": {"/api/v1/luks/enroll/passphrase", http.MethodPost},
	"/platform.v1.LUKSService/EnrollFIDO2":      {"/api/v1/luks/enroll/fido2", http.MethodPost},
	"/platform.v1.LUKSService/EnrollTPM":        {"/api/v1/luks/enroll/tpm", http.MethodPost},
	"/platform.v1.LUKSService/EnrollRecovery":   {"/api/v1/luks/enroll/recovery", http.MethodPost},
	"/platform.v1.LUKSService/RemoveKey":        {"/api/v1/luks/slots", http.MethodDelete},
	"/platform.v1.LUKSService/TestUnlock":       {"/api/v1/luks/test-unlock", http.MethodPost},
	"/platform.v1.LUKSService/ChangePassphrase": {"/api/v1/luks/passphrase", http.MethodPut},

	// Overlay Service — proto: pkg/api/grpc/proto/overlay.proto
	// Server registrations live in pkg/webservice/v1/rest/overlay/.
	"/platform.v1.OverlayService/ListVTEPs":        {"/api/v1/overlay/vteps", http.MethodGet},
	"/platform.v1.OverlayService/CreateVNI":        {"/api/v1/overlay/vnis", http.MethodPost},
	"/platform.v1.OverlayService/DeleteVNI":        {"/api/v1/overlay/vnis", http.MethodDelete},
	"/platform.v1.OverlayService/ListVNIs":         {"/api/v1/overlay/vnis", http.MethodGet},
	"/platform.v1.OverlayService/ListTunnels":      {"/api/v1/overlay/tunnels", http.MethodGet},
	"/platform.v1.OverlayService/GetTunnelStats":   {"/api/v1/overlay/tunnels/stats", http.MethodGet},
	"/platform.v1.OverlayService/ListRemoteMACs":   {"/api/v1/overlay/macs", http.MethodGet},
	"/platform.v1.OverlayService/ForgetMAC":        {"/api/v1/overlay/macs", http.MethodDelete},
	"/platform.v1.OverlayService/GetOverlayStatus": {"/api/v1/overlay/status", http.MethodGet},

	// PIV Service — proto: pkg/api/grpc/proto/piv.proto
	"/platform.v1.PIVService/ListDevices": {"/api/v1/piv/devices", http.MethodGet},
	"/platform.v1.PIVService/ListSlots":   {"/api/v1/piv/slots", http.MethodGet},
	"/platform.v1.PIVService/SlotInfo":    {"/api/v1/piv/slots/info", http.MethodGet},
	"/platform.v1.PIVService/Generate":    {"/api/v1/piv/generate", http.MethodPost},
	"/platform.v1.PIVService/Import":      {"/api/v1/piv/import", http.MethodPost},
	"/platform.v1.PIVService/Sign":        {"/api/v1/piv/sign", http.MethodPost},
	"/platform.v1.PIVService/Attest":      {"/api/v1/piv/attest", http.MethodPost},
	"/platform.v1.PIVService/Reset":       {"/api/v1/piv/reset", http.MethodPost},

	// Config Delivery (provisioning) — proto: pkg/api/grpc/proto/configdelivery.proto
	// Server registrations live in pkg/api/daemon/rest_service.go::SetConfigDeliveryHandler.
	// GetSession / PollSession / FulfillSession carry {sessionID} in the
	// URL and live in templatedRouteTable above.
	"/platform.v1.ConfigDeliveryService/GetNonce":     {"/api/v1/provisioning/config/nonce", http.MethodGet},
	"/platform.v1.ConfigDeliveryService/FetchConfig":  {"/api/v1/provisioning/config", http.MethodPost},
	"/platform.v1.ConfigDeliveryService/SignDigest":   {"/api/v1/provisioning/sign", http.MethodPost},
	"/platform.v1.ConfigDeliveryService/ListSessions": {"/api/v1/provisioning/sessions", http.MethodGet},

	// Provisioning Gateway — proto: pkg/api/grpc/proto/provisioning.proto
	// Server registrations live in pkg/api/daemon/rest_service.go.
	"/platform.v1.ProvisioningGateway/RegisterPXEDevice":     {"/api/v1/provisioning/pxe/register", http.MethodPost},
	"/platform.v1.ProvisioningGateway/GetBootConfig":         {"/api/v1/provisioning/boot-config", http.MethodGet},
	"/platform.v1.ProvisioningGateway/ReportDeviceState":     {"/api/v1/provisioning/devices/state", http.MethodPost},
	"/platform.v1.ProvisioningGateway/NotifyInstallComplete": {"/api/v1/provisioning/devices/install-complete", http.MethodPost},

	// Cluster Service — proto: pkg/api/grpc/proto/cluster.proto
	// REST routes are best-effort; gRPC/Unix remain the canonical
	// transports for cluster lifecycle (Bootstrap/Join/Leave produce
	// streaming-style state transitions that don't fit plain REST).
	"/platform.v1.ClusterService/Bootstrap": {"/api/v1/cluster/bootstrap", http.MethodPost},
	"/platform.v1.ClusterService/Join":      {"/api/v1/cluster/join", http.MethodPost},
	"/platform.v1.ClusterService/Leave":     {"/api/v1/cluster/leave", http.MethodPost},
	"/platform.v1.ClusterService/GetStatus": {"/api/v1/cluster/status", http.MethodGet},
	"/platform.v1.ClusterService/ListNodes": {"/api/v1/cluster/nodes", http.MethodGet},

	// BMC Service and per-tenant barrier RPCs live in
	// templatedRouteTable above — their REST routes encode
	// {profileID} and {id} in the URL path, populated from the
	// request's profile_id / tenant_id field. See buildTemplatedRequest.

	// NTP Service — proto: pkg/api/grpc/proto/ntp.proto
	// Server registrations live in
	// pkg/webservice/v1/rest/ntp/router.go::RegisterRoutes (the 8443
	// webservice) and pkg/api/rest/ntp_handlers.go::RegisterRoutes (the
	// daemon's own REST listener); both mount identical paths.
	// Step answers 409 Conflict when no source is reachable.
	"/platform.v1.NTPService/GetStatus":   {"/api/v1/ntp/status", http.MethodGet},
	"/platform.v1.NTPService/ListSources": {"/api/v1/ntp/sources", http.MethodGet},
	"/platform.v1.NTPService/Step":        {"/api/v1/ntp/step", http.MethodPost},

	// Registry Service intentionally omitted: Push/Pull are
	// bidirectional streams that don't translate to plain REST.
}

// mapGRPCMethodToREST maps a gRPC method to REST endpoint and HTTP method.
// Uses O(1) map lookup for efficient dispatching.
func mapGRPCMethodToREST(grpcMethod string) (path string, httpMethod string) {
	if mapping, ok := grpcMethodToRESTMap[grpcMethod]; ok {
		return mapping.path, mapping.method
	}

	// Fallback: derive REST path from gRPC method
	// /package.Service/Method -> /api/v1/service/method
	parts := strings.Split(grpcMethod, "/")
	if len(parts) >= 3 {
		serviceParts := strings.Split(parts[1], ".")
		service := strings.ToLower(serviceParts[len(serviceParts)-1])
		service = strings.TrimSuffix(service, "service")
		method := strings.ToLower(parts[2])
		return "/api/v1/" + service + "/" + method, http.MethodPost
	}

	return "/api/v1/unknown", http.MethodPost
}

// httpStatusToGRPCMap provides O(1) lookup for HTTP to gRPC status code mapping.
var httpStatusToGRPCMap = map[int]codes.Code{
	http.StatusOK:                  codes.OK,
	http.StatusCreated:             codes.OK,
	http.StatusNoContent:           codes.OK,
	http.StatusBadRequest:          codes.InvalidArgument,
	http.StatusUnauthorized:        codes.Unauthenticated,
	http.StatusForbidden:           codes.PermissionDenied,
	http.StatusNotFound:            codes.NotFound,
	http.StatusConflict:            codes.AlreadyExists,
	http.StatusTooManyRequests:     codes.ResourceExhausted,
	http.StatusInternalServerError: codes.Internal,
	http.StatusNotImplemented:      codes.Unimplemented,
	http.StatusBadGateway:          codes.Unavailable,
	http.StatusServiceUnavailable:  codes.Unavailable,
	http.StatusGatewayTimeout:      codes.DeadlineExceeded,
}

// translateErrorToGRPC translates REST errors to gRPC status errors.
func translateErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case ErrHTTPStatus:
		code, ok := httpStatusToGRPCMap[e.StatusCode]
		if !ok {
			code = codes.Unknown
		}
		return status.Error(code, e.Body)

	case ErrClientClosed:
		return status.Error(codes.Unavailable, e.Error())

	case ErrRequestFailed:
		return status.Error(codes.Unavailable, e.Error())

	case ErrMarshalFailed:
		return status.Error(codes.InvalidArgument, e.Error())

	case ErrUnmarshalFailed:
		return status.Error(codes.Internal, e.Error())

	default:
		return status.Error(codes.Unknown, err.Error())
	}
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
