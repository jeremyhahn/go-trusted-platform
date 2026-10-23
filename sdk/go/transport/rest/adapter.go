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
	"sort"
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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/pollstream"
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
	timeout    time.Duration
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
		timeout:    timeout,
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

// probeHealth issues GET /health/live and succeeds only on a 2xx answer.
// Every REST listener serves the liveness probe unauthenticated. It probes
// liveness, not /health, because /health answers 503 while a component is
// degraded, and a degraded platform is still one the client can talk to.
func (a *Adapter) probeHealth(ctx context.Context, timeout time.Duration) error {
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, a.baseURL+"/health/live", nil)
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
	return a.do(ctx, a.httpClient, method, path, body, result)
}

// do sends one request through client and decodes the response; DoRequest
// uses the adapter's pooled client, a bound call a one-shot client that
// owns the connection its proof was computed for.
func (a *Adapter) do(ctx context.Context, client *http.Client, method, path string, body interface{}, result interface{}) error {
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

	resp, err := client.Do(req)
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
	if resp, ok := result.(*platformv1.GetStatusResponse); ok {
		return decodeStatusResponse(data, resp)
	}
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
func (c *restClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) (err error) {
	if c.adapter.closed.Load() {
		return status.Error(codes.Unavailable, "connection closed")
	}

	// A method the platform serves no REST route for is refused here,
	// before a channel binding or a request could reach the network.
	if reason, refused := restRefusedMethods[method]; refused {
		return ErrNoRESTRoute{Method: method, Reason: reason}
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

	// A call bound to its channel gets a dedicated connection: the
	// BindFunc completes args with a proof over that connection's
	// exporter, and the request travels on the same connection. The route
	// and body are built after the binding so they carry the proof.
	send := c.adapter.DoRequest
	if bind, bound := transport.ChannelBindingFrom(opts); bound {
		boundConn, bindErr := c.adapter.bindChannel(ctx, bind)
		if bindErr != nil {
			return bindErr
		}
		defer func() { err = errors.Join(err, boundConn.release()) }()
		send = func(ctx context.Context, method, path string, body, result interface{}) error {
			return c.adapter.do(ctx, boundConn.client, method, path, body, result)
		}
	}

	httpMethod, path, body, err := route(method, args)
	if err != nil {
		return err
	}
	if reqErr := send(ctx, httpMethod, path, body, result); reqErr != nil {
		if probeVerdict(method, reqErr, reply) {
			return nil
		}
		return translateErrorToGRPC(reqErr)
	}
	return c.finishInvoke(hasDecoder, decode, raw, reply)
}

// route resolves the HTTP method, path and body of a gRPC method call.
// Templated routes substitute path params and strip them from the body,
// which is sent as a clone of args so the caller's message is not
// mutated; flat routes derive the path from the static map (or the gRPC
// method-name heuristic) and send args. Either body then passes through
// the method's request encoder, if it has one.
func route(method string, args interface{}) (httpMethod, path string, body interface{}, err error) {
	if entry, ok := templatedRouteTable[method]; ok {
		path, body, err := buildTemplatedRequest(entry, args)
		if err != nil {
			return "", "", nil, err
		}
		if body, err = encodeInvokeBody(method, body); err != nil {
			return "", "", nil, err
		}
		return entry.method, path, body, nil
	}
	path, httpMethod = mapGRPCMethodToREST(method)
	if body, err = encodeInvokeBody(method, args); err != nil {
		return "", "", nil, err
	}
	return httpMethod, path, body, nil
}

// encodeInvokeBody applies the method's request encoder, if any, and reports a
// body the encoder refuses (an enum outside the wire set) as InvalidArgument
// before anything is sent.
func encodeInvokeBody(method string, body interface{}) (interface{}, error) {
	encoded, err := encodeRequestBody(method, body)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return encoded, nil
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
		v, fd, ok := fieldPathValue(rm, p.field)
		if !ok {
			return "", nil, status.Errorf(codes.Internal,
				"REST adapter: proto field %q missing on %s", p.field, rm.Descriptor().FullName())
		}
		encoded, ok := p.render(v, fd)
		if !ok {
			return "", nil, status.Errorf(codes.InvalidArgument,
				"%s requires non-zero %s for templated REST route", rm.Descriptor().FullName(), p.field)
		}
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
		encoded, qErr := qp.render(rm)
		if qErr != nil {
			return "", nil, qErr
		}
		for _, value := range encoded {
			values.Add(qp.name, value)
		}
	}

	// Clone and clear the templated fields so the body matches what the
	// server expects. proto.Clone is shallow-correct for the fields we
	// touch (we only Clear scalar / nested-scalar fields).
	clone := proto.Clone(msg)
	cloneRefl := clone.ProtoReflect()
	for _, p := range route.pathParams {
		clearProtoFieldPath(cloneRefl, p.field)
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
// request message and renders it as query parameter values. Returns no
// values when the field (or any parent message) is zero-valued so the
// parameter is omitted. Enum fields render as the proto enum value name
// (the servers accept both the full enum name and the short form); a map
// field renders one "key=value" value per entry.
func encodeQueryField(rm protoreflect.Message, fieldPath string) ([]string, error) {
	segments := strings.Split(fieldPath, ".")
	current := rm
	for _, segment := range segments[:len(segments)-1] {
		fd := current.Descriptor().Fields().ByName(protoreflect.Name(segment))
		if fd == nil || fd.Kind() != protoreflect.MessageKind {
			return nil, status.Errorf(codes.Internal,
				"REST adapter: query field path %q invalid on %s", fieldPath, rm.Descriptor().FullName())
		}
		if !current.Has(fd) {
			return nil, nil
		}
		current = current.Get(fd).Message()
	}

	leaf := segments[len(segments)-1]
	fd := current.Descriptor().Fields().ByName(protoreflect.Name(leaf))
	if fd == nil {
		return nil, status.Errorf(codes.Internal,
			"REST adapter: query field %q missing on %s", fieldPath, current.Descriptor().FullName())
	}

	v := current.Get(fd)
	if fd.IsMap() {
		return encodeQueryMap(v.Map()), nil
	}
	switch fd.Kind() {
	case protoreflect.BoolKind:
		if !v.Bool() {
			return nil, nil
		}
		return []string{"true"}, nil
	case protoreflect.EnumKind:
		n := v.Enum()
		if n == 0 {
			return nil, nil
		}
		if desc := fd.Enum().Values().ByNumber(n); desc != nil {
			return []string{string(desc.Name())}, nil
		}
		return []string{strconv.FormatInt(int64(n), 10)}, nil
	default:
		// Use the RAW value: url.Values.Encode() applies query escaping,
		// so pre-escaped path encoding would double-escape.
		raw, _, ok := encodePathField(v, fd)
		if !ok {
			return nil, nil
		}
		return []string{raw}, nil
	}
}

// encodeQueryMap renders a map field as one "key=value" query value per
// entry, sorted by key so the request is deterministic.
func encodeQueryMap(m protoreflect.Map) []string {
	entries := make([]string, 0, m.Len())
	m.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		entries = append(entries, k.String()+"="+fmt.Sprint(v.Interface()))
		return true
	})
	sort.Strings(entries)
	return entries
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

// fieldPathDescriptor resolves a dotted proto field path ("device.id")
// against md and returns the leaf field. Every segment but the last must
// name a singular message field; ok is false otherwise.
func fieldPathDescriptor(md protoreflect.MessageDescriptor, fieldPath string) (protoreflect.FieldDescriptor, bool) {
	segments := strings.Split(fieldPath, ".")
	for _, segment := range segments[:len(segments)-1] {
		fd := md.Fields().ByName(protoreflect.Name(segment))
		if fd == nil || fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			return nil, false
		}
		md = fd.Message()
	}
	leaf := md.Fields().ByName(protoreflect.Name(segments[len(segments)-1]))
	return leaf, leaf != nil
}

// fieldPathValue reads the value at a dotted proto field path. An unset
// intermediate message reads as empty, so its leaf reads as the zero
// value and encodePathField rejects it. ok is false when the path does not
// resolve on the message's descriptor.
func fieldPathValue(rm protoreflect.Message, fieldPath string) (protoreflect.Value, protoreflect.FieldDescriptor, bool) {
	leaf, ok := fieldPathDescriptor(rm.Descriptor(), fieldPath)
	if !ok {
		return protoreflect.Value{}, nil, false
	}
	segments := strings.Split(fieldPath, ".")
	current := rm
	for _, segment := range segments[:len(segments)-1] {
		current = current.Get(current.Descriptor().Fields().ByName(protoreflect.Name(segment))).Message()
	}
	return current.Get(leaf), leaf, true
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

// NewStream serves a server-streaming method by long-polling its unary
// twin; a method without one is Unimplemented.
func (c *restClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return pollstream.NewStream(ctx, c, method, c.adapter.timeout, opts...)
}

// pathParam describes a single placeholder substitution in a templated
// REST route. The placeholder is a literal segment in the route's path
// template (e.g. "{profileID}") and field is the proto field name in
// the request message (snake_case, as protoreflect surfaces it). field
// may be a dotted path ("device.id") into a singular nested message, for
// update requests that carry the identifier inside the resource. encode,
// when set, replaces the default rendering for a server that spells the
// value differently.
type pathParam struct {
	placeholder string
	field       string
	encode      fieldEncoder
}

// fieldEncoder renders a request field's value as the server spells it in
// the URL, unescaped. An empty result means the field is unset: a path
// parameter refuses it and a query parameter is omitted.
type fieldEncoder func(protoreflect.Value) string

// render returns the escaped path segment for the parameter's value and
// whether the value is set.
func (p pathParam) render(v protoreflect.Value, fd protoreflect.FieldDescriptor) (string, bool) {
	if p.encode == nil {
		_, encoded, ok := encodePathField(v, fd)
		return encoded, ok
	}
	raw := p.encode(v)
	return url.PathEscape(raw), raw != ""
}

// queryParam describes a single query-string parameter derived from a
// request field. name is the URL query parameter; field is a
// dot-separated proto field path on the request message (snake_case, as
// protoreflect surfaces it — e.g. "pagination.page"). Zero-valued
// fields are omitted from the URL so "absent" and "no filter" coincide.
// encode, when set, replaces the default rendering of a single value.
type queryParam struct {
	name   string
	field  string
	encode fieldEncoder
}

// render returns the parameter's raw query values; none when it is unset.
func (q queryParam) render(rm protoreflect.Message) ([]string, error) {
	if q.encode == nil {
		return encodeQueryField(rm, q.field)
	}
	v, _, ok := fieldPathValue(rm, q.field)
	if !ok {
		return nil, status.Errorf(codes.Internal,
			"REST adapter: query field %q missing on %s", q.field, rm.Descriptor().FullName())
	}
	if raw := q.encode(v); raw != "" {
		return []string{raw}, nil
	}
	return nil, nil
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
	// NV index operations address the index in the path, the way the
	// server registers them (pkg/webservice/v1/rest/tpm/router.go); the
	// password, offset and size stay in the body.
	"/platform.v1.TPMService/ReadNVRAM":     itemRoute("/api/v1/tpm/nvram/{index}", http.MethodGet, "{index}", "index"),
	"/platform.v1.TPMService/WriteNVRAM":    itemRoute("/api/v1/tpm/nvram/{index}", http.MethodPut, "{index}", "index"),
	"/platform.v1.TPMService/UndefineNVRAM": itemRoute("/api/v1/tpm/nvram/{index}", http.MethodDelete, "{index}", "index"),

	// Admitted overlay VTEPs — server registrations in
	// pkg/api/rest/gateway_handlers.go::RegisterRoutes. An empty gateway_id
	// is omitted, so the server answers for this node's own gateway.
	"/platform.v1.GatewayService/ListGatewayAdmittedVTEPs": {
		path:        "/api/v1/sdn/gateway/overlay/vteps",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "gateway_id", field: "gateway_id"}},
	},
	"/platform.v1.GatewayService/GetGatewayAdmittedVTEP": {
		path:        "/api/v1/sdn/gateway/overlay/vteps/{vtep}",
		method:      http.MethodGet,
		pathParams:  []pathParam{{placeholder: "{vtep}", field: "vtep"}},
		queryParams: []queryParam{{name: "gateway_id", field: "gateway_id"}},
	},

	// BGP withdraw — server registration in
	// pkg/webservice/v1/rest/gateway/router.go::RegisterRoutes. The server
	// reads the prefix from ?prefix= only; sent in the DELETE body it was
	// never seen, so every REST withdraw failed with "prefix is required".
	// An empty prefix is omitted and refused by the server, as on gRPC.
	"/platform.v1.GatewayService/WithdrawPrefix": {
		path:        "/api/v1/gateway/bgp/prefixes",
		method:      http.MethodDelete,
		queryParams: []queryParam{{name: "prefix", field: "prefix"}},
	},
	// Overlay MAC forget — server registration in
	// pkg/webservice/v1/rest/overlay/router.go::RegisterRoutes. The server
	// reads the MAC and VNI from ?mac= and ?vni= only; sent in the DELETE
	// body they were never seen, so every REST forget failed with "mac is
	// required". Empty values are omitted and refused by the server, as on
	// gRPC.
	"/platform.v1.OverlayService/ForgetMAC": {
		path:   "/api/v1/overlay/macs",
		method: http.MethodDelete,
		queryParams: []queryParam{
			{name: "mac", field: "mac"},
			{name: "vni", field: "vni"},
		},
	},
	// Overlay tunnel and MAC reads — the server reads its filters from the
	// query string only. As flat GET routes the filters travelled in a body
	// the server never reads, so a REST caller asking for one VNI got every
	// VNI, and GetTunnelStats never saw its remote VTEP. Zero values are
	// omitted: no filter, as on gRPC.
	"/platform.v1.OverlayService/ListTunnels": {
		path:        "/api/v1/overlay/tunnels",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "vni", field: "vni"}},
	},
	"/platform.v1.OverlayService/GetTunnelStats": {
		path:   "/api/v1/overlay/tunnels/stats",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "remote_vtep", field: "remote_vtep"},
			{name: "vni", field: "vni"},
		},
	},
	"/platform.v1.OverlayService/ListRemoteMACs": {
		path:        "/api/v1/overlay/macs",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "vni", field: "vni"}},
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
	// One singular accessor is NOT here, because the server serves no route
	// for it at all: PlatformIAMService/GetPermission (the IAM router
	// registers /policies, never /permissions, and iam.proto has only
	// CheckPermission). Inventing a path for it would replace a wrong answer
	// with a 404 that reads as fixed, so it stays in the flat table and is
	// recorded as an exemption in
	// TestRouteClaims_NoSingularAccessorSharesACollectionPathWithItsList.
	// The DNS record and zone routes live in dns.go.
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
	"/platform.v1.CAService/GetCertificate": {
		path:        "/api/v1/ca/certificates/{serial}",
		method:      http.MethodGet,
		pathParams:  []pathParam{{placeholder: "{serial}", field: "serial"}},
		queryParams: []queryParam{{name: "include_pem", field: "include_pem"}, {name: "include_der", field: "include_der"}},
	},
	// DELETE /api/v1/ca/certificates/{serial} and
	// POST /api/v1/ca/certificates/{serial}/renew: item operations on the
	// certificate the serial names. reason and delete_keys (revoke) and
	// valid_days and the SANs (renew) stay in the body (#452).
	"/platform.v1.CAService/RevokeCertificate": itemRoute("/api/v1/ca/certificates/{serial}", http.MethodDelete, "{serial}", "serial"),
	"/platform.v1.CAService/RenewCertificate":  itemRoute("/api/v1/ca/certificates/{serial}/renew", http.MethodPost, "{serial}", "serial"),

	// GET /api/v1/compute/containers/{id}
	"/platform.v1.ComputeService/GetContainer": itemRoute("/api/v1/compute/containers/{id}", http.MethodGet, "{id}", "id"),

	// DELETE /api/v1/compute/containers/{id}?force=true&delete_volumes=true
	// -- the handler reads force and delete_volumes from the query.
	"/platform.v1.ComputeService/DeleteContainer": {
		path:        "/api/v1/compute/containers/{id}",
		method:      http.MethodDelete,
		pathParams:  []pathParam{{placeholder: "{id}", field: "id"}},
		queryParams: []queryParam{{name: "force", field: "force"}, {name: "delete_volumes", field: "delete_volumes"}},
	},

	// POST /api/v1/compute/containers/{id}/start
	"/platform.v1.ComputeService/StartContainer": itemRoute("/api/v1/compute/containers/{id}/start", http.MethodPost, "{id}", "id"),

	// POST /api/v1/compute/containers/{id}/stop -- timeout_seconds stays in the body.
	"/platform.v1.ComputeService/StopContainer": itemRoute("/api/v1/compute/containers/{id}/stop", http.MethodPost, "{id}", "id"),

	// POST /api/v1/compute/containers/{id}/attest -- nonce, pcr_indices and
	// pcr_bank stay in the body.
	"/platform.v1.ComputeService/AttestContainer": itemRoute("/api/v1/compute/containers/{id}/attest", http.MethodPost, "{id}", "id"),

	// DELETE /api/v1/compute/vms/{id}?delete_disks=true -- both REST servers
	// read delete_disks from the query.
	"/platform.v1.ComputeService/DeleteVM": {
		path:        "/api/v1/compute/vms/{id}",
		method:      http.MethodDelete,
		pathParams:  []pathParam{{placeholder: "{id}", field: "id"}},
		queryParams: []queryParam{{name: "delete_disks", field: "delete_disks"}},
	},

	// POST /api/v1/compute/vms/{id}/{start,stop,reboot,suspend,resume} --
	// stop's force and timeout_seconds and reboot's force stay in the body.
	"/platform.v1.ComputeService/StartVM":   itemRoute("/api/v1/compute/vms/{id}/start", http.MethodPost, "{id}", "id"),
	"/platform.v1.ComputeService/StopVM":    itemRoute("/api/v1/compute/vms/{id}/stop", http.MethodPost, "{id}", "id"),
	"/platform.v1.ComputeService/RebootVM":  itemRoute("/api/v1/compute/vms/{id}/reboot", http.MethodPost, "{id}", "id"),
	"/platform.v1.ComputeService/SuspendVM": itemRoute("/api/v1/compute/vms/{id}/suspend", http.MethodPost, "{id}", "id"),
	"/platform.v1.ComputeService/ResumeVM":  itemRoute("/api/v1/compute/vms/{id}/resume", http.MethodPost, "{id}", "id"),

	// /api/v1/compute/vms/{id}/snapshots[/{snapshotId}[/restore]] -- the VM
	// and snapshot ids ride the path; create's config stays in the body.
	"/platform.v1.ComputeService/CreateSnapshot": itemRoute("/api/v1/compute/vms/{id}/snapshots", http.MethodPost, "{id}", "vm_id"),
	"/platform.v1.ComputeService/ListSnapshots":  itemRoute("/api/v1/compute/vms/{id}/snapshots", http.MethodGet, "{id}", "vm_id"),
	"/platform.v1.ComputeService/GetSnapshot":    vmSnapshotRoute("/api/v1/compute/vms/{id}/snapshots/{snapshotId}", http.MethodGet),
	"/platform.v1.ComputeService/DeleteSnapshot": vmSnapshotRoute("/api/v1/compute/vms/{id}/snapshots/{snapshotId}", http.MethodDelete),
	"/platform.v1.ComputeService/RestoreSnapshot": vmSnapshotRoute(
		"/api/v1/compute/vms/{id}/snapshots/{snapshotId}/restore", http.MethodPost),

	// POST /api/v1/compute/vms/{id}/attest[/verify] -- the nonce, PCR
	// selection and evidence stay in the body.
	"/platform.v1.ComputeService/AttestVM":            itemRoute("/api/v1/compute/vms/{id}/attest", http.MethodPost, "{id}", "vm_id"),
	"/platform.v1.ComputeService/VerifyVMAttestation": itemRoute("/api/v1/compute/vms/{id}/attest/verify", http.MethodPost, "{id}", "vm_id"),
	// FinalizeMigration names the receiver PrepareMigration returned in the
	// path; commit stays in the body.
	"/platform.v1.ComputeService/FinalizeMigration": itemRoute(
		"/api/v1/compute/migrations/{receiverId}/finalize", http.MethodPost, "{receiverId}", "receiver_id"),

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

	// POST /api/v1/devices/{id}/disable and /enable -- the operator
	// Enable/Disable Device flow (#250), registered in
	// pkg/webservice/v1/router/device.go::RegisterRoutes (admin gate). The
	// device_id request field fills the path; a disable body is
	// {"reason": string}.
	"/platform.v1.DeviceService/DisableDevice": itemRoute("/api/v1/devices/{id:[0-9]+}/disable", http.MethodPost, "{id:[0-9]+}", "device_id"),
	"/platform.v1.DeviceService/EnableDevice":  itemRoute("/api/v1/devices/{id:[0-9]+}/enable", http.MethodPost, "{id:[0-9]+}", "device_id"),

	// GET /api/v1/device/profiles/{id:[0-9]+} -- note the singular "device"
	// prefix: profiles live under /api/v1/device and device records under
	// /api/v1/devices, and no path is served under both (#266).
	"/platform.v1.DeviceService/GetProfile": itemRoute("/api/v1/device/profiles/{id:[0-9]+}", http.MethodGet, "{id:[0-9]+}", "id"),

	// The remaining DeviceService item and lookup routes, each written with
	// the exact template pkg/webservice/v1/router/device.go registers (#321).
	// Before #321 the update, delete and lookup rows sat in the flat table on
	// the collection path or on invented by-serial / by-mac paths, so every
	// one of them answered 404 or 405. Update requests carry the identifier
	// inside the resource, hence the dotted field.
	"/platform.v1.DeviceService/UpdateDevice":            itemRoute("/api/v1/devices/{id:[0-9]+}", http.MethodPut, "{id:[0-9]+}", "device.id"),
	"/platform.v1.DeviceService/DeleteDevice":            itemRoute("/api/v1/devices/{id:[0-9]+}", http.MethodDelete, "{id:[0-9]+}", "id"),
	"/platform.v1.DeviceService/FindDeviceBySerial":      itemRoute("/api/v1/devices/serial/{serial}", http.MethodGet, "{serial}", "serial"),
	"/platform.v1.DeviceService/UpdateProfile":           itemRoute("/api/v1/device/profiles/{id:[0-9]+}", http.MethodPut, "{id:[0-9]+}", "profile.id"),
	"/platform.v1.DeviceService/DeleteProfile":           itemRoute("/api/v1/device/profiles/{id:[0-9]+}", http.MethodDelete, "{id:[0-9]+}", "id"),
	"/platform.v1.DeviceService/FindProfileByMACAddress": itemRoute("/api/v1/device/profiles/mac/{mac}", http.MethodGet, "{mac}", "mac_address"),
	"/platform.v1.DeviceService/FindProfileBySerial":     itemRoute("/api/v1/device/profiles/serial/{serial}", http.MethodGet, "{serial}", "serial"),

	// POST /api/v1/devices/{id}/attest (admin gate). The server leaves this
	// id unconstrained; evidence travels in the body.
	"/platform.v1.DeviceService/AttestDevice": itemRoute("/api/v1/devices/{id}/attest", http.MethodPost, "{id}", "device_id"),

	// GET, PUT and DELETE /api/v1/device/templates/{id:[0-9]+}.
	"/platform.v1.DeviceService/GetTemplate":    itemRoute("/api/v1/device/templates/{id:[0-9]+}", http.MethodGet, "{id:[0-9]+}", "id"),
	"/platform.v1.DeviceService/UpdateTemplate": itemRoute("/api/v1/device/templates/{id:[0-9]+}", http.MethodPut, "{id:[0-9]+}", "template.id"),
	"/platform.v1.DeviceService/DeleteTemplate": itemRoute("/api/v1/device/templates/{id:[0-9]+}", http.MethodDelete, "{id:[0-9]+}", "id"),
	// The template list pages by query parameter; a zero page or size is
	// omitted, so the server's defaults apply.
	"/platform.v1.DeviceService/ListTemplates": {
		path:   "/api/v1/device/templates",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "page", field: "pagination.page"},
			{name: "page_size", field: "pagination.page_size"},
		},
	},
	// POST /api/v1/device/templates/{id:[0-9]+}/create-profile. The body
	// keeps {"overrides": {...}}.
	"/platform.v1.DeviceService/CreateProfileFromTemplate": itemRoute("/api/v1/device/templates/{id:[0-9]+}/create-profile", http.MethodPost, "{id:[0-9]+}", "template_id"),

	// Config delivery: the lookup keys are query parameters, and the server
	// names the MAC parameter "mac".
	"/platform.v1.DeviceService/FindConfigForDevice": {
		path:   "/api/v1/device/profiles/find-config",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "ek_serial", field: "ek_serial"},
			{name: "mac", field: "mac_address"},
		},
	},
	"/platform.v1.DeviceService/AssignProfileToDevice":     itemRoute("/api/v1/device/profiles/{id:[0-9]+}/assign", http.MethodPost, "{id:[0-9]+}", "profile_id"),
	"/platform.v1.DeviceService/UnassignProfileFromDevice": itemRoute("/api/v1/device/profiles/{id:[0-9]+}/unassign", http.MethodPost, "{id:[0-9]+}", "profile_id"),

	// GET /api/v1/invitations/{id:[0-9]+} -- proto field is invitation_id.
	"/platform.v1.InvitationService/GetInvitation": itemRoute("/api/v1/invitations/{id:[0-9]+}", http.MethodGet, "{id:[0-9]+}", "invitation_id"),

	// The invitation item operations (#452), each on the template
	// pkg/webservice/v1/rest/invitation/router.go registers. The flat rows
	// sent DELETE /api/v1/invitations, POST /api/v1/invitations/revoke and
	// GET /api/v1/invitations/by-token with the identifier in the body, and
	// the server serves none of the three. RevokeInvitation keeps revoker_id
	// in the POST body. The token route is the invitee half, registered
	// outside the tenant-admin gate.
	"/platform.v1.InvitationService/DeleteInvitation":     itemRoute("/api/v1/invitations/{id:[0-9]+}", http.MethodDelete, "{id:[0-9]+}", "invitation_id"),
	"/platform.v1.InvitationService/RevokeInvitation":     itemRoute("/api/v1/invitations/{id:[0-9]+}/revoke", http.MethodPost, "{id:[0-9]+}", "invitation_id"),
	"/platform.v1.InvitationService/GetInvitationByToken": itemRoute("/api/v1/invitations/token/{token}", http.MethodGet, "{token}", "token"),

	// GET /api/v1/kms/keys/{name} -- the server names the segment {name}; the
	// proto field is key_id. The two names describe the same value.
	"/platform.v1.KeyManagementService/GetKey": itemRoute("/api/v1/kms/keys/{name}", http.MethodGet, "{name}", "key_id"),

	// The KMS key and crypto operations name the key the same way; their
	// bodies are reshaped to the server's wire names in kms.go.
	"/platform.v1.KeyManagementService/DeleteKey": itemRoute("/api/v1/kms/keys/{name}", http.MethodDelete, "{name}", "key_id"),
	"/platform.v1.KeyManagementService/RotateKey": itemRoute("/api/v1/kms/keys/{name}/rotate", http.MethodPost, "{name}", "key_id"),
	"/platform.v1.KeyManagementService/Encrypt":   itemRoute("/api/v1/kms/encrypt/{name}", http.MethodPost, "{name}", "key_id"),
	"/platform.v1.KeyManagementService/Decrypt":   itemRoute("/api/v1/kms/decrypt/{name}", http.MethodPost, "{name}", "key_id"),
	"/platform.v1.KeyManagementService/Sign":      itemRoute("/api/v1/kms/sign/{name}", http.MethodPost, "{name}", "key_id"),
	"/platform.v1.KeyManagementService/Verify":    itemRoute("/api/v1/kms/verify/{name}", http.MethodPost, "{name}", "key_id"),

	// GET /api/v1/kms/keys/{id}/export -- the daemon REST server's route
	// (pkg/api/rest/kms_handlers.go). It reads the wrapping algorithm and the
	// format as their enum numbers, so they are rendered as numbers here.
	"/platform.v1.KeyManagementService/ExportKey": {
		path:       "/api/v1/kms/keys/{id}/export",
		method:     http.MethodGet,
		pathParams: []pathParam{{placeholder: "{id}", field: "key_id"}},
		queryParams: []queryParam{
			{name: "wrapping_key_id", field: "wrapping_key_id"},
			{name: "wrapping_algorithm", field: "wrapping_algorithm", encode: encodeEnumNumber},
			{name: "format", field: "format", encode: encodeEnumNumber},
			{name: "version", field: "version"},
		},
	},

	// GET /api/v1/overlay/vteps/{nodeId}
	"/platform.v1.OverlayService/GetVTEP": itemRoute("/api/v1/overlay/vteps/{nodeId}", http.MethodGet, "{nodeId}", "node_id"),

	// DELETE /api/v1/overlay/vnis/{vni:[0-9]+} --
	// pkg/webservice/v1/rest/overlay/router.go. The flat row sent the VNI in
	// the body of DELETE /api/v1/overlay/vnis, which the server does not
	// serve (#452).
	"/platform.v1.OverlayService/DeleteVNI": itemRoute("/api/v1/overlay/vnis/{vni:[0-9]+}", http.MethodDelete, "{vni:[0-9]+}", "vni"),

	// GET /api/v1/pxe/devices/{id} -- request message is GetPXEDeviceRequest.
	"/platform.v1.PXEService/GetDevice": itemRoute("/api/v1/pxe/devices/{id}", http.MethodGet, "{id}", "device_id"),

	// PUT /api/v1/pxe/devices/{id}/state, POST .../{id}/authorize and
	// POST .../{id}/quarantine (#452) -- the device travels in the path,
	// the rest of the request in the body.
	"/platform.v1.PXEService/UpdateState": itemRoute("/api/v1/pxe/devices/{id}/state", http.MethodPut, "{id}", "device_id"),
	"/platform.v1.PXEService/Authorize":   itemRoute("/api/v1/pxe/devices/{id}/authorize", http.MethodPost, "{id}", "device_id"),
	"/platform.v1.PXEService/Quarantine":  itemRoute("/api/v1/pxe/devices/{id}/quarantine", http.MethodPost, "{id}", "device_id"),

	// The rest of the PXE control plane (#975): every RPC now rides the
	// route the web service serves it on, the device id or MAC only in the
	// path, and the ListDevices filter as the query the server reads.
	"/platform.v1.PXEService/GetDeviceByMAC":    itemRoute("/api/v1/pxe/devices/mac/{mac}", http.MethodGet, "{mac}", "mac_address"),
	"/platform.v1.PXEService/RemoveDevice":      itemRoute("/api/v1/pxe/devices/{id}", http.MethodDelete, "{id}", "device_id"),
	"/platform.v1.PXEService/SetDeviceEnrolled": itemRoute("/api/v1/pxe/devices/{id}/enrolled", http.MethodPost, "{id}", "device_id"),
	"/platform.v1.PXEService/Retry":             itemRoute("/api/v1/pxe/devices/{id}/retry", http.MethodPost, "{id}", "device_id"),
	"/platform.v1.PXEService/GetEvents":         itemRoute("/api/v1/pxe/devices/{id}/events", http.MethodGet, "{id}", "device_id"),
	"/platform.v1.PXEService/ListDevices": {
		path:   "/api/v1/pxe/devices",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "state", field: "filter.state"},
			{name: "mac_address", field: "filter.mac_address"},
			{name: "vlan", field: "filter.vlan"},
			{name: "limit", field: "filter.limit"},
			{name: "offset", field: "filter.offset"},
		},
	},

	// GET /api/v1/sdn/policies/{id}
	"/platform.v1.SDNService/GetPolicy": itemRoute("/api/v1/sdn/policies/{id}", http.MethodGet, "{id}", "policy_id"),

	// GET /api/v1/tenants/{id}
	"/platform.v1.TenantService/GetTenant": itemRoute("/api/v1/tenants/{id}", http.MethodGet, "{id}", "tenant_id"),

	// The tenant item operations (#452), each on the template
	// pkg/webservice/v1/rest/tenant/router.go registers. The flat rows sent
	// the collection path (or /tenants/suspend, /tenants/resume) with
	// tenant_id in the body; the server serves none of them. UpdateTenant
	// keeps display_name, labels and annotations in the PUT body.
	"/platform.v1.TenantService/UpdateTenant":  itemRoute("/api/v1/tenants/{id}", http.MethodPut, "{id}", "tenant_id"),
	"/platform.v1.TenantService/DeleteTenant":  itemRoute("/api/v1/tenants/{id}", http.MethodDelete, "{id}", "tenant_id"),
	"/platform.v1.TenantService/SuspendTenant": itemRoute("/api/v1/tenants/{id}/suspend", http.MethodPost, "{id}", "tenant_id"),
	"/platform.v1.TenantService/ResumeTenant":  itemRoute("/api/v1/tenants/{id}/resume", http.MethodPost, "{id}", "tenant_id"),

	// The name lookup, quotas and usage behind platformctl tenant show,
	// quotas and usage (and every command that names a tenant). The server
	// registers /by-name/{name} before /{id}, so the name never reads as an
	// id. UpdateQuotas keeps compute, network and storage in the PUT body.
	"/platform.v1.TenantService/GetTenantByName": itemRoute("/api/v1/tenants/by-name/{name}", http.MethodGet, "{name}", "name"),
	"/platform.v1.TenantService/GetQuotas":       itemRoute("/api/v1/tenants/{id}/quotas", http.MethodGet, "{id}", "tenant_id"),
	"/platform.v1.TenantService/UpdateQuotas":    itemRoute("/api/v1/tenants/{id}/quotas", http.MethodPut, "{id}", "tenant_id"),
	"/platform.v1.TenantService/GetUsage":        itemRoute("/api/v1/tenants/{id}/usage", http.MethodGet, "{id}", "tenant_id"),

	// The quota check and the DEK routes. CheckQuota keeps the prospective
	// allocation (resource, amount) in the POST body, and RotateTenantDEK
	// keeps background there.
	"/platform.v1.TenantService/CheckQuota":         itemRoute("/api/v1/tenants/{id}/quota-check", http.MethodPost, "{id}", "tenant_id"),
	"/platform.v1.TenantService/RotateTenantDEK":    itemRoute("/api/v1/tenants/{id}/dek/rotate", http.MethodPost, "{id}", "tenant_id"),
	"/platform.v1.TenantService/GetTenantDEKStatus": itemRoute("/api/v1/tenants/{id}/dek", http.MethodGet, "{id}", "tenant_id"),

	// GET /api/v1/iam/tenants/{tenant}/users/{id} --
	// pkg/webservice/v1/rest/iam/router.go registerUserRoutes.
	//
	// Every IAM request that carries tenant_id alongside an item identifier
	// targets the TENANT-SCOPED tree, with tenant_id in the {tenant} segment
	// (#401). The unscoped twin (/api/v1/iam/users/{id}) serves whatever tenant
	// the session is bound to and never reads tenant_id, so a caller naming
	// another tenant was answered from its own with a 200 -- while gRPC served
	// the tenant it named. On the scoped tree the server's RequireOwnTenant
	// refuses a tenant other than the session's with 403 (PermissionDenied
	// here), which is what gRPC now returns too; an empty tenant_id never
	// leaves the client (InvalidArgument), matching gRPC's required field.
	"/platform.v1.PlatformIAMService/GetUser": tenantItemRoute("/api/v1/iam/tenants/{tenant}/users/{id}", http.MethodGet,
		pathParam{placeholder: "{id}", field: "user_id"}),

	// GET /api/v1/iam/tenants/{tenant}/roles/{id} -- registerRoleRoutes.
	"/platform.v1.PlatformIAMService/GetRole": tenantItemRoute("/api/v1/iam/tenants/{tenant}/roles/{id}", http.MethodGet,
		pathParam{placeholder: "{id}", field: "role_id"}),

	// GET /api/v1/iam/tenants/{tenant}/groups/{id} -- registerGroupRoutes.
	"/platform.v1.PlatformIAMService/GetGroup": tenantItemRoute("/api/v1/iam/tenants/{tenant}/groups/{id}", http.MethodGet,
		pathParam{placeholder: "{id}", field: "group_id"}),

	// GET /api/v1/iam/tenants/{tenant} -- router.go:208. The server names this
	// segment {tenant}, not {id}, and the request has only tenant_id.
	"/platform.v1.PlatformIAMService/GetTenant": itemRoute("/api/v1/iam/tenants/{tenant}", http.MethodGet, "{tenant}", "tenant_id"),

	// DELETE /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}.
	// The flat row sent DELETE /api/v1/iam/groups/members, and the server
	// routed that to DELETE /groups/{id} with id="members": a DeleteGroup on
	// whatever group carries that name, not a membership removal (#415).
	// RemoveGroupMemberRequest carries tenant_id, group_id and user_id; all
	// three travel in the path.
	"/platform.v1.PlatformIAMService/RemoveGroupMember": tenantItemRoute("/api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "group_id"}, pathParam{placeholder: "{user}", field: "user_id"}),

	// The seven item operations #416 repairs (#379's shape on the mutating
	// verbs, found by #400's fixture). Each sent a collection path the server
	// does not serve for that verb; the server's routes are the item paths
	// below (pkg/webservice/v1/rest/iam/router.go), and the identifiers
	// travel in the path, never the body. All but DeleteTenant are on the
	// tenant-scoped tree for the reason given at GetUser (#401).
	"/platform.v1.PlatformIAMService/DeleteUser": tenantItemRoute("/api/v1/iam/tenants/{tenant}/users/{id}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "user_id"}),
	"/platform.v1.PlatformIAMService/DeleteRole": tenantItemRoute("/api/v1/iam/tenants/{tenant}/roles/{id}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "role_id"}),
	"/platform.v1.PlatformIAMService/DeleteGroup": tenantItemRoute("/api/v1/iam/tenants/{tenant}/groups/{id}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "group_id"}),
	"/platform.v1.PlatformIAMService/DeleteTenant": itemRoute("/api/v1/iam/tenants/{tenant}", http.MethodDelete, "{tenant}", "tenant_id"),
	"/platform.v1.PlatformIAMService/AssignRole": tenantItemRoute("/api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}", http.MethodPost,
		pathParam{placeholder: "{id}", field: "user_id"}, pathParam{placeholder: "{role}", field: "role_id"}),
	// RevokeRole changes verb as well as path: the server revokes with DELETE.
	"/platform.v1.PlatformIAMService/RevokeRole": tenantItemRoute("/api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}", http.MethodDelete,
		pathParam{placeholder: "{id}", field: "user_id"}, pathParam{placeholder: "{role}", field: "role_id"}),
	"/platform.v1.PlatformIAMService/AddGroupMember": tenantItemRoute("/api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}", http.MethodPost,
		pathParam{placeholder: "{id}", field: "group_id"}, pathParam{placeholder: "{user}", field: "user_id"}),

	// The four updates are a PUT on the item (router.go). With no row here
	// they fell back to POST /api/v1/platformiam/update<item>, which the
	// server does not serve, so none of them worked over REST (#401). The
	// identifiers travel in the path; the remaining fields are the body,
	// whose JSON names match the server's Update<Item>Request.
	"/platform.v1.PlatformIAMService/UpdateUser": tenantItemRoute("/api/v1/iam/tenants/{tenant}/users/{id}", http.MethodPut,
		pathParam{placeholder: "{id}", field: "user_id"}),
	"/platform.v1.PlatformIAMService/UpdateRole": tenantItemRoute("/api/v1/iam/tenants/{tenant}/roles/{id}", http.MethodPut,
		pathParam{placeholder: "{id}", field: "role_id"}),
	"/platform.v1.PlatformIAMService/UpdateGroup": tenantItemRoute("/api/v1/iam/tenants/{tenant}/groups/{id}", http.MethodPut,
		pathParam{placeholder: "{id}", field: "group_id"}),
	"/platform.v1.PlatformIAMService/UpdateTenant": itemRoute("/api/v1/iam/tenants/{tenant}", http.MethodPut, "{tenant}", "tenant_id"),
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
func itemRoute(path, method, placeholder, field string) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: []pathParam{{placeholder: placeholder, field: field}},
	}
}

// vmSnapshotRoute is itemRoute for a single VM snapshot: vm_id fills {id}
// and snapshot_id fills {snapshotId}, and neither may be empty.
func vmSnapshotRoute(path, method string) templatedRoute {
	return templatedRoute{
		path:   path,
		method: method,
		pathParams: []pathParam{
			{placeholder: "{id}", field: "vm_id"},
			{placeholder: "{snapshotId}", field: "snapshot_id"},
		},
	}
}

// tenantItemRoute is itemRoute for the IAM tenant-scoped tree,
// /api/v1/iam/tenants/{tenant}/...: the request's tenant_id fills {tenant},
// and items fill the identifiers after it (one, or a parent and a child such
// as /users/{id}/roles/{role}). Every identifier must be non-zero; a
// placeholder left unfilled is an error, never a shorter path (#415: the
// collection-path form of RemoveGroupMember routed to DeleteGroup with
// id="members"). Putting tenant_id in the path is what lets the server's
// RequireOwnTenant guard refuse a tenant the caller is not bound to (#401).
func tenantItemRoute(path, method string, items ...pathParam) templatedRoute {
	return templatedRoute{
		path:       path,
		method:     method,
		pathParams: append([]pathParam{{placeholder: "{tenant}", field: "tenant_id"}}, items...),
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
	"/platform.v1.PlatformDaemon/GetHealth": {"/health", http.MethodGet},
	"/platform.v1.PlatformDaemon/Liveness":  {"/health/live", http.MethodGet},
	"/platform.v1.PlatformDaemon/Readiness": {"/health/ready", http.MethodGet},

	// CA Service
	"/platform.v1.CAService/GetCAInfo":         {"/api/v1/ca/info", http.MethodGet},
	"/platform.v1.CAService/IssueCertificate":  {"/api/v1/ca/certificates", http.MethodPost},
	"/platform.v1.CAService/SignCSR":           {"/api/v1/ca/sign-csr", http.MethodPost},
	"/platform.v1.CAService/ListCertificates":  {"/api/v1/ca/certificates", http.MethodGet},
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
	// CreateToken, RevokeToken and VerifyToken have no REST route: route()
	// refuses them through restRefusedMethods (iam.go).

	// KMS Service
	"/platform.v1.KeyManagementService/GenerateKey":            {"/api/v1/kms/keys", http.MethodPost},
	"/platform.v1.KeyManagementService/ListKeys":               {"/api/v1/kms/keys", http.MethodGet},
	"/platform.v1.KeyManagementService/GenerateRandom":         {"/api/v1/kms/random", http.MethodPost},
	"/platform.v1.KeyManagementService/GenerateDataKey":        {"/api/v1/kms/data-keys", http.MethodPost},
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": {"/api/v1/kms/data-keys/wrapped", http.MethodPost},
	// The batch operations and rewrap are the daemon REST server's routes
	// (pkg/api/rest/kms_handlers.go); kms_batch.go reshapes their bodies.
	"/platform.v1.KeyManagementService/BatchEncrypt": {"/api/v1/kms/batch-encrypt", http.MethodPost},
	"/platform.v1.KeyManagementService/BatchDecrypt": {"/api/v1/kms/batch-decrypt", http.MethodPost},
	"/platform.v1.KeyManagementService/Rewrap":       {"/api/v1/kms/rewrap", http.MethodPost},

	// Physical TPM Service — proto: pkg/api/grpc/proto/tpm.proto
	// Server registrations live in pkg/webservice/v1/rest/tpm/router.go
	// (RegisterRoutes). Keep this map in lockstep with that file or
	// the CLI gets 404 on /tpm/info etc. (the bug was: SDK called
	// POST /platform.v1.TPMService/Info because no map entry existed,
	// while the server only handles GET /api/v1/tpm/info).
	"/platform.v1.TPMService/Info":                  {"/api/v1/tpm/info", http.MethodGet},
	"/platform.v1.TPMService/Provision":             {"/api/v1/tpm/provision", http.MethodPost},
	"/platform.v1.TPMService/Clear":                 {"/api/v1/tpm/clear", http.MethodPost},
	"/platform.v1.TPMService/CreateEK":              {"/api/v1/tpm/ek", http.MethodPost},
	"/platform.v1.TPMService/GetEK":                 {"/api/v1/tpm/ek", http.MethodGet},
	"/platform.v1.TPMService/DeleteEK":              {"/api/v1/tpm/ek", http.MethodDelete},
	"/platform.v1.TPMService/GetEKCertificate":      {"/api/v1/tpm/ek/certificate", http.MethodGet},
	"/platform.v1.TPMService/ImportEKCertificate":   {"/api/v1/tpm/ek/certificate", http.MethodPost},
	"/platform.v1.TPMService/CreateSRK":             {"/api/v1/tpm/srk", http.MethodPost},
	"/platform.v1.TPMService/DeleteSRK":             {"/api/v1/tpm/srk", http.MethodDelete},
	"/platform.v1.TPMService/CreateAK":              {"/api/v1/tpm/ak", http.MethodPost},
	"/platform.v1.TPMService/GetAK":                 {"/api/v1/tpm/ak", http.MethodGet},
	"/platform.v1.TPMService/DeleteAK":              {"/api/v1/tpm/ak", http.MethodDelete},
	"/platform.v1.TPMService/Seal":                  {"/api/v1/tpm/seal", http.MethodPost},
	"/platform.v1.TPMService/Unseal":                {"/api/v1/tpm/unseal", http.MethodPost},
	"/platform.v1.TPMService/Quote":                 {"/api/v1/tpm/quote", http.MethodPost},
	"/platform.v1.TPMService/VerifyQuote":           {"/api/v1/tpm/quote/verify", http.MethodPost},
	"/platform.v1.TPMService/Certify":               {"/api/v1/tpm/certify", http.MethodPost},
	"/platform.v1.TPMService/MakeCredential":        {"/api/v1/tpm/make-credential", http.MethodPost},
	"/platform.v1.TPMService/ActivateCredential":    {"/api/v1/tpm/activate-credential", http.MethodPost},
	"/platform.v1.TPMService/GetCapabilities":       {"/api/v1/tpm/capabilities", http.MethodGet},
	"/platform.v1.TPMService/GetPlatformAttributes": {"/api/v1/tpm/platform", http.MethodGet},
	"/platform.v1.TPMService/ExtendPCR":             {"/api/v1/tpm/pcrs/extend", http.MethodPost},
	"/platform.v1.TPMService/GetEventLog":           {"/api/v1/tpm/eventlog", http.MethodGet},
	"/platform.v1.TPMService/GetPCRs":               {"/api/v1/tpm/pcrs", http.MethodGet},
	"/platform.v1.TPMService/DefineNVRAM":           {"/api/v1/tpm/nvram", http.MethodPost},
	"/platform.v1.TPMService/GetRandom":             {"/api/v1/tpm/random", http.MethodPost},

	// Device Service. The item, lookup and nested-action routes live in
	// templatedRouteTable; these are the collection, count and match routes.
	// ActivateDevice targets the admin JSON route: /device/activate is the
	// machine-facing mTLS route a device calls for itself.
	"/platform.v1.DeviceService/CreateDevice":        {"/api/v1/devices", http.MethodPost},
	"/platform.v1.DeviceService/ListDevices":         {"/api/v1/devices", http.MethodGet},
	"/platform.v1.DeviceService/CountDevices":        {"/api/v1/devices/count", http.MethodGet},
	"/platform.v1.DeviceService/ActivateDevice":      {"/api/v1/device/activate-json", http.MethodPost},
	"/platform.v1.DeviceService/CreateProfile":       {"/api/v1/device/profiles", http.MethodPost},
	"/platform.v1.DeviceService/ListProfiles":        {"/api/v1/device/profiles", http.MethodGet},
	"/platform.v1.DeviceService/CountProfiles":       {"/api/v1/device/profiles/count", http.MethodGet},
	"/platform.v1.DeviceService/FindMatchingProfile": {"/api/v1/device/profiles/match", http.MethodPost},
	// A diskless node's per-boot routes. BootDelivery's identity is the
	// connection's client certificate, so the request carries only evidence.
	"/platform.v1.DeviceService/BootCertificate": {"/api/v1/device/boot/certificate", http.MethodPost},
	"/platform.v1.DeviceService/BootDelivery":    {"/api/v1/device/boot", http.MethodPost},

	// SDN Service
	// DeleteBridge, AddPort, DeletePort, AuthenticatePort and RevokePortAuth
	// are templated in sdn.go.
	"/platform.v1.SDNService/CreateBridge": {"/api/v1/sdn/bridges", http.MethodPost},
	"/platform.v1.SDNService/ListBridges":  {"/api/v1/sdn/bridges", http.MethodGet},
	"/platform.v1.SDNService/AddFlow":      {"/api/v1/sdn/flows", http.MethodPost},
	"/platform.v1.SDNService/DeleteFlow":   {"/api/v1/sdn/flows", http.MethodDelete},
	"/platform.v1.SDNService/ListFlows":    {"/api/v1/sdn/flows", http.MethodGet},
	"/platform.v1.SDNService/ApplyPolicy":  {"/api/v1/sdn/policies", http.MethodPost},
	"/platform.v1.SDNService/ListPolicies": {"/api/v1/sdn/policies", http.MethodGet},

	// DNS Service. The record, resolve and zone-delete routes are templated
	// in dns.go.
	"/platform.v1.DNSService/CreateZone": {"/api/v1/dns/zones", http.MethodPost},
	"/platform.v1.DNSService/ListZones":  {"/api/v1/dns/zones", http.MethodGet},

	// Attestation Service. The keys are the rpcs attestation.proto declares;
	// the routes are pkg/webservice/v1/rest/attestation/server_router.go's.
	"/platform.v1.AttestationService/GetAttestationQuote":    {"/api/v1/attestation/quote", http.MethodPost},
	"/platform.v1.AttestationService/VerifyAttestationQuote": {"/api/v1/attestation/quote/verify", http.MethodPost},
	"/platform.v1.AttestationService/CollectHostAttestation": {"/api/v1/attestation/host", http.MethodPost},

	// IDevID Service — the routes are pkg/webservice/v1/rest/idevid/router.go's.
	// CreateLDevID is mapped in ldevid.go.
	//
	// Key delete is refused on every transport. DeleteIDevID and DeleteIAK
	// go to the daemon listener's DELETE /api/v1/tpm/idevid and /tpm/iak
	// (pkg/api/daemon/rest_idevid.go), which answer 412, the HTTP status of
	// the gRPC class FailedPrecondition. The web service's DELETE
	// /api/v1/idevid and /idevid/iak write that class as 400.
	platformv1.IDevIDService_DeleteIDevID_FullMethodName:  {"/api/v1/tpm/idevid", http.MethodDelete},
	platformv1.IDevIDService_DeleteIAK_FullMethodName:     {"/api/v1/tpm/iak", http.MethodDelete},
	"/platform.v1.IDevIDService/GenerateIDevID":           {"/api/v1/idevid/generate", http.MethodPost},
	"/platform.v1.IDevIDService/GetIDevIDInfo":            {"/api/v1/idevid/info", http.MethodGet},
	"/platform.v1.IDevIDService/HasIDevID":                {"/api/v1/idevid/exists", http.MethodGet},
	"/platform.v1.IDevIDService/CreateIDevIDCSR":          {"/api/v1/idevid/csr", http.MethodPost},
	"/platform.v1.IDevIDService/InstallIDevIDCertificate": {"/api/v1/idevid/certificate", http.MethodPost},
	"/platform.v1.IDevIDService/GetIDevIDCertificate":     {"/api/v1/idevid/certificate", http.MethodGet},
	"/platform.v1.IDevIDService/DeleteIDevIDCertificate":  {"/api/v1/idevid/certificate", http.MethodDelete},
	"/platform.v1.IDevIDService/GenerateIAK":              {"/api/v1/idevid/iak/generate", http.MethodPost},
	"/platform.v1.IDevIDService/GetIAKInfo":               {"/api/v1/idevid/iak", http.MethodGet},
	"/platform.v1.IDevIDService/HasIAK":                   {"/api/v1/idevid/iak/exists", http.MethodGet},
	"/platform.v1.IDevIDService/CreateIAKCSR":             {"/api/v1/idevid/iak/csr", http.MethodPost},
	"/platform.v1.IDevIDService/InstallIAKCertificate":    {"/api/v1/idevid/iak/certificate", http.MethodPost},
	"/platform.v1.IDevIDService/GetIAKCertificate":        {"/api/v1/idevid/iak/certificate", http.MethodGet},
	"/platform.v1.IDevIDService/DeleteIAKCertificate":     {"/api/v1/idevid/iak/certificate", http.MethodDelete},
	"/platform.v1.IDevIDService/GetDeviceAttributes":      {"/api/v1/idevid/attributes", http.MethodGet},
	"/platform.v1.IDevIDService/FlushTransientContexts":   {"/api/v1/idevid/flush", http.MethodPost},
	"/platform.v1.IDevIDService/ActivateCredential":       {"/api/v1/idevid/activate-credential", http.MethodPost},

	// Tenant Service
	"/platform.v1.TenantService/CreateTenant": {"/api/v1/tenants", http.MethodPost},
	"/platform.v1.TenantService/ListTenants":  {"/api/v1/tenants", http.MethodGet},
	"/platform.v1.TenantService/Sync":         {"/api/v1/tenants/sync", http.MethodPost},

	// PXE Service
	"/platform.v1.PXEService/RegisterDevice":  {"/api/v1/pxe/devices", http.MethodPost},
	"/platform.v1.PXEService/GetStatus":       {"/api/v1/pxe/status", http.MethodGet},
	"/platform.v1.PXEService/StartService":    {"/api/v1/pxe/start", http.MethodPost},
	"/platform.v1.PXEService/StopService":     {"/api/v1/pxe/stop", http.MethodPost},
	"/platform.v1.PXEService/WebhookComplete": {"/api/v1/pxe/webhook/complete", http.MethodPost},

	// Switch Service routes are templated: see switches.go.

	// Compute Service
	"/platform.v1.ComputeService/CreateContainer":  {"/api/v1/compute/containers", http.MethodPost},
	"/platform.v1.ComputeService/ListContainers":   {"/api/v1/compute/containers", http.MethodGet},
	"/platform.v1.ComputeService/GetContainerLogs": {"/api/v1/compute/containers/logs", http.MethodGet},
	// ListVMs sends its whole request (states, selector, pagination) as the
	// JSON body, which both REST servers decode on this GET.
	"/platform.v1.ComputeService/ListVMs": {"/api/v1/compute/vms", http.MethodGet},
	// CreateVM sends its whole request (config and start) as the JSON body.
	"/platform.v1.ComputeService/CreateVM": {"/api/v1/compute/vms", http.MethodPost},
	// PrepareMigration sends its whole request (VM name, mode and spec) as
	// the JSON body; the receiver it stands up has no id until it answers.
	"/platform.v1.ComputeService/PrepareMigration": {"/api/v1/compute/migrations/prepare", http.MethodPost},

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
	// WaitDevice and Info name the device or the timeout in the URL and live in
	// templatedRouteTable (phase35.go).
	"/platform.v1.FIDO2Service/ListDevices":  {"/api/v1/fido2/devices", http.MethodGet},
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
	"/platform.v1.GatewayService/ListAnnouncedPrefixes": {"/api/v1/gateway/bgp/prefixes", http.MethodGet},
	// The IPAM verbs route to the full /sdn/gateway/ipam surface; see
	// gateway_ipam.go.

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
	// The item routes, which carry {id} or {token} in the URL, are in
	// templatedRouteTable.
	"/platform.v1.InvitationService/CreateInvitation": {"/api/v1/invitations", http.MethodPost},
	"/platform.v1.InvitationService/ListInvitations":  {"/api/v1/invitations", http.MethodGet},
	"/platform.v1.InvitationService/AcceptInvitation": {"/api/v1/invitations/accept", http.MethodPost},

	// LUKS Service — proto: pkg/api/grpc/proto/luks.proto
	// Server registrations live in pkg/api/daemon/luks_rest.go. Status,
	// ListSlots and Info carry ?device= and live in templatedRouteTable
	// (luks.go).
	"/platform.v1.LUKSService/EnrollPassphrase": {"/api/v1/luks/enroll/passphrase", http.MethodPost},
	"/platform.v1.LUKSService/EnrollFIDO2":      {"/api/v1/luks/enroll/fido2", http.MethodPost},
	"/platform.v1.LUKSService/EnrollTPM":        {"/api/v1/luks/enroll/tpm", http.MethodPost},
	"/platform.v1.LUKSService/EnrollRecovery":   {"/api/v1/luks/enroll/recovery", http.MethodPost},
	"/platform.v1.LUKSService/RemoveKey":        {"/api/v1/luks/keys/remove", http.MethodPost},
	"/platform.v1.LUKSService/TestUnlock":       {"/api/v1/luks/keys/test-unlock", http.MethodPost},
	"/platform.v1.LUKSService/ChangePassphrase": {"/api/v1/luks/passphrase/change", http.MethodPost},

	// Overlay Service — proto: pkg/api/grpc/proto/overlay.proto
	// Server registrations live in pkg/webservice/v1/rest/overlay/.
	"/platform.v1.OverlayService/ListVTEPs":        {"/api/v1/overlay/vteps", http.MethodGet},
	"/platform.v1.OverlayService/CreateVNI":        {"/api/v1/overlay/vnis", http.MethodPost},
	"/platform.v1.OverlayService/ListVNIs":         {"/api/v1/overlay/vnis", http.MethodGet},
	"/platform.v1.OverlayService/GetOverlayStatus": {"/api/v1/overlay/status", http.MethodGet},

	// PIV Service — proto: pkg/api/grpc/proto/piv.proto
	// Every other PIV method names a slot or a device in the URL and lives in
	// templatedRouteTable (phase35.go).
	"/platform.v1.PIVService/ListDevices": {"/api/v1/piv/devices", http.MethodGet},

	// Config Delivery (provisioning) — proto: pkg/api/grpc/proto/configdelivery.proto
	// Server registrations live in pkg/api/daemon/rest_service.go::SetConfigDeliveryHandler.
	// GetSession / PollSession / FulfillSession carry {sessionID} in the
	// URL and live in templatedRouteTable above.
	"/platform.v1.ConfigDeliveryService/GetNonce":     {"/api/v1/provisioning/config/nonce", http.MethodGet},
	"/platform.v1.ConfigDeliveryService/FetchConfig":  {"/api/v1/provisioning/config", http.MethodPost},
	"/platform.v1.ConfigDeliveryService/SignDigest":   {"/api/v1/provisioning/sign", http.MethodPost},
	"/platform.v1.ConfigDeliveryService/ListSessions": {"/api/v1/provisioning/sessions", http.MethodGet},

	// Provisioning Gateway — proto: pkg/api/grpc/proto/provisioning.proto.
	// Every RPC names a device by MAC, so all four are templated routes
	// (provisioning_gateway.go).

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
	http.StatusPreconditionFailed:  codes.FailedPrecondition,
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
		return status.Error(code, restErrorMessage(e.Body))

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

// restErrorMessage returns the message a REST error body carries. platformd
// handlers answer a failure as {"error":"<message>"}; the status message is
// that bare message, the same one the QUIC and MCP transports return. A body
// of any other shape is returned unchanged.
func restErrorMessage(body string) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil || payload.Error == "" {
		return body
	}
	return payload.Error
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
