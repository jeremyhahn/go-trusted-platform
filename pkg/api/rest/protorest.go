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
)

// =============================================================================
// Protobuf JSON REST Errors
// =============================================================================

// ErrInvalidQueryParameter is returned when a request's path or query string
// names a parameter the request message does not have, or carries a value
// that does not parse as that field's type.
type ErrInvalidQueryParameter struct {
	Name   string
	Value  string
	Reason string
}

func (e ErrInvalidQueryParameter) Error() string {
	return fmt.Sprintf("invalid query parameter %s=%q: %s", e.Name, e.Value, e.Reason)
}

// ErrResponseEncoding is returned when a service's protobuf response cannot
// be encoded as JSON.
type ErrResponseEncoding struct {
	Cause error
}

func (e ErrResponseEncoding) Error() string {
	return "encode_response failed: " + e.Cause.Error()
}

func (e ErrResponseEncoding) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Protobuf JSON RPC Handler
// =============================================================================

// protoRPC serves one unary RPC of a protobuf service over REST. The request
// message is read from the protobuf JSON body, then from the path variables
// and the query string; a field the message does not have is refused, never
// dropped. The RPC runs with the TLS state of the connection the request
// arrived on, which a quote binds to (#482). service resolves the service at
// request time; its error is a 503.
func protoRPC[Svc any, Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](out protoResponder, service func() (Svc, error), rpc func(Svc, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return protoRPCPrepared(out, service, nil, rpc)
}

// protoRPCPrepared serves one unary RPC as protoRPC does, and runs prepare,
// when set, on the decoded request before the RPC: a route whose reply may
// outlive the server's write timeout moves its write deadline there.
func protoRPCPrepared[Svc any, Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](out protoResponder, service func() (Svc, error), prepare func(http.ResponseWriter, PReq), rpc func(Svc, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		svc, err := service()
		if err != nil {
			out.writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		req := PReq(new(Req))
		if !out.decodeProto(w, r, req) {
			return
		}
		params := r.URL.Query()
		for name, value := range mux.Vars(r) {
			params.Set(name, value)
		}
		if err := decodeProtoParams(params, req.ProtoReflect()); err != nil {
			out.writeError(w, http.StatusBadRequest, err)
			return
		}
		if prepare != nil {
			prepare(w, req)
		}
		ctx := channelbind.WithConnectionTLS(r.Context(), channelbind.TransportREST, r.TLS)
		resp, err := rpc(svc, ctx, req)
		if err != nil {
			out.writeStatusError(w, err)
			return
		}
		out.writeProto(w, http.StatusOK, resp)
	}
}

// =============================================================================
// URL Parameters
// =============================================================================

// decodeProtoParams sets the request fields that URL parameters name. A
// parameter is a field's proto name or JSON name (num_bytes or numBytes); a
// dotted name reaches into a singular message field (pagination.pageSize),
// and a string map takes its key after the field name
// (selector.matchLabels.env). A repeated field takes the parameter once per
// element.
func decodeProtoParams(params url.Values, msg protoreflect.Message) error {
	for name, values := range params {
		if err := decodeProtoParam(msg, name, values); err != nil {
			return err
		}
	}
	return nil
}

// decodeProtoParam sets the field one URL parameter names, walking the
// dotted path down from msg.
func decodeProtoParam(msg protoreflect.Message, name string, values []string) error {
	path := strings.Split(name, ".")
	for {
		field := protoFieldByName(msg.Descriptor().Fields(), path[0])
		if field == nil {
			return ErrInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: "not a field of " + string(msg.Descriptor().FullName())}
		}
		rest := path[1:]
		switch {
		case field.IsMap():
			return setProtoMapParam(msg, field, name, strings.Join(rest, "."), values)
		case len(rest) == 0:
			return setProtoParam(msg, field, name, values)
		case field.Kind() != protoreflect.MessageKind || field.IsList():
			return ErrInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: string(field.Name()) + " has no fields"}
		}
		msg = msg.Mutable(field).Message()
		path = rest
	}
}

// protoFieldByName finds a field by its proto name, then by its JSON name.
func protoFieldByName(fields protoreflect.FieldDescriptors, name string) protoreflect.FieldDescriptor {
	if field := fields.ByName(protoreflect.Name(name)); field != nil {
		return field
	}
	return fields.ByJSONName(name)
}

// setProtoParam sets a scalar or repeated scalar field from its values.
func setProtoParam(msg protoreflect.Message, field protoreflect.FieldDescriptor, name string, values []string) error {
	if !field.IsList() && len(values) > 1 {
		return ErrInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: "given more than once"}
	}
	parse, ok := protoParamParsers[field.Kind()]
	if !ok {
		return ErrInvalidQueryParameter{Name: name, Value: strings.Join(values, ","), Reason: "a " + field.Kind().String() + " field cannot be a URL parameter"}
	}
	for _, raw := range values {
		value, ok := parse(field, raw)
		if !ok {
			return ErrInvalidQueryParameter{Name: name, Value: raw, Reason: "not a valid " + field.Kind().String()}
		}
		if field.IsList() {
			msg.Mutable(field).List().Append(value)
		} else {
			msg.Set(field, value)
		}
	}
	return nil
}

// setProtoMapParam sets one entry of a map of string to string.
func setProtoMapParam(msg protoreflect.Message, field protoreflect.FieldDescriptor, name, key string, values []string) error {
	joined := strings.Join(values, ",")
	if field.MapKey().Kind() != protoreflect.StringKind || field.MapValue().Kind() != protoreflect.StringKind {
		return ErrInvalidQueryParameter{Name: name, Value: joined, Reason: "only a map of string to string can be a URL parameter"}
	}
	if key == "" {
		return ErrInvalidQueryParameter{Name: name, Value: joined, Reason: "a map parameter names its key: " + name + ".<key>"}
	}
	if len(values) > 1 {
		return ErrInvalidQueryParameter{Name: name, Value: joined, Reason: "given more than once"}
	}
	msg.Mutable(field).Map().Set(protoreflect.ValueOfString(key).MapKey(), protoreflect.ValueOfString(values[0]))
	return nil
}

// protoParamParser parses one URL parameter value as a value of field.
type protoParamParser func(field protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool)

// protoParamParsers parses each scalar kind a URL parameter can set. A
// uint32 takes any Go literal base, so ?handle=0x81000002 works; an enum
// takes its name or its number.
var protoParamParsers = map[protoreflect.Kind]protoParamParser{
	protoreflect.BoolKind:   parseBoolParam,
	protoreflect.StringKind: parseStringParam,
	protoreflect.EnumKind:   parseEnumParam,
	protoreflect.Uint32Kind: parseUint32Param,
	protoreflect.Int32Kind:  parseInt32Param,
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

// parseInt32Param parses a decimal int32, such as ?page.limit=50.
func parseInt32Param(_ protoreflect.FieldDescriptor, raw string) (protoreflect.Value, bool) {
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return protoreflect.Value{}, false
	}
	return protoreflect.ValueOfInt32(int32(n)), true
}

// =============================================================================
// Responses
// =============================================================================

// protoUnmarshalOptions decodes protobuf JSON request bodies. An unknown field
// is an error: a misspelled field must never become a silent default.
var protoUnmarshalOptions = protojson.UnmarshalOptions{
	DiscardUnknown: false,
}

// protoResponder reads protobuf JSON requests and writes protobuf JSON
// responses and the standard error envelope.
type protoResponder struct {
	logger *slog.Logger
}

// writeJSON writes a JSON response with the given status code.
func (p protoResponder) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		p.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response with the given status code.
func (p protoResponder) writeError(w http.ResponseWriter, status int, err error) {
	p.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// decodeProto reads a protojson request body into msg. An empty body leaves
// msg at its zero value. It writes a 400 and reports false when the body
// cannot be read or decoded.
func (p protoResponder) decodeProto(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return false
	}
	if len(data) == 0 {
		return true
	}
	if err := protoUnmarshalOptions.Unmarshal(data, msg); err != nil {
		p.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return false
	}
	return true
}

// writeProto writes msg as protojson with the given HTTP status, encoded the
// way the web service's routes encode it so the SDK decodes either listener.
func (p protoResponder) writeProto(w http.ResponseWriter, statusCode int, msg proto.Message) {
	payload, err := webserviceMarshalOptions.Marshal(msg)
	if err != nil {
		p.logger.Error("Failed to encode protobuf response", "error", err)
		p.writeError(w, http.StatusInternalServerError, ErrResponseEncoding{Cause: err})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(payload); err != nil {
		p.logger.Error("Failed to write protobuf response", "error", err)
	}
}

// writeStatusError answers with the HTTP equivalent of a service's gRPC
// status error.
func (p protoResponder) writeStatusError(w http.ResponseWriter, err error) {
	code, ok := protorestHTTPStatus[status.Code(err)]
	if !ok {
		code = http.StatusInternalServerError
	}
	p.logger.Error("REST request failed", "error", err, "http_status", code)
	p.writeError(w, code, err)
}
