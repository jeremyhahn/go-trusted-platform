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

// Package protorest provides shared helpers for REST handlers that delegate
// to sdk/go service clients backed by protobuf request/response types. The
// helpers handle JSON↔protojson marshalling, gRPC error → HTTP status mapping,
// and request-body decoding so individual handlers stay focused on the call
// itself.
package protorest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// MarshalOptions configures how protobuf messages are marshalled to JSON.
// Field names use the original proto camelCase form to align with the
// sdk/javascript expectations of nested response payloads.
var MarshalOptions = protojson.MarshalOptions{
	UseProtoNames:   false,
	EmitUnpopulated: true,
}

// UnmarshalOptions configures how JSON request bodies are decoded into
// protobuf messages. Unknown fields are ignored to keep the API forward
// compatible with sdk/javascript clients that may include extra fields.
var UnmarshalOptions = protojson.UnmarshalOptions{
	DiscardUnknown: true,
	AllowPartial:   true,
}

// DecodeRequest reads the request body as JSON and unmarshals it into msg.
// An empty body is treated as the zero-valued message; callers are expected
// to validate required fields after decoding.
func DecodeRequest(r *http.Request, msg proto.Message) error {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return &ErrReadBodyFailed{Cause: err}
	}
	defer r.Body.Close()
	if len(data) == 0 {
		return nil
	}
	if err := UnmarshalOptions.Unmarshal(data, msg); err != nil {
		return &ErrInvalidJSON{Cause: err}
	}
	return nil
}

// WriteSuccess marshals msg to JSON and writes a 200 response. When msg is
// nil an empty success envelope is emitted so the WebUI can detect the
// operation succeeded.
func WriteSuccess(w http.ResponseWriter, r *http.Request, writer response.HttpWriter, msg proto.Message) {
	WriteSuccessStatus(w, r, writer, http.StatusOK, msg)
}

// WriteSuccessStatus is identical to WriteSuccess but lets callers select a
// specific 2xx status (e.g. 201 Created for resource creation endpoints).
func WriteSuccessStatus(w http.ResponseWriter, r *http.Request, writer response.HttpWriter, status int, msg proto.Message) {
	if msg == nil {
		switch status {
		case http.StatusCreated:
			writer.Success201(w, r, struct{}{})
		default:
			writer.Success200(w, r, struct{}{})
		}
		return
	}
	payload, err := MarshalOptions.Marshal(msg)
	if err != nil {
		writer.Error500(w, r, &ErrMarshalFailed{Cause: err})
		return
	}
	// Wrap the protojson bytes in json.RawMessage so the response writer
	// embeds them directly inside the standard envelope without re-encoding.
	writer.Write(w, r, status, response.WebServiceResponse{
		Code:    status,
		Success: status >= 200 && status < 300,
		Payload: json.RawMessage(payload),
	})
}

// WriteError maps a gRPC status code returned from an sdk/go service client
// onto the appropriate HTTP status and JSON envelope. Non-gRPC errors fall
// back to 500, except ErrServiceUnavailable which maps to 503 to match its
// name and the dashboard's expected empty-state semantics.
func WriteError(w http.ResponseWriter, r *http.Request, writer response.HttpWriter, err error) {
	if err == nil {
		writer.Error500(w, r, &ErrUnknown{})
		return
	}
	var unavailable *ErrServiceUnavailable
	if errors.As(err, &unavailable) {
		writer.Write(w, r, http.StatusServiceUnavailable, response.WebServiceResponse{
			Code:    http.StatusServiceUnavailable,
			Error:   err.Error(),
			Success: false,
		})
		return
	}
	st, ok := status.FromError(err)
	if !ok {
		// errors.As handles wrapped status errors emitted by sdk/go service clients.
		var grpcErr interface{ GRPCStatus() *status.Status }
		if errors.As(err, &grpcErr) {
			st = grpcErr.GRPCStatus()
			ok = true
		}
	}
	if !ok {
		writer.Error500(w, r, err)
		return
	}
	switch st.Code() {
	case codes.OK:
		writer.Success200(w, r, nil)
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		writer.Error400(w, r, err)
	case codes.Unauthenticated:
		writer.Error401(w, r, err)
	case codes.PermissionDenied:
		writer.Error403(w, r, err, nil)
	case codes.NotFound:
		writer.Error404(w, r, err)
	case codes.AlreadyExists, codes.Aborted:
		writer.Write(w, r, http.StatusConflict, response.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   err.Error(),
			Success: false,
		})
	case codes.ResourceExhausted:
		writer.Write(w, r, http.StatusTooManyRequests, response.WebServiceResponse{
			Code:    http.StatusTooManyRequests,
			Error:   err.Error(),
			Success: false,
		})
	case codes.Unimplemented:
		writer.Write(w, r, http.StatusNotImplemented, response.WebServiceResponse{
			Code:    http.StatusNotImplemented,
			Error:   err.Error(),
			Success: false,
		})
	case codes.Unavailable:
		writer.Write(w, r, http.StatusServiceUnavailable, response.WebServiceResponse{
			Code:    http.StatusServiceUnavailable,
			Error:   err.Error(),
			Success: false,
		})
	case codes.DeadlineExceeded:
		writer.Write(w, r, http.StatusGatewayTimeout, response.WebServiceResponse{
			Code:    http.StatusGatewayTimeout,
			Error:   err.Error(),
			Success: false,
		})
	default:
		writer.Error500(w, r, err)
	}
}

// QueryUint32 reads a query parameter and parses it as a uint32. Returns 0
// when the parameter is missing. An invalid value returns ErrInvalidQuery.
func QueryUint32(r *http.Request, name string) (uint32, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, &ErrInvalidQuery{Name: name, Value: v, Cause: err}
	}
	return uint32(parsed), nil
}

// QueryUint64 reads a query parameter and parses it as a uint64. Returns 0
// when the parameter is missing. An invalid value returns ErrInvalidQuery.
func QueryUint64(r *http.Request, name string) (uint64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, &ErrInvalidQuery{Name: name, Value: v, Cause: err}
	}
	return parsed, nil
}

// QueryBool reads a query parameter and parses it as a bool. Returns false
// when the parameter is missing.
func QueryBool(r *http.Request, name string) (bool, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return false, &ErrInvalidQuery{Name: name, Value: v, Cause: err}
	}
	return parsed, nil
}

// IsProtoMessage reports whether v implements proto.Message — used by tests
// to detect helper misuse.
func IsProtoMessage(v interface{}) bool {
	_, ok := v.(proto.Message)
	if !ok {
		return false
	}
	// Defensive: require a valid descriptor to avoid panics on nil pointers
	if pm, ok := v.(proto.Message); ok {
		if reflect := pm.ProtoReflect(); reflect != (protoreflect.Message)(nil) {
			return true
		}
	}
	return ok
}
