//go:build integration

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

package attestation

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestIsNotFound_TransportErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"gRPC NotFound", ErrGRPCCallFailed{Method: "GetManifest", Err: status.Error(codes.NotFound, "manifest not found")}, true},
		{"gRPC InvalidArgument", ErrGRPCCallFailed{Method: "GetManifest", Err: status.Error(codes.InvalidArgument, "manifest id is required")}, false},
		{"Unix NotFound", ErrUnixRPCFailed{Method: "GetManifest", Err: status.Error(codes.NotFound, "manifest not found")}, true},
		{"Unix Internal", ErrUnixRPCFailed{Method: "GetManifest", Err: status.Error(codes.Internal, "boom")}, false},
		{"QUIC StatusNotFound", ErrQUICStatus{Operation: "GetManifest", Status: quicwire.StatusNotFound}, true},
		{"QUIC StatusInvalidArgument", ErrQUICStatus{Operation: "GetManifest", Status: quicwire.StatusInvalidArgument}, false},
		{"MCP NotFound", &MCPAdapterError{Operation: "tools/call", Code: mcpwire.NotFound}, true},
		{"MCP MethodNotFound", &MCPAdapterError{Operation: "tools/call", Code: mcpwire.MethodNotFound}, false},
		{"REST 404 without envelope", &RESTAdapterError{StatusCode: http.StatusNotFound, Body: "404 page not found\n"}, false},
		{"REST no route", ErrRESTNoRoute{Operation: "GetVMIdentity"}, false},
		{"untyped", errors.New("not found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsNotFound_RESTUnknownManifestIsTyped(t *testing.T) {
	a := newRESTAdapterAgainstRouter(t, newFakeAttestationServer())

	_, err := a.GetManifest(context.Background(), GetManifestOptions{ManifestID: "absent"})
	if !IsNotFound(err) {
		t.Fatalf("GetManifest of an unknown manifest = %v, want a typed not-found", err)
	}
	_, err = a.VerifyManifest(context.Background(), VerifyManifestOptions{ManifestID: "absent"})
	if !IsNotFound(err) {
		t.Fatalf("VerifyManifest of an unknown manifest = %v, want a typed not-found", err)
	}
}

func TestIsNotFound_RESTUnregisteredPathIsNot(t *testing.T) {
	a := newRESTAdapterAgainstRouter(t, newFakeAttestationServer())

	err := a.call(context.Background(), "Unrouted", http.MethodGet, "/api/v1/attestation/no-such-route/x/y", nil, nil)
	var restErr *RESTAdapterError
	if !errors.As(err, &restErr) || restErr.StatusCode != http.StatusNotFound {
		t.Fatalf("GET of an unregistered path = %v, want a 404 RESTAdapterError", err)
	}
	if IsNotFound(err) {
		t.Errorf("IsNotFound(%v) = true, want a router 404 to be a missing route, not a missing resource", err)
	}
}
