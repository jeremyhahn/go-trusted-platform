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

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// signCSRServer records the SignCSR request and answers with resp or err.
type signCSRServer struct {
	platformv1.UnimplementedCAServiceServer
	got  *platformv1.SignCSRRequest
	resp *platformv1.IssueCertificateResponse
	err  error
}

func (s *signCSRServer) SignCSR(_ context.Context, req *platformv1.SignCSRRequest) (*platformv1.IssueCertificateResponse, error) {
	s.got = req
	return s.resp, s.err
}

// caBindingOver returns a CABinding whose client reaches registry through
// the SDK's embedded transport.
func caBindingOver(t *testing.T, registry *embedded.ServiceRegistry) *CABinding {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn := NewConnectionBinding(logger)
	cl, err := platform.NewClient(
		context.Background(),
		platform.WithOnlyProtocol(platform.ProtocolEmbedded),
		platform.WithEmbeddedServices(registry),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := cl.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	conn.SetClient(&cl)
	return NewCABinding(logger, conn)
}

// The GUI's sign-csr sends what the CLI's sends and returns the object the
// CLI prints with --output json (#691).
func TestCABinding_SignCSRReturnsTheCertificate(t *testing.T) {
	server := &signCSRServer{resp: &platformv1.IssueCertificateResponse{
		Certificate: &platformv1.Certificate{Serial: "0a1b", Pem: []byte("-----BEGIN CERTIFICATE-----\n")},
	}}
	binding := caBindingOver(t, &embedded.ServiceRegistry{Daemon: platformv1.UnimplementedPlatformDaemonServer{}, CA: server})

	result, err := binding.SignCSR("-----BEGIN CERTIFICATE REQUEST-----\n", 30)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if server.got.GetCsrPem() != "-----BEGIN CERTIFICATE REQUEST-----\n" || server.got.GetValidDays() != 30 {
		t.Fatalf("request = %v, want the CSR and 30 days", server.got)
	}
	if result.Certificate.Serial != "0a1b" || string(result.Certificate.Pem) != "-----BEGIN CERTIFICATE-----\n" {
		t.Fatalf("certificate = %+v, want serial 0a1b and its PEM", result.Certificate)
	}
}

// A refusal from the CA reaches the GUI with its gRPC status intact, so a
// non-admin caller sees PermissionDenied.
func TestCABinding_SignCSRReturnsTheRefusal(t *testing.T) {
	server := &signCSRServer{err: status.Error(codes.PermissionDenied, "ca:sign-csr required")}
	binding := caBindingOver(t, &embedded.ServiceRegistry{Daemon: platformv1.UnimplementedPlatformDaemonServer{}, CA: server})

	result, err := binding.SignCSR("csr", 0)
	if result != nil {
		t.Fatalf("result = %+v, want nil", result)
	}
	var failed *casvc.ErrSignCSRFailed
	if !errors.As(err, &failed) || status.Code(failed.Cause) != codes.PermissionDenied {
		t.Fatalf("err = %v, want ErrSignCSRFailed carrying PermissionDenied", err)
	}
}

func TestCABinding_SignCSRRefusesAnAnswerWithoutACertificate(t *testing.T) {
	server := &signCSRServer{resp: &platformv1.IssueCertificateResponse{}}
	binding := caBindingOver(t, &embedded.ServiceRegistry{Daemon: platformv1.UnimplementedPlatformDaemonServer{}, CA: server})

	_, err := binding.SignCSR("csr", 0)
	var none *NoCertificateIssuedError
	if !errors.As(err, &none) {
		t.Fatalf("err = %v, want NoCertificateIssuedError", err)
	}
}

// A client that has been closed serves no services: CA() is nil, and the
// binding refuses instead of dereferencing it.
func TestCABinding_SignCSRNeedsTheCAService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn := NewConnectionBinding(logger)
	cl, err := platform.NewClient(
		context.Background(),
		platform.WithOnlyProtocol(platform.ProtocolEmbedded),
		platform.WithEmbeddedServices(&embedded.ServiceRegistry{Daemon: platformv1.UnimplementedPlatformDaemonServer{}}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := cl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	conn.SetClient(&cl)
	binding := NewCABinding(logger, conn)

	_, err = binding.SignCSR("csr", 0)
	var unavailable *ServiceUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Service != "CA" {
		t.Fatalf("err = %v, want ServiceUnavailableError{CA}", err)
	}
}

func TestCABinding_SignCSRNeedsAConnection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	binding := NewCABinding(logger, NewConnectionBinding(logger))

	_, err := binding.SignCSR("csr", 0)
	var notConnected *NotConnectedError
	if !errors.As(err, &notConnected) {
		t.Fatalf("err = %v, want NotConnectedError", err)
	}
}

// The desktop window exposes the CA binding to its frontend, sharing the
// window's connection. Before #691 it bound only the connection and daemon
// bindings, so no CA operation was reachable from the GUI.
func TestNewGUIBindings_ExposesTheCABinding(t *testing.T) {
	conn, bindings := newGUIBindings(slog.New(slog.NewTextHandler(io.Discard, nil)))

	var ca *CABinding
	for _, b := range bindings {
		if found, ok := b.(*CABinding); ok {
			ca = found
		}
	}
	if ca == nil {
		t.Fatalf("bindings = %T, want a *CABinding among them", bindings)
	}
	if ca.conn != conn {
		t.Fatal("the CA binding does not share the window's connection")
	}
}
