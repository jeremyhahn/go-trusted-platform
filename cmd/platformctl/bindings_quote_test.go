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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// quoteServer answers every quote rpc with a quote of the nonce as sent —
// the unbound answer #482 forbids — and records the verify requests. A
// binding that reaches it over the embedded transport has skipped the
// channel check.
type quoteServer struct {
	platformv1.UnimplementedAttestationServiceServer
	platformv1.UnimplementedTPMServiceServer

	quoted       int
	verifyAttest *platformv1.VerifyAttestationQuoteRequest
	verifyTPM    *platformv1.VerifyQuoteRequest
	err          error
}

func (s *quoteServer) GetAttestationQuote(_ context.Context, req *platformv1.GetAttestationQuoteRequest) (*platformv1.GetAttestationQuoteResponse, error) {
	s.quoted++
	return &platformv1.GetAttestationQuoteResponse{Quote: &platformv1.AttestationQuote{Nonce: req.GetNonce()}}, nil
}

func (s *quoteServer) CollectHostAttestation(_ context.Context, req *platformv1.CollectHostAttestationRequest) (*platformv1.CollectHostAttestationResponse, error) {
	s.quoted++
	return &platformv1.CollectHostAttestationResponse{Attestation: &platformv1.HostAttestation{Nonce: req.GetNonce()}}, nil
}

func (s *quoteServer) Quote(_ context.Context, req *platformv1.QuoteRequest) (*platformv1.QuoteResponse, error) {
	s.quoted++
	return &platformv1.QuoteResponse{Quote: req.GetNonce()}, nil
}

func (s *quoteServer) VerifyAttestationQuote(_ context.Context, req *platformv1.VerifyAttestationQuoteRequest) (*platformv1.VerifyAttestationQuoteResponse, error) {
	s.verifyAttest = req
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.VerifyAttestationQuoteResponse{Verified: true}, nil
}

func (s *quoteServer) VerifyQuote(_ context.Context, req *platformv1.VerifyQuoteRequest) (*platformv1.VerifyQuoteResponse, error) {
	s.verifyTPM = req
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.VerifyQuoteResponse{Verified: true}, nil
}

// quoteBindingsOver returns the attestation and TPM bindings reaching server
// through the SDK's embedded transport, which has no TLS connection to bind.
func quoteBindingsOver(t *testing.T, server *quoteServer) (*AttestationBinding, *TPMBinding) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn := NewConnectionBinding(logger)
	cl, err := platform.NewClient(
		context.Background(),
		platform.WithOnlyProtocol(platform.ProtocolEmbedded),
		platform.WithEmbeddedServices(&embedded.ServiceRegistry{
			Daemon:      platformv1.UnimplementedPlatformDaemonServer{},
			Attestation: server,
			TPM:         server,
		}),
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
	return NewAttestationBinding(logger, conn), NewTPMBinding(logger, conn)
}

// TestQuoteBindings_RefuseAConnectionWithNothingToBind pins that every GUI
// quote goes through the SDK's channel check: over a transport with no TLS
// connection the call is refused before the node is asked, instead of
// returning the quote of the bare nonce the server would have produced.
func TestQuoteBindings_RefuseAConnectionWithNothingToBind(t *testing.T) {
	calls := map[string]func(*AttestationBinding, *TPMBinding) error{
		"GetAttestationQuote": func(a *AttestationBinding, _ *TPMBinding) error {
			_, err := a.GetAttestationQuote([]uint32{0}, []byte("nonce"))
			return err
		},
		"CollectHostAttestation": func(a *AttestationBinding, _ *TPMBinding) error {
			_, err := a.CollectHostAttestation([]byte("nonce"))
			return err
		},
		"TPM Quote": func(_ *AttestationBinding, tb *TPMBinding) error {
			_, err := tb.Quote(0x81010002, "", []uint32{0}, "sha256", []byte("nonce"))
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			server := &quoteServer{}
			att, tpm := quoteBindingsOver(t, server)

			err := call(att, tpm)
			var unavailable *transport.ErrChannelBindingUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want ErrChannelBindingUnavailable", err)
			}
			if server.quoted != 0 {
				t.Errorf("the node was asked for %d quote(s), want none", server.quoted)
			}
		})
	}
}

func TestAttestationBinding_VerifyAttestationQuoteSendsTheBinding(t *testing.T) {
	server := &quoteServer{}
	att, _ := quoteBindingsOver(t, server)

	result, err := att.VerifyAttestationQuote([]byte("attest"), []byte("sig"), "SHA256-RSAPSS", []byte("ak"), []byte("nonce"), []byte("binding"))
	if err != nil {
		t.Fatalf("VerifyAttestationQuote: %v", err)
	}
	if result["verified"] != true {
		t.Errorf("result = %v, want verified", result)
	}
	got := server.verifyAttest
	if !bytes.Equal(got.GetChannelBinding(), []byte("binding")) || !bytes.Equal(got.GetExpectedNonce(), []byte("nonce")) ||
		!bytes.Equal(got.GetQuote().GetQuoteData(), []byte("attest")) || !bytes.Equal(got.GetQuote().GetSignature(), []byte("sig")) ||
		got.GetQuote().GetSignatureAlgorithm() != "SHA256-RSAPSS" {
		t.Errorf("request = %v, want the quote, signature, algorithm, nonce and binding as given", got)
	}
}

func TestAttestationBinding_VerifyAttestationQuoteReturnsTheRefusal(t *testing.T) {
	server := &quoteServer{err: status.Error(codes.InvalidArgument, "channel binding without a nonce")}
	att, _ := quoteBindingsOver(t, server)

	_, err := att.VerifyAttestationQuote([]byte("attest"), nil, "", nil, nil, []byte("binding"))
	var failed *attestationsvc.ErrVerifyQuoteFailed
	if !errors.As(err, &failed) || status.Code(failed.Cause) != codes.InvalidArgument {
		t.Fatalf("err = %v, want ErrVerifyQuoteFailed carrying InvalidArgument", err)
	}
}

func TestTPMBinding_VerifyQuoteSendsTheBinding(t *testing.T) {
	server := &quoteServer{}
	_, tpm := quoteBindingsOver(t, server)

	result, err := tpm.VerifyQuote([]byte("attest"), []byte("sig"), []byte("ak"), []byte("nonce"), []byte("binding"), "SHA256-RSAPSS")
	if err != nil {
		t.Fatalf("VerifyQuote: %v", err)
	}
	if result["verified"] != true {
		t.Errorf("result = %v, want verified", result)
	}
	if !bytes.Equal(server.verifyTPM.GetChannelBinding(), []byte("binding")) || !bytes.Equal(server.verifyTPM.GetNonce(), []byte("nonce")) {
		t.Errorf("request = %v, want the nonce and binding as given", server.verifyTPM)
	}
	if got := server.verifyTPM.GetSignatureAlgorithm(); got != "SHA256-RSAPSS" {
		t.Errorf("signature_algorithm = %q, want the scheme as given (#482)", got)
	}
}

func TestTPMBinding_VerifyQuoteReturnsTheRefusal(t *testing.T) {
	server := &quoteServer{err: status.Error(codes.InvalidArgument, "channel binding without a nonce")}
	_, tpm := quoteBindingsOver(t, server)

	_, err := tpm.VerifyQuote([]byte("attest"), nil, nil, nil, []byte("binding"), "")
	var failed *tpmsvc.ErrVerifyQuoteFailed
	if !errors.As(err, &failed) || status.Code(failed.Cause) != codes.InvalidArgument {
		t.Fatalf("err = %v, want ErrVerifyQuoteFailed carrying InvalidArgument", err)
	}
}
