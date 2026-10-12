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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// These tests drive the REST adapter against platformd's own attestation
// router, in process, so a path the adapter invents fails here with the 404
// the daemon would answer (#546). Only the service behind the router is fake.

// fakeAttestationServer hands every request it receives to the test over a
// channel and answers with canned messages, or with err when it is set.
type fakeAttestationServer struct {
	platformv1.UnimplementedAttestationServiceServer
	requests chan proto.Message
	manifest *platformv1.HostManifest
	err      error
}

func newFakeAttestationServer() *fakeAttestationServer {
	return &fakeAttestationServer{
		requests: make(chan proto.Message, 4),
		manifest: &platformv1.HostManifest{
			Id:         "manifest-1",
			HostId:     "host-1",
			MerkleRoot: []byte{0x01, 0x02},
			Version:    "1.0",
		},
	}
}

func (s *fakeAttestationServer) CollectVMAttestation(ctx context.Context, req *platformv1.CollectVMAttestationRequest) (*platformv1.CollectVMAttestationResponse, error) {
	s.requests <- req
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.CollectVMAttestationResponse{
		Attestation: &platformv1.VMAttestation{
			VmId:          req.GetVmId(),
			HostId:        "host-1",
			QuoteData:     []byte("quote"),
			Signature:     []byte("signature"),
			HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
		},
	}, nil
}

func (s *fakeAttestationServer) VerifyAttestationQuote(ctx context.Context, req *platformv1.VerifyAttestationQuoteRequest) (*platformv1.VerifyAttestationQuoteResponse, error) {
	s.requests <- req
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.VerifyAttestationQuoteResponse{Verified: true}, nil
}

func (s *fakeAttestationServer) BuildManifest(ctx context.Context, req *platformv1.BuildManifestRequest) (*platformv1.BuildManifestResponse, error) {
	s.requests <- req
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.BuildManifestResponse{Manifest: s.manifest}, nil
}

func (s *fakeAttestationServer) GetManifest(ctx context.Context, req *platformv1.GetManifestRequest) (*platformv1.GetManifestResponse, error) {
	s.requests <- req
	if s.err != nil {
		return nil, s.err
	}
	if req.GetId() != s.manifest.GetId() {
		return nil, status.Error(codes.NotFound, "manifest not found")
	}
	return &platformv1.GetManifestResponse{Manifest: s.manifest}, nil
}

func (s *fakeAttestationServer) VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.VerifyManifestResponse, error) {
	s.requests <- req
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.VerifyManifestResponse{
		Result: &platformv1.ManifestVerificationResult{
			Status:          platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
			SignatureValid:  true,
			MerkleRootValid: true,
		},
	}, nil
}

// next returns the request the fake received, failing if there was none.
func (s *fakeAttestationServer) next(t *testing.T) proto.Message {
	t.Helper()
	select {
	case req := <-s.requests:
		return req
	default:
		t.Fatal("the attestation service received no request")
		return nil
	}
}

// newRESTAdapterAgainstRouter serves the daemon's attestation router under
// /api/v1, plus the /api/v1/status liveness route Setup probes, and returns a
// REST adapter pointed at it.
func newRESTAdapterAgainstRouter(t *testing.T, server platformv1.AttestationServiceServer) *RESTAdapter {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	router := restattestation.NewAttestationServerRouter(logger, server, response.NewResponseWriter(logger, nil))

	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	router.RegisterRoutes(api)

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	return &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
}

func TestRESTAdapter_SetupProbesTheStatusRoute(t *testing.T) {
	a := newRESTAdapterAgainstRouter(t, newFakeAttestationServer())

	if err := a.Setup(context.Background()); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

func TestRESTAdapter_SetupFailsWhenTheDaemonIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	a := &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
	srv.Close()

	err := a.Setup(context.Background())
	var restErr *RESTAdapterError
	if !errors.As(err, &restErr) {
		t.Fatalf("Setup against a closed listener = %v, want a RESTAdapterError", err)
	}
	if restErr.StatusCode != 0 {
		t.Errorf("status = %d, want 0 for a request that never got an answer", restErr.StatusCode)
	}
}

func TestRESTAdapter_GenerateVMQuoteReachesCollectVM(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	result, err := a.GenerateVMQuote(context.Background(), GenerateVMQuoteOptions{
		VMID:          "vm one",
		Nonce:         []byte("nonce"),
		PCRIndices:    []int{0, 7},
		HashAlgorithm: "sha256",
	})
	if err != nil {
		t.Fatalf("GenerateVMQuote: %v", err)
	}

	req, ok := server.next(t).(*platformv1.CollectVMAttestationRequest)
	if !ok {
		t.Fatalf("the router dispatched %T, want CollectVMAttestationRequest", req)
	}
	if req.GetVmId() != "vm one" {
		t.Errorf("VM ID = %q, want the escaped path segment decoded back to %q", req.GetVmId(), "vm one")
	}
	if !bytes.Equal(req.GetNonce(), []byte("nonce")) {
		t.Errorf("nonce = %q, want %q", req.GetNonce(), "nonce")
	}
	if got := req.GetConfig().GetPcrIndices(); len(got) != 2 || got[0] != 0 || got[1] != 7 {
		t.Errorf("PCR indices = %v, want [0 7]", got)
	}
	if string(result.QuoteData) != "quote" || result.HashAlgorithm != "sha256" {
		t.Errorf("result = %+v, want the service's quote under sha256", result)
	}
}

func TestRESTAdapter_GetVMAttestationReachesCollectVM(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	result, err := a.GetVMAttestation(context.Background(), GetVMAttestationOptions{VMID: "vm-2", Nonce: []byte("n")})
	if err != nil {
		t.Fatalf("GetVMAttestation: %v", err)
	}

	if _, ok := server.next(t).(*platformv1.CollectVMAttestationRequest); !ok {
		t.Fatal("the router did not dispatch CollectVMAttestation")
	}
	if result.VMID != "vm-2" || result.HostID != "host-1" {
		t.Errorf("result = %+v, want VM vm-2 on host-1", result)
	}
}

func TestRESTAdapter_VerifyVMAttestationReachesVerifyQuote(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	result, err := a.VerifyVMAttestation(context.Background(), VerifyVMAttestationOptions{
		AttestationID: "att-1",
		ExpectedNonce: []byte("nonce"),
	})
	if err != nil {
		t.Fatalf("VerifyVMAttestation: %v", err)
	}

	req, ok := server.next(t).(*platformv1.VerifyAttestationQuoteRequest)
	if !ok {
		t.Fatal("the router did not dispatch VerifyAttestationQuote")
	}
	if !bytes.Equal(req.GetExpectedNonce(), []byte("nonce")) {
		t.Errorf("expected nonce = %q, want %q", req.GetExpectedNonce(), "nonce")
	}
	if !result.Valid || result.AttestationID != "att-1" {
		t.Errorf("result = %+v, want a valid verdict for att-1", result)
	}
}

func TestRESTAdapter_BuildManifestReachesBuild(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	result, err := a.BuildManifest(context.Background(), BuildManifestOptions{HostID: "host-1", Version: "1.0"})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	req, ok := server.next(t).(*platformv1.BuildManifestRequest)
	if !ok {
		t.Fatal("the router did not dispatch BuildManifest")
	}
	if req.GetConfig().GetHostId() != "host-1" || !req.GetSign() {
		t.Errorf("request = %v, want a signed build for host-1", req)
	}
	if result.ManifestID != "manifest-1" {
		t.Errorf("manifest ID = %q, want manifest-1", result.ManifestID)
	}
}

func TestRESTAdapter_GetManifestReachesGet(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	result, err := a.GetManifest(context.Background(), GetManifestOptions{ManifestID: "manifest-1"})
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}

	req, ok := server.next(t).(*platformv1.GetManifestRequest)
	if !ok || req.GetId() != "manifest-1" {
		t.Fatalf("the router dispatched %v, want GetManifest for manifest-1", req)
	}
	if result.HostID != "host-1" || result.Version != "1.0" {
		t.Errorf("result = %+v, want host-1 version 1.0", result)
	}
}

func TestRESTAdapter_VerifyManifestSendsTheStoredManifest(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	result, err := a.VerifyManifest(context.Background(), VerifyManifestOptions{
		ManifestID:     "manifest-1",
		ExpectedHostID: "host-1",
	})
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}

	if _, ok := server.next(t).(*platformv1.GetManifestRequest); !ok {
		t.Fatal("VerifyManifest did not fetch the stored manifest first")
	}
	req, ok := server.next(t).(*platformv1.VerifyManifestRequest)
	if !ok {
		t.Fatal("the router did not dispatch VerifyManifest")
	}
	if !proto.Equal(req.GetManifest(), server.manifest) {
		t.Errorf("verified manifest = %v, want the stored one", req.GetManifest())
	}
	if !result.Valid || !result.HostIDMatch {
		t.Errorf("result = %+v, want a valid manifest for host-1", result)
	}
}

func TestRESTAdapter_ServiceErrorsKeepTheHTTPStatus(t *testing.T) {
	server := newFakeAttestationServer()
	server.err = status.Error(codes.InvalidArgument, "nonce is required")
	a := newRESTAdapterAgainstRouter(t, server)

	_, err := a.BuildManifest(context.Background(), BuildManifestOptions{HostID: "host-1"})
	var restErr *RESTAdapterError
	if !errors.As(err, &restErr) {
		t.Fatalf("BuildManifest = %v, want a RESTAdapterError", err)
	}
	if restErr.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", restErr.StatusCode, http.StatusBadRequest)
	}
}

func TestRESTAdapter_VerifyManifestStopsWhenTheManifestIsMissing(t *testing.T) {
	server := newFakeAttestationServer()
	a := newRESTAdapterAgainstRouter(t, server)

	_, err := a.VerifyManifest(context.Background(), VerifyManifestOptions{ManifestID: "absent"})
	var restErr *RESTAdapterError
	if !errors.As(err, &restErr) || restErr.StatusCode != http.StatusNotFound {
		t.Fatalf("VerifyManifest of an unknown manifest = %v, want a 404 RESTAdapterError", err)
	}

	server.next(t)
	select {
	case req := <-server.requests:
		t.Errorf("VerifyManifest went on to send %T after the lookup failed", req)
	default:
	}
}

func TestRESTAdapter_UnavailableServiceIsAnError(t *testing.T) {
	a := newRESTAdapterAgainstRouter(t, nil)

	_, err := a.GetManifest(context.Background(), GetManifestOptions{ManifestID: "manifest-1"})
	var restErr *RESTAdapterError
	if !errors.As(err, &restErr) || restErr.StatusCode < 400 {
		t.Fatalf("GetManifest with no attestation service = %v, want an HTTP error", err)
	}
}

func TestDecodeRESTPayload(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"success envelope", `{"code":200,"success":true,"payload":{"verified":true,"message":"ok"}}`, false},
		{"unknown payload fields are ignored", `{"code":200,"success":true,"payload":{"verified":true,"future":1}}`, false},
		{"not JSON", `<html>`, true},
		{"failure envelope", `{"code":200,"success":false,"error":"refused"}`, true},
		{"payload of the wrong shape", `{"code":200,"success":true,"payload":{"verified":"yes"}}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := &platformv1.VerifyAttestationQuoteResponse{}
			err := decodeRESTPayload("Test", http.StatusOK, []byte(tt.body), out)
			if tt.wantErr {
				var restErr *RESTAdapterError
				if !errors.As(err, &restErr) {
					t.Fatalf("err = %v, want a RESTAdapterError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeRESTPayload: %v", err)
			}
			if !out.GetVerified() {
				t.Errorf("payload = %v, want verified", out)
			}
		})
	}
}

// TestRESTAdapter_UnservedOperationsReportTheGap pins the operations platformd
// serves no REST route for. Each reports ErrRESTNoRoute without touching the
// network; one that starts calling a path must first find that path in
// pkg/webservice/v1/testdata/routes.golden.
func TestRESTAdapter_UnservedOperationsReportTheGap(t *testing.T) {
	ctx := context.Background()
	a := &RESTAdapter{endpoint: "http://unreachable.invalid", client: http.DefaultClient}

	probes := map[string]func() error{
		"GetVMIdentity":           func() error { _, e := a.GetVMIdentity(ctx, GetVMIdentityOptions{}); return e },
		"SignManifest":            func() error { _, e := a.SignManifest(ctx, SignManifestOptions{}); return e },
		"PushAttestation":         func() error { _, e := a.PushAttestation(ctx, PushAttestationOptions{}); return e },
		"PushAttestationBatch":    func() error { _, e := a.PushAttestationBatch(ctx, PushAttestationBatchOptions{}); return e },
		"GetPushStatus":           func() error { _, e := a.GetPushStatus(ctx, GetPushStatusOptions{}); return e },
		"ExtendWorkloadChain":     func() error { _, e := a.ExtendWorkloadChain(ctx, ExtendWorkloadChainOptions{}); return e },
		"GetWorkloadChainHistory": func() error { _, e := a.GetWorkloadChainHistory(ctx, GetWorkloadChainHistoryOptions{}); return e },
		"VerifyWorkloadChain":     func() error { _, e := a.VerifyWorkloadChain(ctx, VerifyWorkloadChainOptions{}); return e },
		"GetWorkloadChainStats":   func() error { _, e := a.GetWorkloadChainStats(ctx, GetWorkloadChainStatsOptions{}); return e },
	}
	for name, call := range probes {
		var noRoute ErrRESTNoRoute
		if err := call(); !errors.As(err, &noRoute) || noRoute.Operation != name {
			t.Errorf("%s = %v, want ErrRESTNoRoute naming it", name, err)
		}
	}
}
