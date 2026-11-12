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
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingAttestationServer records the context and request of the last
// call, answers with err when it is set, and otherwise echoes the request
// fields the router is responsible for into its response, so a test sees
// both what the router decoded and what it rendered.
type recordingAttestationServer struct {
	platformv1.UnimplementedAttestationServiceServer
	err error
	ctx context.Context
	req proto.Message
}

func (s *recordingAttestationServer) record(ctx context.Context, req proto.Message) error {
	s.ctx = ctx
	s.req = req
	return s.err
}

func (s *recordingAttestationServer) GetManifest(ctx context.Context, req *platformv1.GetManifestRequest) (*platformv1.GetManifestResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.GetManifestResponse{Manifest: &platformv1.HostManifest{Id: req.GetId()}}, nil
}

func (s *recordingAttestationServer) ListManifests(ctx context.Context, req *platformv1.ListManifestsRequest) (*platformv1.ListManifestsResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.ListManifestsResponse{Manifests: []*platformv1.HostManifest{{Id: "m-a"}, {Id: "m-b"}}}, nil
}

func (s *recordingAttestationServer) BuildManifest(ctx context.Context, req *platformv1.BuildManifestRequest) (*platformv1.BuildManifestResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.BuildManifestResponse{Manifest: &platformv1.HostManifest{Id: "m-built", Nonce: req.GetNonce()}}, nil
}

func (s *recordingAttestationServer) VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.VerifyManifestResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.VerifyManifestResponse{Result: &platformv1.ManifestVerificationResult{
		Status: platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
	}}, nil
}

func (s *recordingAttestationServer) DeleteManifest(ctx context.Context, req *platformv1.DeleteManifestRequest) (*platformv1.DeleteManifestResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteManifestResponse{}, nil
}

func (s *recordingAttestationServer) GetAttestationQuote(ctx context.Context, req *platformv1.GetAttestationQuoteRequest) (*platformv1.GetAttestationQuoteResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.GetAttestationQuoteResponse{Quote: &platformv1.AttestationQuote{Nonce: req.GetNonce()}}, nil
}

func (s *recordingAttestationServer) VerifyAttestationQuote(ctx context.Context, req *platformv1.VerifyAttestationQuoteRequest) (*platformv1.VerifyAttestationQuoteResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.VerifyAttestationQuoteResponse{Verified: true}, nil
}

func (s *recordingAttestationServer) CollectHostAttestation(ctx context.Context, req *platformv1.CollectHostAttestationRequest) (*platformv1.CollectHostAttestationResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.CollectHostAttestationResponse{Attestation: &platformv1.HostAttestation{Nonce: req.GetNonce()}}, nil
}

func (s *recordingAttestationServer) CollectVMAttestation(ctx context.Context, req *platformv1.CollectVMAttestationRequest) (*platformv1.CollectVMAttestationResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.CollectVMAttestationResponse{Attestation: &platformv1.VMAttestation{VmId: req.GetVmId()}}, nil
}

func (s *recordingAttestationServer) CollectContainerAttestation(ctx context.Context, req *platformv1.CollectContainerAttestationRequest) (*platformv1.CollectContainerAttestationResponse, error) {
	if err := s.record(ctx, req); err != nil {
		return nil, err
	}
	return &platformv1.CollectContainerAttestationResponse{Attestation: &platformv1.ContainerAttestation{ContainerId: req.GetContainerId()}}, nil
}

// mountAllAttestationRoutes mounts both route sets the way the daemon does,
// with the quote routes open (nil gate, nil operator chain).
func mountAllAttestationRoutes(server platformv1.AttestationServiceServer) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	r := NewAttestationServerRouter(logger, server, response.NewResponseWriter(logger, nil))
	parent := mux.NewRouter()
	api := parent.PathPrefix("/api/v1").Subrouter()
	r.RegisterRoutes(api)
	r.RegisterQuoteRoutes(api, nil, nil)
	return parent
}

// attestationRoute is one REST route of the server router, with the request
// a client sends and what the router must hand the server and render back.
type attestationRoute struct {
	name, method, path, body string
	status                   int
	check                    func(t *testing.T, req proto.Message, payload map[string]any)
}

// The nonce AQID is base64 for {1, 2, 3}; YWstcGVt is base64 for "ak-pem".
var attestationRoutes = []attestationRoute{
	{
		name: "get manifest", method: http.MethodGet, path: "/api/v1/attestation/manifests/m-1", status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			assert.Equal(t, "m-1", req.(*platformv1.GetManifestRequest).GetId())
			assert.Equal(t, "m-1", payload["manifest"].(map[string]any)["id"])
		},
	},
	{
		name: "list manifests", method: http.MethodGet, path: "/api/v1/attestation/manifests", status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			assert.IsType(t, &platformv1.ListManifestsRequest{}, req)
			manifests := payload["manifests"].([]any)
			require.Len(t, manifests, 2)
			assert.Equal(t, "m-b", manifests[1].(map[string]any)["id"])
		},
	},
	{
		// The query carries the page and the host filter (#1686).
		name: "list manifests paged", method: http.MethodGet,
		path: "/api/v1/attestation/manifests?host_id=h1&limit=10&offset=20", status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			got := req.(*platformv1.ListManifestsRequest)
			assert.Equal(t, "h1", got.GetHostId())
			assert.Equal(t, uint32(10), got.GetLimit())
			assert.Equal(t, uint32(20), got.GetOffset())
		},
	},
	{
		name: "build manifest", method: http.MethodPost, path: "/api/v1/attestation/manifests/build",
		body: `{"nonce":"AQID","vmIds":["vm-1"],"sign":true}`, status: http.StatusCreated,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			build := req.(*platformv1.BuildManifestRequest)
			assert.Equal(t, []byte{1, 2, 3}, build.GetNonce())
			assert.Equal(t, []string{"vm-1"}, build.GetVmIds())
			assert.True(t, build.GetSign())
			manifest := payload["manifest"].(map[string]any)
			assert.Equal(t, "m-built", manifest["id"])
			assert.Equal(t, "AQID", manifest["nonce"])
		},
	},
	{
		name: "verify manifest", method: http.MethodPost, path: "/api/v1/attestation/manifests/verify",
		body: `{"manifest":{"id":"m-2"},"expectedNonce":"AQID"}`, status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			verify := req.(*platformv1.VerifyManifestRequest)
			assert.Equal(t, "m-2", verify.GetManifest().GetId())
			assert.Equal(t, []byte{1, 2, 3}, verify.GetExpectedNonce())
			assert.Equal(t, "MANIFEST_VERIFICATION_STATUS_VERIFIED", payload["result"].(map[string]any)["status"])
		},
	},
	{
		name: "delete manifest", method: http.MethodDelete, path: "/api/v1/attestation/manifests/m-3", status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, _ map[string]any) {
			assert.Equal(t, "m-3", req.(*platformv1.DeleteManifestRequest).GetId())
		},
	},
	{
		name: "get quote", method: http.MethodPost, path: "/api/v1/attestation/quote",
		body: `{"nonce":"AQID"}`, status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			assert.Equal(t, []byte{1, 2, 3}, req.(*platformv1.GetAttestationQuoteRequest).GetNonce())
			assert.Equal(t, "AQID", payload["quote"].(map[string]any)["nonce"])
		},
	},
	{
		name: "verify quote", method: http.MethodPost, path: "/api/v1/attestation/quote/verify",
		body: `{"quote":{"nonce":"AQID"},"akPublicKeyPem":"YWstcGVt","expectedNonce":"AQID"}`, status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			verify := req.(*platformv1.VerifyAttestationQuoteRequest)
			assert.Equal(t, []byte{1, 2, 3}, verify.GetQuote().GetNonce())
			assert.Equal(t, []byte("ak-pem"), verify.GetAkPublicKeyPem())
			assert.Equal(t, []byte{1, 2, 3}, verify.GetExpectedNonce())
			assert.Equal(t, true, payload["verified"])
		},
	},
	{
		name: "collect host", method: http.MethodPost, path: "/api/v1/attestation/host",
		body: `{"nonce":"AQID"}`, status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			assert.Equal(t, []byte{1, 2, 3}, req.(*platformv1.CollectHostAttestationRequest).GetNonce())
			assert.Equal(t, "AQID", payload["attestation"].(map[string]any)["nonce"])
		},
	},
	{
		// The path names the VM; a vmId in the body must not override it.
		name: "collect vm", method: http.MethodPost, path: "/api/v1/attestation/vm/vm-7",
		body: `{"vmId":"vm-from-body","nonce":"AQID"}`, status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			vm := req.(*platformv1.CollectVMAttestationRequest)
			assert.Equal(t, "vm-7", vm.GetVmId())
			assert.Equal(t, []byte{1, 2, 3}, vm.GetNonce())
			assert.Equal(t, "vm-7", payload["attestation"].(map[string]any)["vmId"])
		},
	},
	{
		// The path names the container; a containerId in the body must not override it.
		name: "collect container", method: http.MethodPost, path: "/api/v1/attestation/container/c-9",
		body: `{"containerId":"c-from-body"}`, status: http.StatusOK,
		check: func(t *testing.T, req proto.Message, payload map[string]any) {
			assert.Equal(t, "c-9", req.(*platformv1.CollectContainerAttestationRequest).GetContainerId())
			assert.Equal(t, "c-9", payload["attestation"].(map[string]any)["containerId"])
		},
	},
}

func serveAttestationRoute(router http.Handler, rt attestationRoute, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAttestationServerRouter_HandlersDelegateToServer(t *testing.T) {
	for _, rt := range attestationRoutes {
		t.Run(rt.name, func(t *testing.T) {
			server := &recordingAttestationServer{}
			rec := serveAttestationRoute(mountAllAttestationRoutes(server), rt, rt.body)
			require.Equal(t, rt.status, rec.Code, rec.Body.String())
			require.NotNil(t, server.req, "the server was not called")
			env := decodeEnvelope(t, rec)
			assert.Equal(t, true, env["success"])
			rt.check(t, server.req, env["payload"].(map[string]any))
		})
	}
}

func TestAttestationServerRouter_ServerErrorKeepsItsStatus(t *testing.T) {
	for _, rt := range attestationRoutes {
		t.Run(rt.name, func(t *testing.T) {
			server := &recordingAttestationServer{err: status.Error(codes.NotFound, "no such attestation subject")}
			rec := serveAttestationRoute(mountAllAttestationRoutes(server), rt, rt.body)
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "no such attestation subject")
			assert.NotNil(t, server.req, "the server was called")
		})
	}
}

func TestAttestationServerRouter_MalformedBodyIs400(t *testing.T) {
	for _, rt := range attestationRoutes {
		if rt.body == "" {
			continue // the route takes no body
		}
		t.Run(rt.name, func(t *testing.T) {
			server := &recordingAttestationServer{}
			rec := serveAttestationRoute(mountAllAttestationRoutes(server), rt, `{"nonce":`)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, server.req, "the server is not called with an undecoded request")
		})
	}
}

func TestAttestationServerRouter_NilServerIs503OnEveryRoute(t *testing.T) {
	router := mountAllAttestationRoutes(nil)
	for _, rt := range attestationRoutes {
		t.Run(rt.name, func(t *testing.T) {
			rec := serveAttestationRoute(router, rt, rt.body)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "attestation service is not available")
		})
	}
}

// The quote-producing routes bind the quote to the connection the request
// arrived on (#482): the server must receive that connection's TLS state.
func TestAttestationServerRouter_QuoteRoutesPassTheConnectionTLS(t *testing.T) {
	for _, path := range []string{"/api/v1/attestation/quote", "/api/v1/attestation/host"} {
		t.Run(path, func(t *testing.T) {
			server := &recordingAttestationServer{}
			state := &tls.ConnectionState{ServerName: "node-1.example"}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"nonce":"AQID"}`))
			req.TLS = state
			rec := httptest.NewRecorder()
			mountAllAttestationRoutes(server).ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			got, transport, ok := channelbind.ConnectionTLS(server.ctx)
			require.True(t, ok, "no connection recorded in the server context")
			assert.Same(t, state, got)
			assert.Equal(t, channelbind.TransportREST, transport)
		})
	}
}

// TestAttestationServerRouter_CollectVMDecodesTheEscapedPathSegment requires
// the VM named by a percent-encoded path segment to reach the server decoded,
// with the quote configuration from the body alongside it.
func TestAttestationServerRouter_CollectVMDecodesTheEscapedPathSegment(t *testing.T) {
	server := &recordingAttestationServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/vm/vm%20one",
		strings.NewReader(`{"nonce":"AQID","config":{"pcrIndices":[0,7]}}`))
	rec := httptest.NewRecorder()
	mountAllAttestationRoutes(server).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	vm, ok := server.req.(*platformv1.CollectVMAttestationRequest)
	require.True(t, ok, "the router dispatched %T, want CollectVMAttestationRequest", server.req)
	assert.Equal(t, "vm one", vm.GetVmId())
	assert.Equal(t, []byte{1, 2, 3}, vm.GetNonce())
	assert.Equal(t, []uint32{0, 7}, vm.GetConfig().GetPcrIndices())
}
