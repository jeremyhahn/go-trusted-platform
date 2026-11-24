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

package ceremony

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingServer answers every CeremonyService call with err, or with a
// canned reply, and records the request it was given.
type recordingServer struct {
	platformv1.UnimplementedCeremonyServiceServer
	err  error
	last proto.Message
}

func (s *recordingServer) Init(_ context.Context, req *platformv1.CeremonyInitRequest) (*platformv1.CeremonyInitResponse, error) {
	s.last = req
	return &platformv1.CeremonyInitResponse{
		CeremonyId:   "cer-1",
		State:        platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS,
		AdminCertPem: "CERT",
		AdminKeyPem:  "KEY",
		SpkiPin:      "PIN",
	}, s.err
}

func (s *recordingServer) Status(_ context.Context, req *platformv1.CeremonyStatusRequest) (*platformv1.CeremonyStatusResponse, error) {
	s.last = req
	return &platformv1.CeremonyStatusResponse{CeremonyId: "cer-1", OfficersEnrolled: 2, OfficersRequired: 5}, s.err
}

func (s *recordingServer) ClaimCertBegin(_ context.Context, req *platformv1.CeremonyClaimCertBeginRequest) (*platformv1.CeremonyClaimCertBeginResponse, error) {
	s.last = req
	return &platformv1.CeremonyClaimCertBeginResponse{Nonce: "n1", ChallengeId: "ch-1"}, s.err
}

func (s *recordingServer) ClaimCertComplete(_ context.Context, req *platformv1.CeremonyClaimCertCompleteRequest) (*platformv1.CeremonyClaimCertCompleteResponse, error) {
	s.last = req
	return &platformv1.CeremonyClaimCertCompleteResponse{CertificatePem: "OFFICER", ChainPem: "CHAIN"}, s.err
}

func (s *recordingServer) ClaimShareBegin(_ context.Context, req *platformv1.CeremonyClaimShareBeginRequest) (*platformv1.CeremonyClaimShareBeginResponse, error) {
	s.last = req
	return &platformv1.CeremonyClaimShareBeginResponse{Nonce: "n2"}, s.err
}

func (s *recordingServer) ClaimShareComplete(_ context.Context, req *platformv1.CeremonyClaimShareCompleteRequest) (*platformv1.CeremonyClaimShareCompleteResponse, error) {
	s.last = req
	return &platformv1.CeremonyClaimShareCompleteResponse{Share: "SHARE", Index: 3}, s.err
}

func (s *recordingServer) SignCSR(_ context.Context, req *platformv1.CeremonySignCSRRequest) (*platformv1.CeremonySignCSRResponse, error) {
	s.last = req
	return &platformv1.CeremonySignCSRResponse{CertificatePem: "SIGNED", ChainPem: "CHAIN"}, s.err
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

func newTestRouter(server platformv1.CeremonyServiceServer) *Router {
	return NewRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil))
}

// mount mounts the ceremony routes under /api/v1.
func mount(ceremonyRouter *Router) *mux.Router {
	router := mux.NewRouter()
	ceremonyRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return router
}

// mountRouter mounts the ceremony routes on server behind a scope check that
// grants every scope, as production mounts them behind its authorizer.
func mountRouter(server platformv1.CeremonyServiceServer) *mux.Router {
	ceremonyRouter := newTestRouter(server)
	ceremonyRouter.SetScopeAuthorizer(everyScope{})
	return mount(ceremonyRouter)
}

// envelope is the standard webservice response wrapper.
type envelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

func serve(router *mux.Router, verb, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(verb, path, strings.NewReader(body)))
	return rec
}

// ceremonyProbe is one route, the scope it requires, the request the
// service must receive and a camelCase field its reply must carry.
type ceremonyProbe struct {
	name    string
	verb    string
	path    string
	body    string
	scope   string
	want    proto.Message
	wantKey string
}

var ceremonyProbes = []ceremonyProbe{
	{
		name: "init", scope: scopeInitialize, verb: http.MethodPost, path: "/api/v1/ceremony/init",
		body: `{"soPin":"1234","userPin":"5678","threshold":"3-of-5","hostname":"ca.example","sans":["ca.example"],"credentialSealStrategy":"tpm","officers":[{"username":"alice","csrPem":"CSR-A"},{"username":"bob","csrPem":"CSR-B"}]}`,
		want: &platformv1.CeremonyInitRequest{
			SoPin: "1234", UserPin: "5678", Threshold: "3-of-5", Hostname: "ca.example",
			Sans: []string{"ca.example"}, CredentialSealStrategy: "tpm",
			Officers: []*platformv1.CeremonyInitOfficer{{Username: "alice", CsrPem: "CSR-A"}, {Username: "bob", CsrPem: "CSR-B"}},
		},
		wantKey: "adminKeyPem",
	},
	{
		name: "status", scope: scopeStatus, verb: http.MethodGet, path: "/api/v1/ceremony/status",
		want:    &platformv1.CeremonyStatusRequest{},
		wantKey: "officersRequired",
	},
	{
		name: "claim cert begin", scope: scopeClaimCert, verb: http.MethodPost, path: "/api/v1/ceremony/claim-cert/begin",
		body: `{"username":"alice","authenticatorType":"CEREMONY_AUTHENTICATOR_TYPE_PIV","slot":"9a","credentialId":"cred-1"}`,
		want: &platformv1.CeremonyClaimCertBeginRequest{
			Username: "alice", AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV,
			Slot: "9a", CredentialId: "cred-1",
		},
		wantKey: "challengeId",
	},
	{
		name: "claim cert complete", scope: scopeClaimCert, verb: http.MethodPost, path: "/api/v1/ceremony/claim-cert/complete",
		body:    `{"username":"alice","nonce":"n1","signature":"sig"}`,
		want:    &platformv1.CeremonyClaimCertCompleteRequest{Username: "alice", Nonce: "n1", Signature: "sig"},
		wantKey: "certificatePem",
	},
	{
		name: "claim share begin", scope: scopeClaimShareBegin, verb: http.MethodPost, path: "/api/v1/ceremony/claim-share/begin",
		body:    `{"username":"alice"}`,
		want:    &platformv1.CeremonyClaimShareBeginRequest{Username: "alice"},
		wantKey: "nonce",
	},
	{
		name: "claim share complete", scope: scopeClaimShareComplete, verb: http.MethodPost, path: "/api/v1/ceremony/claim-share/complete",
		body:    `{"username":"alice","nonce":"n2","signature":"c2ln"}`,
		want:    &platformv1.CeremonyClaimShareCompleteRequest{Username: "alice", Nonce: "n2", Signature: []byte("sig")},
		wantKey: "share",
	},
	{
		name: "sign csr", scope: scopeSignCSR, verb: http.MethodPost, path: "/api/v1/ceremony/sign-csr",
		body: `{"username":"alice","soPin":"1234","csrPem":"CSR","role":"CEREMONY_OFFICER_ROLE_ADMIN"}`,
		want: &platformv1.CeremonySignCSRRequest{
			Username: "alice", SoPin: "1234", CsrPem: "CSR", Role: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
		},
		wantKey: "chainPem",
	},
}

func TestCeremonyRouterServesEveryOperation(t *testing.T) {
	if len(platformv1.CeremonyService_ServiceDesc.Methods) != len(ceremonyProbes) {
		t.Fatalf("CeremonyService has %d methods, the test probes %d",
			len(platformv1.CeremonyService_ServiceDesc.Methods), len(ceremonyProbes))
	}
	for _, probe := range ceremonyProbes {
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serve(mountRouter(server), probe.verb, probe.path, probe.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("code = %d, want 200, body %s", rec.Code, rec.Body)
			}
			var body envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if !body.Success {
				t.Fatalf("envelope = %+v", body)
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(body.Payload, &payload); err != nil {
				t.Fatalf("decode payload %s: %v", body.Payload, err)
			}
			if _, ok := payload[probe.wantKey]; !ok {
				t.Fatalf("payload %s has no %q", body.Payload, probe.wantKey)
			}
			if !proto.Equal(server.last, probe.want) {
				t.Fatalf("service got %v, want %v", server.last, probe.want)
			}
		})
	}
}

// TestCeremonyRouterMapsServiceRefusals checks that a refused call reaches
// the client as the matching HTTP status on every route.
func TestCeremonyRouterMapsServiceRefusals(t *testing.T) {
	refusals := map[codes.Code]int{
		codes.Unavailable:        http.StatusServiceUnavailable,
		codes.InvalidArgument:    http.StatusBadRequest,
		codes.PermissionDenied:   http.StatusForbidden,
		codes.FailedPrecondition: http.StatusConflict,
	}
	for code, want := range refusals {
		for _, probe := range ceremonyProbes {
			server := &recordingServer{err: status.Error(code, "refused")}
			rec := serve(mountRouter(server), probe.verb, probe.path, probe.body)
			if rec.Code != want {
				t.Errorf("%s refused with %s: code = %d, want %d", probe.name, code, rec.Code, want)
			}
		}
	}
}

func TestCeremonyRouterWithoutAServiceIsUnavailable(t *testing.T) {
	for _, probe := range ceremonyProbes {
		rec := serve(mountRouter(nil), probe.verb, probe.path, probe.body)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: code = %d, want 503", probe.name, rec.Code)
		}
	}
}

func TestCeremonyRouterRefusesBadBodies(t *testing.T) {
	for _, probe := range ceremonyProbes {
		if probe.verb != http.MethodPost {
			continue
		}
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serve(mountRouter(server), probe.verb, probe.path, `{"username":`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400, body %s", rec.Code, rec.Body)
			}
			if server.last != nil {
				t.Fatalf("the service was called with %v", server.last)
			}
		})
	}
}

// TestCeremonyRouterSetsNoStore checks that no ceremony answer is cached:
// Init carries the admin private key and ClaimShareComplete a Shamir share,
// and an error answer is no more cacheable than a success.
func TestCeremonyRouterSetsNoStore(t *testing.T) {
	for _, probe := range ceremonyProbes {
		answers := map[string]*httptest.ResponseRecorder{
			"success":       serve(mountRouter(&recordingServer{}), probe.verb, probe.path, probe.body),
			"refusal":       serve(mountRouter(&recordingServer{err: status.Error(codes.Unavailable, "down")}), probe.verb, probe.path, probe.body),
			"no service":    serve(mountRouter(nil), probe.verb, probe.path, probe.body),
			"scope refusal": serve(scopedRouter(&recordingServer{}, "none"), probe.verb, probe.path, probe.body),
		}
		if probe.verb == http.MethodPost {
			answers["bad body"] = serve(mountRouter(&recordingServer{}), probe.verb, probe.path, `{"username":`)
		}
		for kind, rec := range answers {
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("%s %s (code %d): Cache-Control = %q, want no-store", probe.name, kind, rec.Code, got)
			}
		}
	}
}

// grantingAuthorizer lets a request through only when the route asks for
// the one scope it grants.
type grantingAuthorizer struct {
	granted string
}

func (a grantingAuthorizer) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != a.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// everyScope is a scope authorizer that grants every scope.
type everyScope struct{}

func (everyScope) RequireScope(string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

func scopedRouter(server platformv1.CeremonyServiceServer, granted string) *mux.Router {
	ceremonyRouter := newTestRouter(server)
	ceremonyRouter.SetScopeAuthorizer(grantingAuthorizer{granted: granted})
	return mount(ceremonyRouter)
}

// TestCeremonyRouterRequiresEachRouteScope checks that every route asks for
// its own scope: the right one reaches the service, any other is refused
// before the service is called.
func TestCeremonyRouterRequiresEachRouteScope(t *testing.T) {
	scopes := map[string]string{
		"init":                 "ceremony:initialize",
		"status":               "ceremony:status",
		"claim cert begin":     "ceremony:claim_cert",
		"claim cert complete":  "ceremony:claim_cert",
		"claim share begin":    "ceremony:claim_share_begin",
		"claim share complete": "ceremony:claim_share_complete",
		"sign csr":             "ceremony:sign_csr",
	}
	all := []string{
		"ceremony:initialize", "ceremony:status", "ceremony:claim_cert",
		"ceremony:claim_share_begin", "ceremony:claim_share_complete", "ceremony:sign_csr",
	}
	for _, probe := range ceremonyProbes {
		if probe.scope != scopes[probe.name] {
			t.Errorf("%s: scope = %q, want %q", probe.name, probe.scope, scopes[probe.name])
		}
		for _, granted := range all {
			server := &recordingServer{}
			rec := serve(scopedRouter(server, granted), probe.verb, probe.path, probe.body)
			if granted == scopes[probe.name] {
				if rec.Code != http.StatusOK || server.last == nil {
					t.Errorf("%s with %s: code = %d, service called = %v; want 200 and a call",
						probe.name, granted, rec.Code, server.last != nil)
				}
				continue
			}
			if rec.Code != http.StatusForbidden || server.last != nil {
				t.Errorf("%s with %s: code = %d, service called = %v; want 403 and no call",
					probe.name, granted, rec.Code, server.last != nil)
			}
		}
	}
}

// TestCeremonyRouterRefusesEveryRouteWithoutAScopeAuthorizer checks that the
// routes fail closed when no scope authorizer is set (the legacy JWT handler,
// whose role-only sessions carry no ceremony scope): every route answers 403
// before the service is called, as scopeRouteGuard does (#1990, #2158 Codex).
func TestCeremonyRouterRefusesEveryRouteWithoutAScopeAuthorizer(t *testing.T) {
	for _, probe := range ceremonyProbes {
		server := &recordingServer{}
		rec := serve(mount(newTestRouter(server)), probe.verb, probe.path, probe.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, want %d", probe.name, rec.Code, http.StatusForbidden)
		}
		if server.last != nil {
			t.Errorf("%s: the service was called without a scope authorizer", probe.name)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", probe.name, got)
		}
	}
}

// TestCeremonyRouterKeepsSecretsOutOfTheLog checks that the admin private key
// Init returns and the Shamir share ClaimShareComplete returns never reach a
// debug-level log, whatever the Accept header asks for (#2158 Codex).
func TestCeremonyRouterKeepsSecretsOutOfTheLog(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewLogger(slog.LevelDebug, &buf)
	r := NewRouter(logger, &recordingServer{}, response.NewResponseWriter(logger, nil))
	r.SetScopeAuthorizer(everyScope{})
	router := mount(r)
	for _, probe := range ceremonyProbes {
		if probe.name != "init" && probe.name != "claim share complete" {
			continue
		}
		for _, accept := range []string{"", "application/yaml"} {
			req := httptest.NewRequest(probe.verb, probe.path, strings.NewReader(probe.body))
			if accept != "" {
				req.Header.Set("Accept", accept)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s (Accept %q): code = %d, want 200", probe.name, accept, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), probe.wantKey) {
				t.Errorf("%s (Accept %q): body %q lacks %q", probe.name, accept, rec.Body.String(), probe.wantKey)
			}
		}
	}
	logged := buf.String()
	for _, secret := range []string{"adminKeyPem", `"KEY"`, "SHARE"} {
		if strings.Contains(logged, secret) {
			t.Errorf("the log carries %s:\n%s", secret, logged)
		}
	}
}
