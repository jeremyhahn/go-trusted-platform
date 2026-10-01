// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// memStore is an in-memory gwstate.Store recording what the handler
// actually persisted, so a test can assert that a rejected request wrote
// nothing at all rather than only asserting on the status code.
type memStore struct {
	snaps map[string]*gwstate.Snapshot
	puts  int
}

func newMemStore() *memStore {
	return &memStore{snaps: map[string]*gwstate.Snapshot{}}
}

func (m *memStore) Put(snap *gwstate.Snapshot) error {
	m.puts++
	m.snaps[snap.GatewayID] = snap
	return nil
}

func (m *memStore) Get(id string) (*gwstate.Snapshot, error) {
	snap, ok := m.snaps[id]
	if !ok {
		return nil, gwstate.ErrSnapshotNotFound{GatewayID: id}
	}
	return snap, nil
}

func (m *memStore) List() ([]*gwstate.Snapshot, error) {
	out := make([]*gwstate.Snapshot, 0, len(m.snaps))
	for _, s := range m.snaps {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) Delete(id string) error {
	delete(m.snaps, id)
	return nil
}

// recordingConfigSource reports whether the handler reached the config
// source, which is what proves an unauthorized desired-config request
// was refused before any fleet intent was read.
type recordingConfigSource struct {
	calls   int
	lastID  string
	payload *gwstate.DesiredConfig
}

func (r *recordingConfigSource) DesiredConfig(gatewayID string) (*gwstate.DesiredConfig, error) {
	r.calls++
	r.lastID = gatewayID
	return r.payload, nil
}

func newControlPlane(store gwstate.Store, cfg DesiredConfigSource) *ControlPlane {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	return NewControlPlane(logger, store, cfg, response.NewResponseWriter(logger, nil))
}

// controlPlaneRouter mounts BOTH halves of the control-plane surface, the
// way v1Router.gatewayRoutes does, so the existing behavioural tests keep
// exercising the routes they were written for. The halves differ in which
// router production hands them — the operator half gets the gated one —
// and that division is asserted by registeredControlPlanePaths below
// rather than by this helper.
func controlPlaneRouter(cp *ControlPlane) *mux.Router {
	parent := mux.NewRouter()
	sub := parent.PathPrefix("/api/v1").Subrouter()
	cp.RegisterGatewayFacingRoutes(sub)
	cp.RegisterRoutes(sub)
	return parent
}

// registeredControlPlanePaths returns the "METHOD /path" set one
// registration method installs, so the split can be asserted by its effect
// on the route table rather than by reading the source.
func registeredControlPlanePaths(register func(*mux.Router)) map[string]bool {
	router := mux.NewRouter()
	register(router.PathPrefix("/api/v1").Subrouter())

	out := map[string]bool{}
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			out[m+" "+path] = true
		}
		return nil
	})
	return out
}

// TestRegisterRoutes_OperatorHalfIsExactlyTheStateSurface pins which routes
// take the caller's role gate. A gatewayd-facing route that drifted in here
// would start demanding a bearer token from a caller whose credential is a
// certificate, and every gateway in the fleet would stop reporting.
func TestRegisterRoutes_OperatorHalfIsExactlyTheStateSurface(t *testing.T) {
	cp := newControlPlane(nil, nil)

	assert.Equal(t, map[string]bool{
		"GET /api/v1/gateway/state":         true,
		"GET /api/v1/gateway/state/{id}":    true,
		"DELETE /api/v1/gateway/state/{id}": true,
	}, registeredControlPlanePaths(cp.RegisterRoutes))
}

// TestRegisterGatewayFacingRoutes_IsExactlyTheSelfAuthenticatingPair pins
// the other half. An operator route that drifted in here would be published
// to anyone holding any gateway certificate — including the fleet-wide list,
// which is precisely what no single gateway's certificate should authorise.
func TestRegisterGatewayFacingRoutes_IsExactlyTheSelfAuthenticatingPair(t *testing.T) {
	cp := newControlPlane(nil, nil)

	assert.Equal(t, map[string]bool{
		"POST /api/v1/gateway/telemetry":          true,
		"GET /api/v1/gateway/desired-config/{id}": true,
	}, registeredControlPlanePaths(cp.RegisterGatewayFacingRoutes))
}

// TestControlPlaneHalvesAreDisjointAndCoverTheSurface proves the split lost
// nothing: together the two methods register every route the control plane
// had before it was divided, and no route appears in both.
func TestControlPlaneHalvesAreDisjointAndCoverTheSurface(t *testing.T) {
	cp := newControlPlane(nil, nil)

	operator := registeredControlPlanePaths(cp.RegisterRoutes)
	gateway := registeredControlPlanePaths(cp.RegisterGatewayFacingRoutes)

	for route := range operator {
		assert.False(t, gateway[route], "route is in both halves: %s", route)
	}
	assert.Len(t, operator, 3)
	assert.Len(t, gateway, 2)
}

// withClientCert attaches a verified TLS chain whose leaf carries the
// given Common Name — the shape the TLS stack produces once the peer's
// certificate has chained to the listener's ClientCAs.
func withClientCert(r *http.Request, commonName string) *http.Request {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: commonName}}
	r.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf},
		VerifiedChains:    [][]*x509.Certificate{{leaf}},
	}
	return r
}

// withUnverifiedClientCert attaches a peer certificate that never
// produced a verified chain. This is the substitution the binding must
// refuse: PeerCertificates is attacker-supplied, VerifiedChains is not.
func withUnverifiedClientCert(r *http.Request, commonName string) *http.Request {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: commonName}}
	r.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf},
	}
	return r
}

func telemetryRequest(t *testing.T, gatewayID string) *http.Request {
	t.Helper()
	body, err := json.Marshal(&gwstate.Snapshot{GatewayID: gatewayID, Hostname: "gw.example.com"})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/telemetry", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestPostTelemetry_AcceptsOwnGatewayID is the positive path: a gateway
// whose certificate CN matches the body's gateway_id is persisted.
func TestPostTelemetry_AcceptsOwnGatewayID(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "node-01"), "node-01"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if store.puts != 1 {
		t.Fatalf("store.puts = %d, want 1", store.puts)
	}
	if _, ok := store.snaps["node-01"]; !ok {
		t.Fatal("snapshot for node-01 was not persisted")
	}
}

// TestPostTelemetry_RejectsOtherGatewayID is the finding this binding
// exists for: a gateway holding a perfectly valid certificate must not
// be able to overwrite another gateway's state by naming it in the body.
func TestPostTelemetry_RejectsOtherGatewayID(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "node-02"), "node-01"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0 — a refused request must persist nothing", store.puts)
	}
	if _, ok := store.snaps["node-02"]; ok {
		t.Fatal("node-01's certificate wrote node-02's snapshot")
	}
}

// TestPostTelemetry_RejectsWithoutClientCert covers the unauthenticated
// caller: no certificate means no gateway identity, so the request is
// refused rather than trusting the body.
func TestPostTelemetry_RejectsWithoutClientCert(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, telemetryRequest(t, "node-01"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestPostTelemetry_RejectsUnverifiedClientCert proves the binding reads
// VerifiedChains and not PeerCertificates. A caller can put any CN in a
// self-signed certificate; only a chain the TLS stack verified against
// the configured ClientCAs is an identity.
func TestPostTelemetry_RejectsUnverifiedClientCert(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withUnverifiedClientCert(telemetryRequest(t, "node-01"), "node-01"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestPostTelemetry_RejectsNamelessCommonName covers certificates that
// verified but name no principal: there is nothing to bind to, so they
// must not fall through to trusting the body. Both an absent CN and a
// whitespace-only one are refused, by different rules in
// gatewayPrincipal — the empty check and the verbatim check.
func TestPostTelemetry_RejectsNamelessCommonName(t *testing.T) {
	cases := map[string]string{
		"absent common name":          "",
		"whitespace-only common name": "   ",
	}
	for name, cn := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			router := controlPlaneRouter(newControlPlane(store, nil))

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "node-01"), cn))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if store.puts != 0 {
				t.Fatalf("store.puts = %d, want 0", store.puts)
			}
		})
	}
}

// TestPostTelemetry_MissingGatewayIDStillRejected keeps the empty-ID 400
// from becoming an authorization bypass: an omitted gateway_id must not
// be silently filled in from the certificate.
func TestPostTelemetry_MissingGatewayIDStillRejected(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, ""), "node-01"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestPostTelemetry_BindingIsCaseSensitive pins the exact-match rule. A
// case-insensitive comparison would make "NODE-02" and "node-02" the
// same principal and reopen the substitution this check closes.
func TestPostTelemetry_BindingIsCaseSensitive(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "NODE-01"), "node-01"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// sampleDesiredConfig is a valid typed document for the pull-side tests.
func sampleDesiredConfig() *gwstate.DesiredConfig {
	return &gwstate.DesiredConfig{
		Version: "rev-7",
		LoadBalancer: &gwstate.DesiredLoadBalancer{VIPs: []gwstate.DesiredVIP{{
			Address: "10.0.200.10", Port: 443, Protocol: "tcp",
			Backends: []gwstate.DesiredBackend{{Address: "10.0.100.11", Port: 8443}},
		}}},
		NAT: &gwstate.DesiredNAT{SNATInternalCIDR: "10.0.100.0/24"},
	}
}

// TestGetDesiredConfig_AcceptsOwnGatewayID is the positive path for the
// pull side: the typed document round-trips through the envelope with
// the gateway id filled in.
func TestGetDesiredConfig_AcceptsOwnGatewayID(t *testing.T) {
	src := &recordingConfigSource{payload: sampleDesiredConfig()}
	router := controlPlaneRouter(newControlPlane(nil, src))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	router.ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if src.calls != 1 || src.lastID != "node-01" {
		t.Fatalf("DesiredConfig calls = %d, lastID = %q; want 1, \"node-01\"", src.calls, src.lastID)
	}
	var envelope struct {
		Payload struct {
			GatewayID string          `json:"gateway_id"`
			Config    json.RawMessage `json:"config"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	got, err := gwstate.DecodeDesiredConfig(envelope.Payload.Config)
	if err != nil {
		t.Fatalf("the served document must decode as the wire contract: %v", err)
	}
	if got.GatewayID != "node-01" || got.Version != "rev-7" || got.LoadBalancer == nil || len(got.LoadBalancer.VIPs) != 1 || got.NAT == nil {
		t.Fatalf("round trip lost content: %+v", got)
	}
}

// TestGetDesiredConfig_RefusesAnInvalidDocument: a control plane serving
// intent the gateway would refuse learns it here, as a 500 on its own
// log, not from a gateway that never converges.
func TestGetDesiredConfig_RefusesAnInvalidDocument(t *testing.T) {
	bad := sampleDesiredConfig()
	bad.NAT.SNATInternalCIDR = "not-a-prefix"
	router := controlPlaneRouter(newControlPlane(nil, &recordingConfigSource{payload: bad}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	router.ServeHTTP(rec, withClientCert(req, "node-01"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestGetDesiredConfig_NilDocumentIsEmpty: a source with nothing to say
// serves an empty document, which the gateway applies as a no-op.
func TestGetDesiredConfig_NilDocumentIsEmpty(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, &recordingConfigSource{}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	router.ServeHTTP(rec, withClientCert(req, "node-01"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestGetDesiredConfig_RejectsOtherGatewayID is the read half of the
// same finding: desired configuration carries a gateway's intended BGP
// ASN, IPAM pools and PXE posture, so an unbound {id} would let one
// gateway enumerate the control plane's intent for the whole fleet.
func TestGetDesiredConfig_RejectsOtherGatewayID(t *testing.T) {
	src := &recordingConfigSource{payload: sampleDesiredConfig()}
	router := controlPlaneRouter(newControlPlane(nil, src))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-02", nil)
	router.ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if src.calls != 0 {
		t.Fatalf("DesiredConfig calls = %d, want 0 — a refused request must not read fleet intent", src.calls)
	}
}

// TestGetDesiredConfig_RejectsWithoutClientCert covers the
// unauthenticated pull.
func TestGetDesiredConfig_RejectsWithoutClientCert(t *testing.T) {
	src := &recordingConfigSource{}
	router := controlPlaneRouter(newControlPlane(nil, src))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if src.calls != 0 {
		t.Fatalf("DesiredConfig calls = %d, want 0", src.calls)
	}
}

// TestGetDesiredConfig_RejectsUnverifiedClientCert mirrors the telemetry
// case: an unverified peer certificate is not an identity.
func TestGetDesiredConfig_RejectsUnverifiedClientCert(t *testing.T) {
	src := &recordingConfigSource{}
	router := controlPlaneRouter(newControlPlane(nil, src))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	router.ServeHTTP(rec, withUnverifiedClientCert(req, "node-01"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if src.calls != 0 {
		t.Fatalf("DesiredConfig calls = %d, want 0", src.calls)
	}
}

// TestControlPlane_AuthorizationPrecedesConfiguration proves the refusal
// is not an accident of wiring: an unauthenticated caller is turned away
// even when the handler has no store or config source to serve from, so
// the 503/500 not-configured envelope cannot be used to probe the route.
func TestControlPlane_AuthorizationPrecedesConfiguration(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, nil))

	cases := []struct {
		name string
		req  *http.Request
	}{
		{"telemetry", telemetryRequest(t, "node-01")},
		{"desired-config", httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, tc.req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

// failingStore reports a persistence failure so the handler's 500 path
// is exercised with a real error rather than left unproven.
type failingStore struct{ memStore }

func (f *failingStore) Put(*gwstate.Snapshot) error { return errStorePut }

var errStorePut = errors.New("gateway/state: disk full")

// failingConfigSource reports a lookup failure on the pull side.
type failingConfigSource struct{}

func (failingConfigSource) DesiredConfig(string) (*gwstate.DesiredConfig, error) {
	return nil, errConfigLookup
}

var errConfigLookup = errors.New("gateway: desired-config lookup failed")

// TestPostTelemetry_NotConfigured proves an authenticated gateway is
// told the control plane is unwired rather than silently succeeding.
func TestPostTelemetry_NotConfigured(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "node-01"), "node-01"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestPostTelemetry_EmptyBody covers a POST that authenticates but
// carries nothing to record.
func TestPostTelemetry_EmptyBody(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/telemetry", strings.NewReader(""))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestPostTelemetry_MalformedJSON covers a body that is present but not
// a snapshot.
func TestPostTelemetry_MalformedJSON(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/telemetry", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestPostTelemetry_StoreFailureIsReported keeps a persistence failure
// from being reported to the gateway as an accepted push, which would
// leave the control plane's view silently stale.
func TestPostTelemetry_StoreFailureIsReported(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(&failingStore{}, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "node-01"), "node-01"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestGetDesiredConfig_NotConfigured covers the pull side with no
// configuration source wired.
func TestGetDesiredConfig_NotConfigured(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestGetDesiredConfig_SourceFailureIsReported keeps a lookup failure
// from being served to the gateway as an empty-but-valid configuration,
// which the reload loop would reconcile toward.
func TestGetDesiredConfig_SourceFailureIsReported(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, failingConfigSource{}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "node-01"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestPostTelemetry_RejectsPaddedCommonName closes the aliasing path a
// normalizing binding would open: if the CN were trimmed before the
// comparison, a certificate issued for " node-01 " would authenticate as
// node-01 and reach that gateway's record. The CN is the identity
// verbatim, so a padded one is refused rather than cleaned up.
func TestPostTelemetry_RejectsPaddedCommonName(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "node-01"), " node-01 "))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d — a padded CN must not alias onto the trimmed identity", rec.Code, http.StatusUnauthorized)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
	if _, ok := store.snaps["node-01"]; ok {
		t.Fatal("a certificate for \" node-01 \" wrote node-01's snapshot")
	}
}

// TestGetDesiredConfig_RejectsPaddedCommonName mirrors the rule on the
// pull side.
func TestGetDesiredConfig_RejectsPaddedCommonName(t *testing.T) {
	src := &recordingConfigSource{}
	router := controlPlaneRouter(newControlPlane(nil, src))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "node-01\t"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if src.calls != 0 {
		t.Fatalf("DesiredConfig calls = %d, want 0", src.calls)
	}
}
