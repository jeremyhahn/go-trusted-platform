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
	payload map[string]interface{}
}

func (r *recordingConfigSource) DesiredConfig(gatewayID string) (map[string]interface{}, error) {
	r.calls++
	r.lastID = gatewayID
	return r.payload, nil
}

func newControlPlane(store gwstate.Store, cfg DesiredConfigSource) *ControlPlane {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	return NewControlPlane(logger, store, cfg, response.NewResponseWriter(logger, nil))
}

func controlPlaneRouter(cp *ControlPlane) *mux.Router {
	parent := mux.NewRouter()
	cp.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
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
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "lab-node-1"), "lab-node-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if store.puts != 1 {
		t.Fatalf("store.puts = %d, want 1", store.puts)
	}
	if _, ok := store.snaps["lab-node-1"]; !ok {
		t.Fatal("snapshot for lab-node-1 was not persisted")
	}
}

// TestPostTelemetry_RejectsOtherGatewayID is the finding this binding
// exists for: a gateway holding a perfectly valid certificate must not
// be able to overwrite another gateway's state by naming it in the body.
func TestPostTelemetry_RejectsOtherGatewayID(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "lab-node-2"), "lab-node-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0 — a refused request must persist nothing", store.puts)
	}
	if _, ok := store.snaps["lab-node-2"]; ok {
		t.Fatal("lab-node-1's certificate wrote lab-node-2's snapshot")
	}
}

// TestPostTelemetry_RejectsWithoutClientCert covers the unauthenticated
// caller: no certificate means no gateway identity, so the request is
// refused rather than trusting the body.
func TestPostTelemetry_RejectsWithoutClientCert(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, telemetryRequest(t, "lab-node-1"))

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
	router.ServeHTTP(rec, withUnverifiedClientCert(telemetryRequest(t, "lab-node-1"), "lab-node-1"))

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
			router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "lab-node-1"), cn))

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
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, ""), "lab-node-1"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestPostTelemetry_BindingIsCaseSensitive pins the exact-match rule. A
// case-insensitive comparison would make "MINI-02" and "lab-node-2" the
// same principal and reopen the substitution this check closes.
func TestPostTelemetry_BindingIsCaseSensitive(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "MINI-01"), "lab-node-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
}

// TestGetDesiredConfig_AcceptsOwnGatewayID is the positive path for the
// pull side.
func TestGetDesiredConfig_AcceptsOwnGatewayID(t *testing.T) {
	src := &recordingConfigSource{payload: map[string]interface{}{"bgp_asn": float64(65001)}}
	router := controlPlaneRouter(newControlPlane(nil, src))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if src.calls != 1 || src.lastID != "lab-node-1" {
		t.Fatalf("DesiredConfig calls = %d, lastID = %q; want 1, \"lab-node-1\"", src.calls, src.lastID)
	}
}

// TestGetDesiredConfig_RejectsOtherGatewayID is the read half of the
// same finding: desired configuration carries a gateway's intended BGP
// ASN, IPAM pools and PXE posture, so an unbound {id} would let one
// gateway enumerate the control plane's intent for the whole fleet.
func TestGetDesiredConfig_RejectsOtherGatewayID(t *testing.T) {
	src := &recordingConfigSource{payload: map[string]interface{}{"bgp_asn": float64(65001)}}
	router := controlPlaneRouter(newControlPlane(nil, src))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-2", nil)
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1"))

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
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)
	router.ServeHTTP(rec, withUnverifiedClientCert(req, "lab-node-1"))

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
		{"telemetry", telemetryRequest(t, "lab-node-1")},
		{"desired-config", httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)},
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

func (failingConfigSource) DesiredConfig(string) (map[string]interface{}, error) {
	return nil, errConfigLookup
}

var errConfigLookup = errors.New("gateway: desired-config lookup failed")

// TestPostTelemetry_NotConfigured proves an authenticated gateway is
// told the control plane is unwired rather than silently succeeding.
func TestPostTelemetry_NotConfigured(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "lab-node-1"), "lab-node-1"))

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
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1"))

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
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1"))

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
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "lab-node-1"), "lab-node-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestGetDesiredConfig_NotConfigured covers the pull side with no
// configuration source wired.
func TestGetDesiredConfig_NotConfigured(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestGetDesiredConfig_SourceFailureIsReported keeps a lookup failure
// from being served to the gateway as an empty-but-valid configuration,
// which the reload loop would reconcile toward.
func TestGetDesiredConfig_SourceFailureIsReported(t *testing.T) {
	router := controlPlaneRouter(newControlPlane(nil, failingConfigSource{}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestPostTelemetry_RejectsPaddedCommonName closes the aliasing path a
// normalizing binding would open: if the CN were trimmed before the
// comparison, a certificate issued for " lab-node-1 " would authenticate as
// lab-node-1 and reach that gateway's record. The CN is the identity
// verbatim, so a padded one is refused rather than cleaned up.
func TestPostTelemetry_RejectsPaddedCommonName(t *testing.T) {
	store := newMemStore()
	router := controlPlaneRouter(newControlPlane(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(telemetryRequest(t, "lab-node-1"), " lab-node-1 "))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d — a padded CN must not alias onto the trimmed identity", rec.Code, http.StatusUnauthorized)
	}
	if store.puts != 0 {
		t.Fatalf("store.puts = %d, want 0", store.puts)
	}
	if _, ok := store.snaps["lab-node-1"]; ok {
		t.Fatal("a certificate for \" lab-node-1 \" wrote lab-node-1's snapshot")
	}
}

// TestGetDesiredConfig_RejectsPaddedCommonName mirrors the rule on the
// pull side.
func TestGetDesiredConfig_RejectsPaddedCommonName(t *testing.T) {
	src := &recordingConfigSource{}
	router := controlPlaneRouter(newControlPlane(nil, src))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/lab-node-1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withClientCert(req, "lab-node-1\t"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if src.calls != 0 {
		t.Fatalf("DesiredConfig calls = %d, want 0", src.calls)
	}
}
