package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// oidTCGIDevIDTest is the TCG IDevID OID (2.23.133.5.4.2) added to test
// leaf certificates that must pass auth.ValidateIDevID.
var oidTCGIDevIDTest = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2}

// leafSpec describes a test leaf certificate.
type leafSpec struct {
	cn     string
	ou     []string
	zone   string
	idevid bool
	uri    string
}

// testCA holds an in-test certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newTestCA generates a self-signed CA for leaf issuance.
func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "proxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// newLeafCert issues a CA-signed leaf with the requested platform
// extensions: the TCG IDevID OID (2.23.133.5.4.2) and the canonical
// OIDTPNetworkZone extension (1.3.6.1.4.1.29377.101.21) built with the
// quicbaas SDK encoder.
func newLeafCert(t *testing.T, ca *testCA, spec leafSpec) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         spec.cn,
			Organization:       []string{"Test Org"},
			OrganizationalUnit: spec.ou,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if spec.uri != "" {
		u, err := url.Parse(spec.uri)
		if err != nil {
			t.Fatalf("parse uri san: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	if spec.idevid {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:    oidTCGIDevIDTest,
			Value: []byte{0x05, 0x00}, // ASN.1 NULL; ValidateIDevID checks presence
		})
	}
	if spec.zone != "" {
		ext, err := quicbaasca.CreateNetworkZoneExtension(spec.zone)
		if err != nil {
			t.Fatalf("create zone extension: %v", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return cert
}

// fakeMTLSAuth is a configurable MTLSAuthenticator.
type fakeMTLSAuth struct {
	err   error
	attrs map[string]string

	mu       sync.Mutex
	lastCert *x509.Certificate
}

func (f *fakeMTLSAuth) Authenticate(ctx context.Context, cert *x509.Certificate) (*auth.Identity, error) {
	f.mu.Lock()
	f.lastCert = cert
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &auth.Identity{
		ID:           cert.Subject.CommonName,
		SerialNumber: cert.SerialNumber.Text(16),
		Attributes:   f.attrs,
	}, nil
}

// tlsRequest builds a request with the given peer certificate. A nil leaf
// yields a TLS request without peer certificates.
func tlsRequest(leaf *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://svc.example.com/api", nil)
	r.TLS = &tls.ConnectionState{}
	if leaf != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{leaf}
	}
	return r
}

// chainRoute builds a compiled route carrying the given auth requirements.
func chainRoute(a AuthRequirements) *CompiledRoute {
	return &CompiledRoute{cfg: RouteConfig{ID: "api", PathPrefix: "/", PoolID: "pool", Auth: a}}
}

// testMatrix compiles a matrix allowing control-plane → internal only.
func testMatrix() zone.Matrix {
	return zone.CompileMatrix([]zone.ZoneConfig{
		{Name: "control-plane", AllowTo: []zone.ZonePath{{Zone: "internal"}}},
		{Name: "internal"},
	})
}

// newTestChain builds a zone-capable chain around the fake authenticator.
func newTestChain(t *testing.T, mtls MTLSAuthenticator) *Chain {
	t.Helper()
	c, err := NewAuthChain(AuthChainConfig{
		MTLS:          mtls,
		ZoneExtractor: NewPolicyZoneExtractor(),
		Matrix:        testMatrix,
		Logger:        testLogger(),
	})
	if err != nil {
		t.Fatalf("NewAuthChain: %v", err)
	}
	return c
}

func TestNewAuthChain(t *testing.T) {
	mtls := &fakeMTLSAuth{}
	tests := []struct {
		name    string
		cfg     AuthChainConfig
		wantErr error
	}{
		{"missing mtls", AuthChainConfig{}, ErrMTLSAuthenticatorRequired},
		{"extractor without matrix", AuthChainConfig{MTLS: mtls, ZoneExtractor: NewPolicyZoneExtractor()}, ErrZoneConfigIncomplete},
		{"matrix without extractor", AuthChainConfig{MTLS: mtls, Matrix: testMatrix}, ErrZoneConfigIncomplete},
		{"mtls only", AuthChainConfig{MTLS: mtls}, nil},
		{"fully configured", AuthChainConfig{MTLS: mtls, ZoneExtractor: NewPolicyZoneExtractor(), Matrix: testMatrix, Logger: testLogger()}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewAuthChain(tt.cfg)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewAuthChain error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewAuthChain: %v", err)
			}
			if c.logger == nil {
				t.Error("logger not defaulted")
			}
		})
	}
}

func TestChainCapabilities(t *testing.T) {
	full := newTestChain(t, &fakeMTLSAuth{})
	caps := full.Capabilities()
	if !caps.MTLS || !caps.Zones {
		t.Errorf("full chain caps = %+v, want MTLS and Zones", caps)
	}
	if caps.Token || caps.Attestation || caps.OPA {
		t.Errorf("phase 5 caps must be false, got %+v", caps)
	}
	bare, err := NewAuthChain(AuthChainConfig{MTLS: &fakeMTLSAuth{}, Logger: testLogger()})
	if err != nil {
		t.Fatalf("NewAuthChain: %v", err)
	}
	if bare.Capabilities().Zones {
		t.Error("chain without zone collaborators must not report Zones")
	}
}

func TestChainAuthenticateNilArguments(t *testing.T) {
	c := newTestChain(t, &fakeMTLSAuth{})
	if _, err := c.Authenticate(context.Background(), nil, chainRoute(AuthRequirements{Mode: AuthModeMTLS})); !errors.Is(err, ErrNilRequest) {
		t.Errorf("nil request error = %v, want ErrNilRequest", err)
	}
	if _, err := c.Authenticate(context.Background(), tlsRequest(nil), nil); !errors.Is(err, ErrNilRoute) {
		t.Errorf("nil route error = %v, want ErrNilRoute", err)
	}
}

// TestChainAuthenticateDenyReasons table-tests every stable deny reason.
func TestChainAuthenticateDenyReasons(t *testing.T) {
	ca := newTestCA(t)
	plain := newLeafCert(t, ca, leafSpec{cn: "device-1"})
	trusted := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "control-plane"})
	public := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "public"})
	adapterErr := errors.New("certificate expired")

	noTLS := httptest.NewRequest(http.MethodGet, "http://svc.example.com/api", nil)

	tests := []struct {
		name       string
		mtls       *fakeMTLSAuth
		req        *http.Request
		auth       AuthRequirements
		wantReason string
	}{
		{"token mode not configured", &fakeMTLSAuth{}, tlsRequest(plain),
			AuthRequirements{Mode: AuthModeToken}, ReasonTokenAuthNotConfigured},
		{"mtls-or-token without cert", &fakeMTLSAuth{}, tlsRequest(nil),
			AuthRequirements{Mode: AuthModeMTLSOrToken}, ReasonTokenAuthNotConfigured},
		{"no tls state", &fakeMTLSAuth{}, noTLS,
			AuthRequirements{Mode: AuthModeMTLS}, ReasonClientCertRequired},
		{"tls without peer cert", &fakeMTLSAuth{}, tlsRequest(nil),
			AuthRequirements{Mode: AuthModeMTLS}, ReasonClientCertRequired},
		{"adapter rejects certificate", &fakeMTLSAuth{err: adapterErr}, tlsRequest(plain),
			AuthRequirements{Mode: AuthModeMTLS}, ReasonMTLSAuthFailed},
		{"idevid required but absent", &fakeMTLSAuth{}, tlsRequest(plain),
			AuthRequirements{Mode: AuthModeMTLS, RequireIDevID: true}, ReasonIDevIDRequired},
		{"zone required but missing", &fakeMTLSAuth{}, tlsRequest(plain),
			AuthRequirements{Mode: AuthModeMTLS, AllowedZones: []string{"control-plane"}}, ReasonZoneMissing},
		{"zone not in allowed set", &fakeMTLSAuth{}, tlsRequest(public),
			AuthRequirements{Mode: AuthModeMTLS, AllowedZones: []string{"control-plane"}}, ReasonZoneNotAllowed},
		{"zone matrix denies path", &fakeMTLSAuth{}, tlsRequest(public),
			AuthRequirements{Mode: AuthModeMTLS, BackendZone: "internal"}, ReasonZoneMatrixDenied},
		{"role required but absent", &fakeMTLSAuth{}, tlsRequest(trusted),
			AuthRequirements{Mode: AuthModeMTLS, RequiredRoles: []string{"admin"}}, ReasonRoleRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestChain(t, tt.mtls)
			d, err := c.Authenticate(context.Background(), tt.req, chainRoute(tt.auth))
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if d.Allowed {
				t.Fatal("decision allowed, want deny")
			}
			if d.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", d.Reason, tt.wantReason)
			}
			if d.Identity != nil {
				t.Error("deny decision must carry no identity")
			}
		})
	}
}

// TestChainAuthenticateAllow pins the full allow path and the identity it
// produces.
func TestChainAuthenticateAllow(t *testing.T) {
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{
		cn:     "device-1",
		ou:     []string{"operators"},
		zone:   "control-plane",
		idevid: true,
		uri:    "spiffe://platform/device-1",
	})
	mtls := &fakeMTLSAuth{attrs: map[string]string{"organizational_unit": "operators"}}
	c := newTestChain(t, mtls)
	d, err := c.Authenticate(context.Background(), tlsRequest(leaf), chainRoute(AuthRequirements{
		Mode:          AuthModeMTLS,
		RequireIDevID: true,
		AllowedZones:  []string{"control-plane"},
		BackendZone:   "internal",
		RequiredRoles: []string{"operators"},
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("decision denied: %s", d.Reason)
	}
	id := d.Identity
	if id == nil {
		t.Fatal("allow decision must carry an identity")
	}
	if id.ID != "device-1" {
		t.Errorf("ID = %q, want device-1", id.ID)
	}
	if id.DeviceID != leaf.SerialNumber.Text(16) {
		t.Errorf("DeviceID = %q, want certificate serial %q", id.DeviceID, leaf.SerialNumber.Text(16))
	}
	if id.Zone != "control-plane" {
		t.Errorf("Zone = %q, want control-plane", id.Zone)
	}
	if id.AuthMethod != authMethodMTLS {
		t.Errorf("AuthMethod = %q, want mtls", id.AuthMethod)
	}
	if id.Attested {
		t.Error("Attested must be false until the attestation gate attaches")
	}
	if id.CertFingerprint != fingerprintHex(leaf) {
		t.Errorf("CertFingerprint = %q, want sha256 of leaf", id.CertFingerprint)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "operators" {
		t.Errorf("Roles = %v, want [operators]", id.Roles)
	}
	if id.subjectDN != leaf.Subject.String() {
		t.Errorf("subjectDN = %q, want %q", id.subjectDN, leaf.Subject.String())
	}
	if id.uriSAN != "spiffe://platform/device-1" {
		t.Errorf("uriSAN = %q, want spiffe uri", id.uriSAN)
	}
	if mtls.lastCert == nil || !mtls.lastCert.Equal(leaf) {
		t.Error("adapter did not receive the presented leaf")
	}
}

func TestChainAuthenticatePublicModeDefensiveAllow(t *testing.T) {
	c := newTestChain(t, &fakeMTLSAuth{})
	d, err := c.Authenticate(context.Background(), tlsRequest(nil), chainRoute(AuthRequirements{Mode: AuthModePublic}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed {
		t.Error("public mode must allow defensively")
	}
}

// TestChainAuthenticateMTLSOrTokenWithCert verifies the hybrid mode follows
// the mTLS path when a certificate is presented.
func TestChainAuthenticateMTLSOrTokenWithCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "control-plane"})
	c := newTestChain(t, &fakeMTLSAuth{})
	d, err := c.Authenticate(context.Background(), tlsRequest(leaf), chainRoute(AuthRequirements{
		Mode:         AuthModeMTLSOrToken,
		AllowedZones: []string{"control-plane"},
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("decision denied: %s", d.Reason)
	}
	if d.Identity.AuthMethod != authMethodMTLS {
		t.Errorf("AuthMethod = %q, want mtls", d.Identity.AuthMethod)
	}
}

// TestChainAuthenticateZoneEnrichment verifies zone-free routes still record
// the client zone when present, and tolerate its absence.
func TestChainAuthenticateZoneEnrichment(t *testing.T) {
	ca := newTestCA(t)
	c := newTestChain(t, &fakeMTLSAuth{})
	route := chainRoute(AuthRequirements{Mode: AuthModeMTLS})

	withZone := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "control-plane"})
	d, err := c.Authenticate(context.Background(), tlsRequest(withZone), route)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed || d.Identity.Zone != "control-plane" {
		t.Errorf("zone enrichment failed: allowed=%v zone=%q", d.Allowed, d.Identity.Zone)
	}

	withoutZone := newLeafCert(t, ca, leafSpec{cn: "device-1"})
	d, err = c.Authenticate(context.Background(), tlsRequest(withoutZone), route)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed || d.Identity.Zone != "" {
		t.Errorf("zone-free cert on zone-free route: allowed=%v zone=%q", d.Allowed, d.Identity.Zone)
	}
}

// TestChainAuthenticateZoneRequiredWithoutExtractor pins the defensive
// fail-closed deny for zone-requiring routes on a chain without zone
// collaborators.
func TestChainAuthenticateZoneRequiredWithoutExtractor(t *testing.T) {
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "control-plane"})
	c, err := NewAuthChain(AuthChainConfig{MTLS: &fakeMTLSAuth{}, Logger: testLogger()})
	if err != nil {
		t.Fatalf("NewAuthChain: %v", err)
	}
	d, err := c.Authenticate(context.Background(), tlsRequest(leaf), chainRoute(AuthRequirements{
		Mode:         AuthModeMTLS,
		AllowedZones: []string{"control-plane"},
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if d.Allowed || d.Reason != ReasonZoneMissing {
		t.Errorf("decision = %+v, want deny %s", d, ReasonZoneMissing)
	}
}

// TestChainAuthenticateMatrixAllowedPath verifies the allowed matrix path
// control-plane → internal.
func TestChainAuthenticateMatrixAllowedPath(t *testing.T) {
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "control-plane"})
	c := newTestChain(t, &fakeMTLSAuth{})
	d, err := c.Authenticate(context.Background(), tlsRequest(leaf), chainRoute(AuthRequirements{
		Mode:        AuthModeMTLS,
		BackendZone: "internal",
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("decision denied: %s", d.Reason)
	}
}

func TestPolicyZoneExtractor(t *testing.T) {
	ca := newTestCA(t)
	ex := NewPolicyZoneExtractor()

	t.Run("extracts zone", func(t *testing.T) {
		leaf := newLeafCert(t, ca, leafSpec{cn: "device-1", zone: "control-plane"})
		z, err := ex.ExtractZone(leaf)
		if err != nil {
			t.Fatalf("ExtractZone: %v", err)
		}
		if z != "control-plane" {
			t.Errorf("zone = %q, want control-plane", z)
		}
	})

	t.Run("missing extension", func(t *testing.T) {
		leaf := newLeafCert(t, ca, leafSpec{cn: "device-1"})
		if _, err := ex.ExtractZone(leaf); !errors.Is(err, ErrZoneExtensionMissing) {
			t.Errorf("error = %v, want ErrZoneExtensionMissing", err)
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		if _, err := ex.ExtractZone(nil); !errors.Is(err, ErrNilLeafCertificate) {
			t.Errorf("error = %v, want ErrNilLeafCertificate", err)
		}
	})
}

func TestRolesFromIdentity(t *testing.T) {
	tests := []struct {
		name  string
		ident *auth.Identity
		want  []string
	}{
		{"nil identity", nil, nil},
		{"nil attributes", &auth.Identity{}, nil},
		{"roles attribute", &auth.Identity{Attributes: map[string]string{"roles": "admin, operator ,,"}}, []string{"admin", "operator"}},
		{"ou fallback", &auth.Identity{Attributes: map[string]string{"organizational_unit": "operators"}}, []string{"operators"}},
		{"roles wins over ou", &auth.Identity{Attributes: map[string]string{"roles": "admin", "organizational_unit": "operators"}}, []string{"admin"}},
		{"empty attributes", &auth.Identity{Attributes: map[string]string{}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rolesFromIdentity(tt.ident)
			if len(got) != len(tt.want) {
				t.Fatalf("roles = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("roles = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestHasAllRoles(t *testing.T) {
	tests := []struct {
		name     string
		held     []string
		required []string
		want     bool
	}{
		{"no requirements", nil, nil, true},
		{"subset", []string{"a", "b"}, []string{"a"}, true},
		{"exact", []string{"a"}, []string{"a"}, true},
		{"missing", []string{"a"}, []string{"a", "b"}, false},
		{"none held", nil, []string{"a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAllRoles(tt.held, tt.required); got != tt.want {
				t.Errorf("hasAllRoles(%v, %v) = %v, want %v", tt.held, tt.required, got, tt.want)
			}
		})
	}
}

func TestFirstURISAN(t *testing.T) {
	ca := newTestCA(t)
	withURI := newLeafCert(t, ca, leafSpec{cn: "d", uri: "spiffe://platform/d"})
	if got := firstURISAN(withURI); got != "spiffe://platform/d" {
		t.Errorf("firstURISAN = %q, want spiffe uri", got)
	}
	without := newLeafCert(t, ca, leafSpec{cn: "d"})
	if got := firstURISAN(without); got != "" {
		t.Errorf("firstURISAN = %q, want empty", got)
	}
}
