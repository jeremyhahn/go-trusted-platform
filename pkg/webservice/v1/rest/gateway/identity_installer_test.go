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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
)

// issueInstaller mints a client certificate signed the way the issuer signs
// a PXE installer leaf: the critical extended key usage extension carrying
// id-kp-clientAuth and tp-pxeInstaller.
func (ca *testCA) issueInstaller(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	marker, err := issuance.InstallerMarkerExtension()
	if err != nil {
		t.Fatalf("installer marker: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate installer key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: commonName},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{marker},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign installer %s: %v", commonName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse installer %s: %v", commonName, err)
	}
	if !issuance.HasInstallerMarker(leaf) {
		t.Fatal("the fixture certificate does not carry tp-pxeInstaller")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// requestWithVerifiedLeaf builds a request whose TLS state holds leaf as
// the verified chain's leaf, as the TLS stack leaves it after a handshake.
func requestWithVerifiedLeaf(ca *testCA, leaf *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/node-01", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca.cert}}}
	return r
}

func TestGatewayPrincipal_RefusesInstallerCertificate(t *testing.T) {
	ca := newTestCA(t)
	installer := ca.issueInstaller(t, "node-01")

	principal, err := gatewayPrincipal(requestWithVerifiedLeaf(ca, installer.Leaf))
	if !errors.Is(err, ErrInstallerNotGateway{}) {
		t.Fatalf("err = %v, want ErrInstallerNotGateway", err)
	}
	if principal != "" {
		t.Fatalf("principal = %q, want none for an installer certificate", principal)
	}
}

func TestGatewayPrincipal_AdmitsUnmarkedGatewayWithTheSameCN(t *testing.T) {
	ca := newTestCA(t)
	gw := ca.issue(t, "node-01")

	principal, err := gatewayPrincipal(requestWithVerifiedLeaf(ca, gw.Leaf))
	if err != nil {
		t.Fatalf("gatewayPrincipal: %v", err)
	}
	if principal != "node-01" {
		t.Fatalf("principal = %q, want node-01", principal)
	}
}

// TestControlPlaneOverRealTLS_InstallerIsRefused proves that a CA-signed
// installer certificate whose CN names a gateway passes the TLS handshake
// (it carries clientAuth) yet is refused by every machine-facing route,
// while the same CN on an unmarked gateway certificate is still admitted.
func TestControlPlaneOverRealTLS_InstallerIsRefused(t *testing.T) {
	ca := newTestCA(t)
	store := newMemStore()
	src := &recordingConfigSource{payload: sampleDesiredConfig()}
	srv := startControlPlaneTLS(t, ca, newControlPlane(store, src))
	installerCert := ca.issueInstaller(t, "node-01")
	gatewayCert := ca.issue(t, "node-01")
	installer := clientFor(ca, &installerCert)
	gateway := clientFor(ca, &gatewayCert)

	t.Run("telemetry from an installer is refused", func(t *testing.T) {
		resp := postSnapshot(t, installer, srv.URL, "node-01")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if store.puts != 0 {
			t.Fatalf("store.puts = %d, want 0 — an installer certificate wrote gateway state", store.puts)
		}
	})

	t.Run("desired config to an installer is refused", func(t *testing.T) {
		resp, err := installer.Get(srv.URL + "/api/v1/gateway/desired-config/node-01")
		if err != nil {
			t.Fatalf("GET desired-config: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if src.calls != 0 {
			t.Fatalf("DesiredConfig calls = %d, want 0 — an installer read fleet intent", src.calls)
		}
	})

	t.Run("the same CN on a gateway certificate is admitted", func(t *testing.T) {
		resp := postSnapshot(t, gateway, srv.URL, "node-01")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		resp, err := gateway.Get(srv.URL + "/api/v1/gateway/desired-config/node-01")
		if err != nil {
			t.Fatalf("GET desired-config: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("desired-config status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestErrInstallerNotGateway(t *testing.T) {
	err := error(ErrInstallerNotGateway{CommonName: "node-01"})
	msg := err.Error()
	for _, want := range []string{`"node-01"`, "tp-pxeInstaller", "not a gateway identity"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Error() = %q, missing %q", msg, want)
		}
	}
	if !errors.Is(err, ErrInstallerNotGateway{}) {
		t.Fatal("errors.Is does not match ErrInstallerNotGateway with another Common Name")
	}
	if errors.Is(err, ErrGatewayIdentityRequired{}) {
		t.Fatal("ErrInstallerNotGateway matched ErrGatewayIdentityRequired")
	}
	if errors.Is(ErrGatewayIdentityRequired{Reason: "x"}, ErrInstallerNotGateway{}) {
		t.Fatal("ErrGatewayIdentityRequired matched ErrInstallerNotGateway")
	}
}
