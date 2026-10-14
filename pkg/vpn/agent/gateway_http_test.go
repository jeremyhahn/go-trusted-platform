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

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// deviceCertificate is a self-signed stand-in for the IDevID.
func deviceCertificate(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	return selfSignedCertificate(t, cn, x509.ExtKeyUsageClientAuth)
}

// selfSignedCertificate is a self-signed leaf for usage; a pool holding the
// leaf trusts it.
func selfSignedCertificate(t *testing.T, cn string, usage x509.ExtKeyUsage, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// admissionListener is an httptest TLS server that demands a client
// certificate and answers errors through the gateway's own RefusalOf.
type admissionListener struct {
	srv   *httptest.Server
	mu    sync.Mutex
	peers []string
}

func newAdmissionListener(t *testing.T, handle func(w http.ResponseWriter, r *http.Request) error) *admissionListener {
	t.Helper()
	l := &admissionListener{}
	l.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.peers = append(l.peers, r.TLS.PeerCertificates[0].Subject.CommonName)
		l.mu.Unlock()
		if err := handle(w, r); err != nil {
			refusal, status := gwvpn.RefusalOf(err)
			w.WriteHeader(status)
			assert.NoError(t, json.NewEncoder(w).Encode(refusal))
		}
	}))
	l.srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	l.srv.StartTLS()
	t.Cleanup(l.srv.Close)
	return l
}

func (l *admissionListener) addr() string { return strings.TrimPrefix(l.srv.URL, "https://") }

// seen returns the client certificate common names the handler saw.
func (l *admissionListener) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.peers)
}

func (l *admissionListener) gateway(t *testing.T) *HTTPGateway {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(l.srv.Certificate())
	gw, err := NewHTTPGateway(l.addr(), deviceCertificate(t, "laptop-1"), roots)
	require.NoError(t, err)
	return gw
}

func writeJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func TestHTTPGateway_RunsTheAdmissionRoutesWithTheDeviceCertificate(t *testing.T) {
	var admitted gwvpn.AdmissionRequestWire
	var revoked string
	l := newAdmissionListener(t, func(w http.ResponseWriter, r *http.Request) error {
		switch r.Method + " " + r.URL.EscapedPath() {
		case "POST " + gwvpn.PathChallenges:
			return writeJSON(w, gwvpn.ChallengeWire{Nonce: []byte("nonce-1"), DataPlanes: []gwvpn.DataPlaneKind{gwvpn.DataPlaneMASQUE}})
		case "POST " + gwvpn.PathAdmissions:
			if err := gwvpn.DecodeRequest(r.Body, &admitted); err != nil {
				return err
			}
			return writeJSON(w, gwvpn.LeaseWire{ID: "l-1", DataPlane: gwvpn.DataPlaneMASQUE, Address: "10.8.0.2/32"})
		case "DELETE " + gwvpn.LeasePath("l-1"):
			revoked = "l-1"
			w.WriteHeader(http.StatusNoContent)
			return nil
		default:
			return &gwvpn.ErrLeaseNotFound{}
		}
	})
	gw := l.gateway(t)
	ctx := context.Background()

	challenge, err := gw.Challenge(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("nonce-1"), challenge.Nonce)
	assert.Equal(t, []gwvpn.DataPlaneKind{gwvpn.DataPlaneMASQUE}, challenge.DataPlanes)

	lease, err := gw.Admit(ctx, &gwvpn.AdmissionRequestWire{TenantID: "acme", DeviceID: "laptop-1", Nonce: challenge.Nonce, DataPlane: gwvpn.DataPlaneMASQUE})
	require.NoError(t, err)
	assert.Equal(t, gwvpn.LeaseID("l-1"), lease.ID)
	assert.Equal(t, "acme", admitted.TenantID)
	assert.Equal(t, "laptop-1", admitted.DeviceID)
	assert.Equal(t, []byte("nonce-1"), admitted.Nonce)

	require.NoError(t, gw.Revoke(ctx, "l-1"))
	assert.Equal(t, "l-1", revoked)
	assert.Equal(t, []string{"laptop-1", "laptop-1", "laptop-1"}, l.seen(), "every route sees the device certificate")
}

func TestHTTPGateway_DecodesTheGatewaysRefusal(t *testing.T) {
	l := newAdmissionListener(t, func(http.ResponseWriter, *http.Request) error {
		return &gwvpn.ErrPostureViolation{Violations: []string{"secure_boot", "fde"}}
	})

	_, err := l.gateway(t).Admit(context.Background(), &gwvpn.AdmissionRequestWire{})

	var refused *RefusedError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, http.StatusForbidden, refused.Status)
	assert.Equal(t, gwvpn.RefusalPostureViolation, refused.Class)
	assert.Equal(t, []string{"secure_boot", "fde"}, refused.Rules)
	assert.Equal(t, ExitPostureViolation, ExitCode(err))
}

func TestHTTPGateway_RenewPostsTheEvidenceToTheLeasesRoute(t *testing.T) {
	var renewal gwvpn.RenewalRequestWire
	l := newAdmissionListener(t, func(w http.ResponseWriter, r *http.Request) error {
		if r.Method+" "+r.URL.EscapedPath() != "POST "+gwvpn.LeaseRenewPath("l-1") {
			return &gwvpn.ErrLeaseNotFound{}
		}
		if err := gwvpn.DecodeRequest(r.Body, &renewal); err != nil {
			return err
		}
		return writeJSON(w, gwvpn.LeaseWire{ID: "l-1", DataPlane: gwvpn.DataPlaneMASQUE, Renewals: 1})
	})

	lease, err := l.gateway(t).Renew(context.Background(), "l-1", &gwvpn.RenewalRequestWire{Nonce: []byte("nonce-2")})

	require.NoError(t, err)
	assert.Equal(t, 1, lease.Renewals)
	assert.Equal(t, []byte("nonce-2"), renewal.Nonce)
	assert.Equal(t, []string{"laptop-1"}, l.seen())
}

func TestHTTPGateway_RenewDecodesTheRefusal(t *testing.T) {
	l := newAdmissionListener(t, func(http.ResponseWriter, *http.Request) error {
		return &gwvpn.ErrRenewalNotOpen{LeaseID: "l-1", OpensAt: time.Unix(1760325200, 0)}
	})

	_, err := l.gateway(t).Renew(context.Background(), "l-1", &gwvpn.RenewalRequestWire{})

	var refused *RefusedError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, gwvpn.RefusalRenewalNotOpen, refused.Class)
	assert.Equal(t, ExitRefused, ExitCode(err))
}

func TestHTTPGateway_AnErrorPageIsNotARefusal(t *testing.T) {
	l := newAdmissionListener(t, func(w http.ResponseWriter, _ *http.Request) error {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return nil
	})

	err := l.gateway(t).Revoke(context.Background(), "l-1")

	var invalid *ErrInvalidResponse
	require.ErrorAs(t, err, &invalid)
	assert.Contains(t, invalid.Reason, "502")
	assert.Equal(t, ExitFailure, ExitCode(err))
}

func TestHTTPGateway_RejectsAChallengeWithoutANonce(t *testing.T) {
	l := newAdmissionListener(t, func(w http.ResponseWriter, _ *http.Request) error {
		return writeJSON(w, gwvpn.ChallengeWire{})
	})

	_, err := l.gateway(t).Challenge(context.Background())
	var invalid *ErrInvalidResponse
	assert.ErrorAs(t, err, &invalid)
}

func TestHTTPGateway_RejectsABodyThatIsNotTheContract(t *testing.T) {
	l := newAdmissionListener(t, func(w http.ResponseWriter, _ *http.Request) error {
		_, err := w.Write([]byte("<html>"))
		return err
	})

	_, err := l.gateway(t).Admit(context.Background(), &gwvpn.AdmissionRequestWire{})
	var invalid *ErrInvalidResponse
	assert.ErrorAs(t, err, &invalid)
}

func TestHTTPGateway_RefusesAGatewayOutsideTheRoots(t *testing.T) {
	l := newAdmissionListener(t, func(http.ResponseWriter, *http.Request) error { return nil })
	gw, err := NewHTTPGateway(l.addr(), deviceCertificate(t, "laptop-1"), x509.NewCertPool())
	require.NoError(t, err)

	_, err = gw.Challenge(context.Background())
	var unreachable *ErrGatewayUnreachable
	require.ErrorAs(t, err, &unreachable)
	var unknownAuthority x509.UnknownAuthorityError
	assert.ErrorAs(t, err, &unknownAuthority)
	assert.Empty(t, l.seen())
}

func TestHTTPGateway_ReportsAnUnreachableGateway(t *testing.T) {
	l := newAdmissionListener(t, func(http.ResponseWriter, *http.Request) error { return nil })
	gw := l.gateway(t)
	l.srv.Close()

	_, err := gw.Challenge(context.Background())
	var unreachable *ErrGatewayUnreachable
	assert.ErrorAs(t, err, &unreachable)
}

func TestNewHTTPGateway_RejectsBadOptions(t *testing.T) {
	cert := deviceCertificate(t, "laptop-1")
	tests := []struct {
		name  string
		addr  string
		cert  tls.Certificate
		field string
	}{
		{"no port", "gw.example", cert, "gateway"},
		{"no host", ":4433", cert, "gateway"},
		{"no certificate", "gw.example:4433", tls.Certificate{}, "device certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHTTPGateway(tt.addr, tt.cert, nil)
			var invalid *ErrInvalidOptions
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tt.field, invalid.Field)
		})
	}
}

func TestDialHTTPGateway_BuildsAnHTTPGateway(t *testing.T) {
	gw, err := DialHTTPGateway(nil)("gw.example:4433", deviceCertificate(t, "laptop-1"))
	require.NoError(t, err)
	assert.IsType(t, &HTTPGateway{}, gw)

	_, err = DialHTTPGateway(nil)("gw.example", deviceCertificate(t, "laptop-1"))
	var invalid *ErrInvalidOptions
	assert.ErrorAs(t, err, &invalid)
}
