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

package pxe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const webhookPath = "/api/v1/pxe/webhook/complete"

const webhookBody = `{"macAddress":"aa:bb:cc:dd:ee:ff","hostname":"node-1","success":true}`

// webhookRoot mounts only the machine-facing webhook, with secret as its key
// (none when empty).
func webhookRoot(server platformv1.PXEServiceServer, secret string) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	r := NewPXERouter(logger, server, response.NewResponseWriter(logger, nil), true)
	if secret != "" {
		r.SetWebhookSecret(secret)
	}
	root := mux.NewRouter()
	r.RegisterMachineFacingRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func postWebhook(root *mux.Router, body, signature string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(body))
	if signature != "" {
		req.Header.Set(WebhookSignatureHeader, signature)
	}
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec
}

// TestWebhook_SignedReportReachesTheService: the body the service decodes is
// the body that was signed.
func TestWebhook_SignedReportReachesTheService(t *testing.T) {
	cert := deviceCert(t, 1001)
	server := newWebhookPXE("aa:bb:cc:dd:ee:ff", "1001")
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))

	rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, verifiedTLS(cert))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, server.report, "the service saw no report")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", server.report.MacAddress)
	assert.Equal(t, "node-1", server.report.Hostname)
}

// webhookPXE is a PXE service holding one device record, the record the
// webhook binds the caller's certificate to, and the report it received.
type webhookPXE struct {
	platformv1.UnimplementedPXEServiceServer
	devices map[string]*platformv1.PXEDeviceInfo
	report  *platformv1.PXEWebhookCompleteRequest
}

func newWebhookPXE(mac, certSerial string) *webhookPXE {
	return &webhookPXE{devices: map[string]*platformv1.PXEDeviceInfo{
		mac: {Id: "dev-1", MacAddress: mac, CertificateSerial: certSerial},
	}}
}

func (s *webhookPXE) GetDeviceByMAC(_ context.Context, req *platformv1.GetPXEDeviceByMACRequest) (*platformv1.GetPXEDeviceByMACResponse, error) {
	d, ok := s.devices[req.GetMacAddress()]
	if !ok {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	return &platformv1.GetPXEDeviceByMACResponse{Device: d}, nil
}

func (s *webhookPXE) WebhookComplete(_ context.Context, req *platformv1.PXEWebhookCompleteRequest) (*platformv1.PXEWebhookCompleteResponse, error) {
	s.report = req
	return &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}, nil
}

// deviceCert is a client certificate with the given serial, standing in
// for the identity a device presented at enrollment.
func deviceCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// verifiedTLS is the connection state of a client whose certificate the
// listener verified.
func verifiedTLS(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

func postWebhookAs(root *mux.Router, body, signature string, state *tls.ConnectionState) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(body))
	if signature != "" {
		req.Header.Set(WebhookSignatureHeader, signature)
	}
	req.TLS = state
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec
}

// TestWebhook_RefusesWithoutAVerifiedClientCertificate pins SPEC installer
// row: the install-completion caller authenticates with its device identity
// over mTLS. A correctly signed report from a plain-TLS client, or from one
// whose certificate the listener did not verify, answers 401.
func TestWebhook_RefusesWithoutAVerifiedClientCertificate(t *testing.T) {
	cert := deviceCert(t, 1001)
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))
	for name, state := range map[string]*tls.ConnectionState{
		"no TLS":            nil,
		"no client cert":    {},
		"unverified client": {PeerCertificates: []*x509.Certificate{cert}},
	} {
		t.Run(name, func(t *testing.T) {
			server := newWebhookPXE("aa:bb:cc:dd:ee:ff", "1001")
			rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, state)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.Nil(t, server.report, "the service was reached")
		})
	}
}

// TestWebhook_RefusesAnotherDevicesIdentity pins the binding: a verified
// client may report only for the device whose recorded certificate it holds.
func TestWebhook_RefusesAnotherDevicesIdentity(t *testing.T) {
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))
	for name, server := range map[string]*webhookPXE{
		"other device's cert": newWebhookPXE("aa:bb:cc:dd:ee:ff", "1001"),
		"no cert recorded":    newWebhookPXE("aa:bb:cc:dd:ee:ff", ""),
		"unknown MAC":         newWebhookPXE("11:22:33:44:55:66", "2002"),
	} {
		t.Run(name, func(t *testing.T) {
			rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, verifiedTLS(deviceCert(t, 2002)))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Nil(t, server.report, "the service was reached")
		})
	}
}

// TestWebhook_BoundIdentityStillNeedsTheSignature keeps the HMAC as the
// second factor: the bound device's certificate without the signature is 401.
func TestWebhook_BoundIdentityStillNeedsTheSignature(t *testing.T) {
	server := newWebhookPXE("aa:bb:cc:dd:ee:ff", "1001")
	rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, "", verifiedTLS(deviceCert(t, 1001)))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Nil(t, server.report, "the service was reached")
}

// TestWebhook_RefusesWithoutAValidSignature is #240: knowing a device's MAC
// is no longer enough to report its install complete.
func TestWebhook_RefusesWithoutAValidSignature(t *testing.T) {
	cases := map[string]struct {
		signature   string
		wantMissing bool
	}{
		"missing":      {signature: "", wantMissing: true},
		"wrong secret": {signature: SignWebhookBody([]byte("guess"), []byte(webhookBody))},
		"other body":   {signature: SignWebhookBody([]byte("s3cret"), []byte(`{"macAddress":"aa:bb:cc:dd:ee:00"}`))},
		"no prefix":    {signature: strings.TrimPrefix(SignWebhookBody([]byte("s3cret"), []byte(webhookBody)), webhookSignaturePrefix)},
		"upper case":   {signature: strings.ToUpper(SignWebhookBody([]byte("s3cret"), []byte(webhookBody)))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server := &operatorPXE{resp: &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}}

			rec := postWebhook(webhookRoot(server, "s3cret"), webhookBody, c.signature)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Empty(t, server.rpc, "an unsigned report reached the service")
			assert.Contains(t, rec.Body.String(), ErrWebhookSignature{Missing: c.wantMissing}.Error())
		})
	}
}

// TestWebhook_NoSecretRefusesEveryReport: an enabled webhook with no key
// fails closed, whatever the caller sends.
func TestWebhook_NoSecretRefusesEveryReport(t *testing.T) {
	server := &operatorPXE{resp: &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}}

	rec := postWebhook(webhookRoot(server, ""), webhookBody, SignWebhookBody(nil, []byte(webhookBody)))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, server.rpc)
	assert.Contains(t, rec.Body.String(), ErrWebhookSecretUnset{}.Error())
}

// TestWebhook_OversizedBodyIsRefused: the body is read with a bound before
// it is authenticated.
func TestWebhook_OversizedBodyIsRefused(t *testing.T) {
	server := &operatorPXE{resp: &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}}
	body := strings.Repeat("x", maxWebhookBody+1)

	rec := postWebhook(webhookRoot(server, "s3cret"), body, SignWebhookBody([]byte("s3cret"), []byte(body)))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, server.rpc)
}
