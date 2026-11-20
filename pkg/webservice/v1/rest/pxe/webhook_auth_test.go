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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	server := newWebhookPXE("aa:bb:cc:dd:ee:ff", fingerprintOf(cert))
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))

	rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, verifiedTLS(cert))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, server.report, "the service saw no report")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", server.report.MacAddress)
	assert.Equal(t, "node-1", server.report.Hostname)
}

// webhookPXE is a PXE service holding one device, the IDevID fingerprint
// recorded for it at enrolment (the binding the webhook checks its caller
// against, ruling 673), and the report it received.
type webhookPXE struct {
	platformv1.UnimplementedPXEServiceServer
	mu           sync.Mutex
	fingerprints map[string]string
	report       *platformv1.PXEWebhookCompleteRequest
	// afterLookup runs after a fingerprint lookup has read its answer:
	// the window between a separate check and the transition.
	afterLookup func(mac string)
}

func newWebhookPXE(mac, fingerprint string) *webhookPXE {
	return &webhookPXE{fingerprints: map[string]string{mac: fingerprint}}
}

// RecordedIDevIDFingerprint answers the fingerprint recorded for mac, and
// NotFound for a MAC with no device.
func (s *webhookPXE) RecordedIDevIDFingerprint(_ context.Context, mac string) (string, error) {
	s.mu.Lock()
	fp, ok := s.fingerprints[mac]
	s.mu.Unlock()
	if s.afterLookup != nil {
		s.afterLookup(mac)
	}
	if !ok {
		return "", status.Error(codes.NotFound, "device not found")
	}
	return fp, nil
}

func (s *webhookPXE) WebhookComplete(_ context.Context, req *platformv1.PXEWebhookCompleteRequest) (*platformv1.PXEWebhookCompleteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report = req
	return &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}, nil
}

// WebhookCompleteForIDevID is the backend's compare-and-transition: under
// the device lock it compares the authenticated fingerprint with the one
// recorded and only then applies the report.
func (s *webhookPXE) WebhookCompleteForIDevID(_ context.Context, req *platformv1.PXEWebhookCompleteRequest, fingerprint string) (*platformv1.PXEWebhookCompleteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, ok := s.fingerprints[req.GetMacAddress()]
	if !ok {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	if fp == "" || fp != fingerprint {
		return nil, status.Error(codes.PermissionDenied, "the IDevID fingerprint is not the device's")
	}
	s.report = req
	return &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}, nil
}

// recordIDevIDFingerprint is enrolment recording a new IDevID for mac.
func (s *webhookPXE) recordIDevIDFingerprint(mac, fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fingerprints[mac] = fingerprint
}

// TestWebhook_FingerprintIsComparedWithTheTransition pins #1896 Codex r2:
// a report signed with a superseded IDevID A passes a separate lookup, then
// enrolment records B before the transition; the completion is refused.
func TestWebhook_FingerprintIsComparedWithTheTransition(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))
	certA := deviceCert(t, 1001)
	certB := deviceCert(t, 2002)
	server := newWebhookPXE(mac, fingerprintOf(certA))
	server.afterLookup = func(m string) {
		server.recordIDevIDFingerprint(m, fingerprintOf(certB))
	}

	rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, verifiedTLS(certA))
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	server.mu.Lock()
	defer server.mu.Unlock()
	assert.Nil(t, server.report, "the superseded identity completed the install")
}

// fingerprintOf is the IDevID fingerprint recorded at enrolment: the
// lower-case hex SHA-256 of the certificate's DER.
func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
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
			server := newWebhookPXE("aa:bb:cc:dd:ee:ff", fingerprintOf(cert))
			rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, state)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.Nil(t, server.report, "the service was reached")
		})
	}
}

// TestWebhook_RefusesAnotherDevicesIdentity pins the binding: a verified
// client may report only for the device whose IDevID fingerprint was
// recorded at enrolment (ruling 673).
func TestWebhook_RefusesAnotherDevicesIdentity(t *testing.T) {
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))
	recorded := deviceCert(t, 1001)
	caller := deviceCert(t, 2002)
	for name, server := range map[string]*webhookPXE{
		"another device's IDevID": newWebhookPXE("aa:bb:cc:dd:ee:ff", fingerprintOf(recorded)),
		"no IDevID recorded":      newWebhookPXE("aa:bb:cc:dd:ee:ff", ""),
		"unknown MAC":             newWebhookPXE("11:22:33:44:55:66", fingerprintOf(caller)),
	} {
		t.Run(name, func(t *testing.T) {
			rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, verifiedTLS(caller))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Nil(t, server.report, "the service was reached")
		})
	}
}

// TestWebhook_SameSerialOtherKeyIsRefused pins that the certificate serial
// is no longer the binding: a certificate carrying the recorded IDevID's
// serial, but another key, is refused.
func TestWebhook_SameSerialOtherKeyIsRefused(t *testing.T) {
	recorded := deviceCert(t, 1001)
	impostor := deviceCert(t, 1001)
	require.Equal(t, recorded.SerialNumber, impostor.SerialNumber)
	server := newWebhookPXE("aa:bb:cc:dd:ee:ff", fingerprintOf(recorded))
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))

	rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, sig, verifiedTLS(impostor))

	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Nil(t, server.report, "the service was reached")
}

// TestWebhook_BoundIdentityStillNeedsTheSignature keeps the HMAC as the
// second factor: the bound device's certificate without the signature is 401.
func TestWebhook_BoundIdentityStillNeedsTheSignature(t *testing.T) {
	cert := deviceCert(t, 1001)
	server := newWebhookPXE("aa:bb:cc:dd:ee:ff", fingerprintOf(cert))
	rec := postWebhookAs(webhookRoot(server, "s3cret"), webhookBody, "", verifiedTLS(cert))
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
