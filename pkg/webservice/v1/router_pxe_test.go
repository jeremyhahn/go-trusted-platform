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

package v1

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	pxeWebhookPath = "/api/v1/pxe/webhook/complete"
	pxeInstalling  = "installing"
	pxeInstalled   = "installed"
)

// recordingPXEServer holds one device mid-install. A completion that
// reaches it moves the device to installed, the state change an
// anonymous caller could force before the webhook checked a signature.
type recordingPXEServer struct {
	platformv1.UnimplementedPXEServiceServer
	state string
	calls int
}

// pxeDeviceCert is the client certificate recorded on the reporting device.
var pxeDeviceCert = &x509.Certificate{SerialNumber: big.NewInt(7001)}

// GetDeviceByMAC answers the device record the webhook binds its caller
// to: the reported MAC, enrolled with pxeDeviceCert.
func (s *recordingPXEServer) GetDeviceByMAC(_ context.Context, req *platformv1.GetPXEDeviceByMACRequest) (*platformv1.GetPXEDeviceByMACResponse, error) {
	return &platformv1.GetPXEDeviceByMACResponse{Device: &platformv1.PXEDeviceInfo{
		Id:                "dev-1",
		MacAddress:        req.GetMacAddress(),
		CertificateSerial: pxeDeviceCert.SerialNumber.String(),
	}}, nil
}

// RecordedIDevIDFingerprint answers the IDevID fingerprint recorded at
// enrolment (ruling 673): the presented certificate's, so the signed
// report reaches the handler.
func (s *recordingPXEServer) RecordedIDevIDFingerprint(_ context.Context, _ string) (string, error) {
	sum := sha256.Sum256(pxeDeviceCert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func (s *recordingPXEServer) WebhookComplete(
	_ context.Context,
	_ *platformv1.PXEWebhookCompleteRequest,
) (*platformv1.PXEWebhookCompleteResponse, error) {
	s.calls++
	s.state = pxeInstalled
	return &platformv1.PXEWebhookCompleteResponse{}, nil
}

const pxeTestWebhookSecret = "router-test-webhook-secret"

const pxeWebhookBody = `{"mac_address":"52:54:00:12:34:56","success":true}`

// postPXEWebhook builds the web service router with the webhook switch set
// as given and the secret pxeTestWebhookSecret, and posts one install
// completion to it carrying signature, as a booting node would.
func postPXEWebhook(t *testing.T, server *recordingPXEServer, enabled bool, signature string) int {
	t.Helper()

	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{
		tokenHandler:      &mockTokenHandler{},
		responseWriter:    respWriter,
		pxeService:        server,
		pxeWebhookEnabled: enabled,
		pxeWebhookSecret:  pxeTestWebhookSecret,
	}
	root := mux.NewRouter()
	NewRouter(logger, nil, nil, nil, registry, respWriter).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	req := httptest.NewRequest(http.MethodPost, pxeWebhookPath, strings.NewReader(pxeWebhookBody))
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set(restpxe.WebhookSignatureHeader, signature)
	}
	// The booting node presents the certificate its PXE device record holds,
	// verified by the listener (VerifyClientCertIfGiven).
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pxeDeviceCert},
		VerifiedChains:   [][]*x509.Certificate{{pxeDeviceCert}},
	}
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}

func signedPXEWebhook() string {
	return restpxe.SignWebhookBody([]byte(pxeTestWebhookSecret), []byte(pxeWebhookBody))
}

// TestPXEWebhook_DisabledIsNotServed: unless the operator enabled it the
// path is unknown and the device cannot be moved by it.
func TestPXEWebhook_DisabledIsNotServed(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, false, signedPXEWebhook())

	assert.Equal(t, http.StatusNotFound, code)
	assert.Zero(t, server.calls, "a disabled webhook reached WebhookComplete")
	assert.Equal(t, pxeInstalling, server.state)
}

// TestPXEWebhook_SignedReportReachesTheHandler: the registry's
// WebhookSecret reaches the router, so a report signed with it moves the
// device.
func TestPXEWebhook_SignedReportReachesTheHandler(t *testing.T) {
	server := &recordingPXEServer{state: pxeInstalling}

	code := postPXEWebhook(t, server, true, signedPXEWebhook())

	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, 1, server.calls)
	assert.Equal(t, pxeInstalled, server.state)
}

// TestPXEWebhook_UnsignedReportIsRefused pins #240: a caller that knows a
// device's MAC but not the secret cannot report its install complete.
func TestPXEWebhook_UnsignedReportIsRefused(t *testing.T) {
	for name, signature := range map[string]string{
		"no signature":    "",
		"wrong secret":    restpxe.SignWebhookBody([]byte("guessed"), []byte(pxeWebhookBody)),
		"other body":      restpxe.SignWebhookBody([]byte(pxeTestWebhookSecret), []byte(`{}`)),
		"malformed value": "sha256=zz",
	} {
		t.Run(name, func(t *testing.T) {
			server := &recordingPXEServer{state: pxeInstalling}

			code := postPXEWebhook(t, server, true, signature)

			assert.Equal(t, http.StatusUnauthorized, code)
			assert.Zero(t, server.calls, "an unsigned report reached WebhookComplete")
			assert.Equal(t, pxeInstalling, server.state)
		})
	}
}

// pxeConfigRegistry answers the webhook switch and key from a real
// HandlerRegistry whose params were filled from a pxe: config, so the route
// is built from the config rather than from hand-set registry fields.
type pxeConfigRegistry struct {
	*testHandlerRegistry
	real *HandlerRegistry
}

func (r *pxeConfigRegistry) PXEWebhookEnabled() bool  { return r.real.PXEWebhookEnabled() }
func (r *pxeConfigRegistry) PXEWebhookSecret() string { return r.real.PXEWebhookSecret() }

// TestPXEWebhookRouteFromConfig: the daemon pxe: section's webhook-enabled
// and webhook-secret reach the registry, so the install-completion route is
// served exactly when the section and its webhook are both enabled (#1694).
func TestPXEWebhookRouteFromConfig(t *testing.T) {
	cases := []struct {
		name    string
		section *pxe.DaemonConfig
		want    int
	}{
		{"no pxe section", nil, http.StatusNotFound},
		{"pxe disabled", &pxe.DaemonConfig{WebhookEnabled: true, WebhookSecret: pxeTestWebhookSecret}, http.StatusNotFound},
		{"webhook disabled", &pxe.DaemonConfig{Enabled: true, WebhookSecret: pxeTestWebhookSecret}, http.StatusNotFound},
		{"webhook enabled", &pxe.DaemonConfig{Enabled: true, WebhookEnabled: true, WebhookSecret: pxeTestWebhookSecret}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &recordingPXEServer{state: pxeInstalling}
			var params RegistryParams
			params.SetPXEWebhook(tc.section)

			logger := testLogger()
			respWriter := response.NewResponseWriter(logger, nil)
			registry := &pxeConfigRegistry{
				testHandlerRegistry: &testHandlerRegistry{
					tokenHandler:   &mockTokenHandler{},
					responseWriter: respWriter,
					pxeService:     server,
				},
				real: &HandlerRegistry{params: params},
			}
			root := mux.NewRouter()
			NewRouter(logger, nil, nil, nil, registry, respWriter).
				RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

			req := httptest.NewRequest(http.MethodPost, pxeWebhookPath, strings.NewReader(pxeWebhookBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(restpxe.WebhookSignatureHeader, signedPXEWebhook())
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{pxeDeviceCert},
				VerifiedChains:   [][]*x509.Certificate{{pxeDeviceCert}},
			}
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			assert.Equal(t, tc.want, rec.Code)
		})
	}
}
