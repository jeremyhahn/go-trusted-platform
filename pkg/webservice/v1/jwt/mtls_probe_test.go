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

package jwt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	loginpkg "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #201: the login page probes /api/v1/auth/mtls/probe before it offers
// "Sign in with mTLS", and the webservice had no such route. The probe
// answers from the login driver /login runs, so it never offers a sign-in
// the login then refuses.

// bindableMTLSBinder is the mTLS binder as it will be once
// go-quicbaas#857 lets the caller's certificate be bound: its ceremony
// opens. It stands in for that future so the probe's "available" answer
// is pinned before the real binder can give it.
type bindableMTLSBinder struct{}

func (bindableMTLSBinder) Type() quicbaas.FactorType { return quicbaas.FactorTypeMTLS }

func (bindableMTLSBinder) Begin(*http.Request) (quicbaas.BeginLoginRequest, error) {
	return quicbaas.BeginLoginRequest{Type: quicbaas.FactorTypeMTLS}, nil
}

func (bindableMTLSBinder) Challenge(*quicbaas.BeginLoginResponse) (any, error) { return nil, nil }

func (bindableMTLSBinder) Finish(*http.Request, string) (quicbaas.FinishLoginRequest, error) {
	return quicbaas.FinishLoginRequest{Type: quicbaas.FactorTypeMTLS}, nil
}

func (bindableMTLSBinder) Tenant(context.Context, *quicbaas.Identity) (string, error) {
	return "tenant-a", nil
}

func driverWithBinder(t *testing.T, handler *RestHandler, client loginpkg.UnifiedLoginClient,
	binder loginpkg.Binder) *loginpkg.Driver {

	t.Helper()
	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	driver, err := loginpkg.NewDriver(loginpkg.DriverParams{
		Client:         client,
		Binders:        []loginpkg.Binder{binder},
		SessionIssuer:  handler.jwtService,
		Logger:         logger,
		ResponseWriter: response.NewResponseWriter(logger, nil),
	})
	require.NoError(t, err)
	return driver
}

func probeMTLS(handler *RestHandler, withClientCert bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodHead, "/api/v1/auth/mtls/probe", nil)
	if withClientCert {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	}
	rec := httptest.NewRecorder()
	handler.ProbeMTLS(rec, req)
	return rec
}

func TestProbeMTLS_NotSupportedWithoutALoginDriver(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)

	rec := probeMTLS(handler, true)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestProbeMTLS_NotSupportedWhileTheBinderDeclines(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	client := &stubLoginClient{bearer: "broker.issued.bearer"}
	handler.SetLoginDriver(newLoginDriverForTest(t, client, handler.jwtService, nil))

	// A certificate does not help: /login declines the factor, so the
	// probe must not offer it.
	rec := probeMTLS(handler, true)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Zero(t, client.beginCalls, "a probe must not open a ceremony")
}

func TestProbeMTLS_NotSupportedWithoutABackbone(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	handler.SetLoginDriver(driverWithBinder(t, handler, nil, bindableMTLSBinder{}))

	assert.Equal(t, http.StatusNotImplemented, probeMTLS(handler, true).Code)
}

func TestProbeMTLS_NoClientCertificate(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	client := &stubLoginClient{bearer: "broker.issued.bearer"}
	handler.SetLoginDriver(driverWithBinder(t, handler, client, bindableMTLSBinder{}))

	assert.Equal(t, http.StatusUnauthorized, probeMTLS(handler, false).Code)
	assert.Zero(t, client.beginCalls)
}

func TestProbeMTLS_AvailableWithAClientCertificate(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	client := &stubLoginClient{bearer: "broker.issued.bearer"}
	handler.SetLoginDriver(driverWithBinder(t, handler, client, bindableMTLSBinder{}))

	rec := probeMTLS(handler, true)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Zero(t, client.beginCalls,
		"the probe must not contact the backbone: it is no oracle for enrolled certificates")
}
