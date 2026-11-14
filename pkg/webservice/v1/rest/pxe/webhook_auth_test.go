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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	server := &operatorPXE{resp: &platformv1.PXEWebhookCompleteResponse{Status: handlerOK}}
	sig := SignWebhookBody([]byte("s3cret"), []byte(webhookBody))

	rec := postWebhook(webhookRoot(server, "s3cret"), webhookBody, sig)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "WebhookComplete", server.rpc)
	got, ok := server.req.(*platformv1.PXEWebhookCompleteRequest)
	require.True(t, ok)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", got.MacAddress)
	assert.Equal(t, "node-1", got.Hostname)
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
