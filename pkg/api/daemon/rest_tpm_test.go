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

//go:build codec_msgpack

package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// answeringQuoteService answers every quote with the same quote and records
// that it was asked. Every other TPM RPC is unimplemented.
type answeringQuoteService struct {
	platformv1.UnimplementedTPMServiceServer

	quoted bool
}

func (s *answeringQuoteService) Quote(context.Context, *platformv1.QuoteRequest) (*platformv1.QuoteResponse, error) {
	s.quoted = true
	return &platformv1.QuoteResponse{Quote: []byte("quote")}, nil
}

func (s *answeringQuoteService) VerifyQuote(context.Context, *platformv1.VerifyQuoteRequest) (*platformv1.VerifyQuoteResponse, error) {
	return &platformv1.VerifyQuoteResponse{Verified: true}, nil
}

func newTPMTestRESTServer(t *testing.T) *RESTServer {
	t.Helper()
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)
	return server
}

// serveTPMRoute sends one request to server's router, with bearer as its
// platform token when it is set.
func serveTPMRoute(server *RESTServer, method, path, bearer string) *httptest.ResponseRecorder {
	return serveTPMBody(server, method, path, bearer, "")
}

// serveTPMBody is serveTPMRoute with a JSON request body.
func serveTPMBody(server *RESTServer, method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	return w
}

func TestRESTServer_SetTPMHandlers_NilMountsNothing(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)

	server.SetTPMHandlers(nil, nil)

	assert.Equal(t, http.StatusNotFound, serveTPMRoute(server, http.MethodPost, "/api/v1/tpm/quote", "token").Code)
}

// Without the platform-token validator nobody holds a TPM scope, so every
// mounted route refuses.
func TestRESTServer_SetTPMHandlers_WithoutAValidatorRefuses(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)
	quotes := &answeringQuoteService{}

	server.SetTPMHandlers(quotes, nil)

	assert.Equal(t, http.StatusForbidden, serveTPMRoute(server, http.MethodPost, "/api/v1/tpm/quote", "token").Code)
	assert.False(t, quotes.quoted)
}

func TestRESTServer_SetTPMHandlers_ServesAScopedToken(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"tpm:read"})
	writer := key.sign(t, "installer", "", []string{"tpm:write"})

	server := newTPMTestRESTServer(t)
	quotes := &answeringQuoteService{}
	server.SetTPMHandlers(quotes, validator)

	t.Run("a tpm:read token quotes through the quote service", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodPost, "/api/v1/tpm/quote", reader)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.True(t, quotes.quoted)
	})

	t.Run("a token without tpm:read is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, serveTPMRoute(server, http.MethodPost, "/api/v1/tpm/quote/verify", writer).Code)
	})

	t.Run("no token is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, serveTPMRoute(server, http.MethodPost, "/api/v1/tpm/quote/verify", "").Code)
	})
}

// errCredentialMismatch is what activatingTPM fails with when told to.
type errCredentialMismatch struct{}

func (errCredentialMismatch) Error() string { return "the credential was not made for this key" }

// activatingTPM activates every credential to the same secret, or fails,
// and records what it was given.
type activatingTPM struct {
	infoOnlyTPM

	fail            bool
	credentialBlob  []byte
	encryptedSecret []byte
}

func (t *activatingTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	t.credentialBlob, t.encryptedSecret = credentialBlob, encryptedSecret
	if t.fail {
		return nil, errCredentialMismatch{}
	}
	return []byte("activated"), nil
}

// POST /api/v1/tpm/activate-credential runs TPMService.ActivateCredential on
// the SDK's camelCase body, under tpm:write like its gRPC twin. The old
// {credential_blob, secret} body is refused, never half-read.
func TestRESTServer_SetTPMHandlers_ActivatesCredentials(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"tpm:read"})
	writer := key.sign(t, "installer", "", []string{"tpm:write"})
	const path = "/api/v1/tpm/activate-credential"
	const body = `{"credentialBlob":"YmxvYg==","encryptedSecret":"c2VjcmV0"}`

	mount := func(tpm *activatingTPM) *RESTServer {
		server := newTPMTestRESTServer(t)
		service := NewTPMGRPCService(logging.NewLogger(0, nil))
		service.SetTPM2Service(tpm)
		server.SetTPMHandlers(service, validator)
		return server
	}

	t.Run("a tpm:write token activates the credential", func(t *testing.T) {
		tpm := &activatingTPM{}
		w := serveTPMBody(mount(tpm), http.MethodPost, path, writer, body)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.JSONEq(t, `{"secret":"YWN0aXZhdGVk"}`, w.Body.String())
		assert.Equal(t, []byte("blob"), tpm.credentialBlob)
		assert.Equal(t, []byte("secret"), tpm.encryptedSecret)
	})

	t.Run("a tpm:read token is refused", func(t *testing.T) {
		tpm := &activatingTPM{}
		assert.Equal(t, http.StatusForbidden, serveTPMBody(mount(tpm), http.MethodPost, path, reader, body).Code)
		assert.Nil(t, tpm.credentialBlob)
	})

	t.Run("the old IDevID-shaped body is refused", func(t *testing.T) {
		tpm := &activatingTPM{}
		w := serveTPMBody(mount(tpm), http.MethodPost, path, writer, `{"credential_blob":"YmxvYg==","secret":"c2VjcmV0"}`)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), `unknown field \"secret\"`)
		assert.Nil(t, tpm.credentialBlob)
	})

	t.Run("a missing encrypted secret is a bad request", func(t *testing.T) {
		tpm := &activatingTPM{}
		w := serveTPMBody(mount(tpm), http.MethodPost, path, writer, `{"credentialBlob":"YmxvYg=="}`)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Nil(t, tpm.credentialBlob)
	})

	t.Run("a TPM that cannot activate is an internal error", func(t *testing.T) {
		w := serveTPMBody(mount(&activatingTPM{fail: true}), http.MethodPost, path, writer, body)

		assert.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	})
}

// The daemon mounts the TPM handlers before it injects the TPM into the TPM
// service, so the REST routes must reach a TPM injected after mounting.
func TestRESTServer_SetTPMHandlers_ReceivesTheTPM(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"tpm:read"})

	t.Run("injected after mounting", func(t *testing.T) {
		server := newTPMTestRESTServer(t)
		tpm := NewTPMGRPCService(logging.NewLogger(0, nil))
		server.SetTPMHandlers(tpm, validator)
		tpm.SetTPM2Service(&infoOnlyTPM{info: "after-mount"})

		w := serveTPMRoute(server, http.MethodGet, "/api/v1/tpm/info", reader)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "after-mount")
	})

	t.Run("never injected is 503", func(t *testing.T) {
		server := newTPMTestRESTServer(t)
		server.SetTPMHandlers(NewTPMGRPCService(logging.NewLogger(0, nil)), validator)

		assert.Equal(t, http.StatusServiceUnavailable, serveTPMRoute(server, http.MethodGet, "/api/v1/tpm/info", reader).Code)
	})
}
