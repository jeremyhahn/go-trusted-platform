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

package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeCAService stands in for the daemon's CAGRPCService, the service the
// renew and verify handlers delegate to. It records what reached it.
type fakeCAService struct {
	platformv1.UnimplementedCAServiceServer

	renewReq  *platformv1.RenewCertificateRequest
	verifyReq *platformv1.VerifyCertificateRequest
	err       error
}

func (f *fakeCAService) RenewCertificate(_ context.Context, req *platformv1.RenewCertificateRequest) (*platformv1.RenewCertificateResponse, error) {
	f.renewReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.RenewCertificateResponse{
		OldCertificate: &platformv1.Certificate{Serial: req.GetSerial()},
		NewCertificate: &platformv1.Certificate{Serial: "beef02"},
	}, nil
}

func (f *fakeCAService) VerifyCertificate(_ context.Context, req *platformv1.VerifyCertificateRequest) (*platformv1.VerifyCertificateResponse, error) {
	f.verifyReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.VerifyCertificateResponse{Valid: true}, nil
}

// fakeScopes is a ScopeAuthorizer granting a fixed scope set, refusing the
// rest with 403 as the platform-token middleware does.
type fakeScopes map[string]bool

func (f fakeScopes) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f[scope] {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func renewRequest(serial, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates/"+serial+"/renew", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return mux.SetURLVars(req, map[string]string{"serial": serial})
}

func TestRenewCertificate_Success(t *testing.T) {
	service := &fakeCAService{}
	handlers, writer := newTestHandlers(nil)
	handlers.WithService(service)
	rec := httptest.NewRecorder()

	handlers.RenewCertificate(rec, renewRequest("5a17e5", `{"validDays":30,"serial":"ignored"}`))

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	require.NotNil(t, service.renewReq)
	assert.Equal(t, "5a17e5", service.renewReq.GetSerial(), "the path serial wins over the body")
	assert.Equal(t, int32(30), service.renewReq.GetValidDays())
	payload := decodeProtoBody(t, rec)
	require.IsType(t, map[string]interface{}{}, payload["newCertificate"])
	assert.Equal(t, "beef02", payload["newCertificate"].(map[string]interface{})["serial"])
}

// TestRenewCertificate_ChunkedBody proves a chunked body (ContentLength -1)
// is decoded and its fields reach the service rather than being dropped.
func TestRenewCertificate_ChunkedBody(t *testing.T) {
	service := &fakeCAService{}
	handlers, writer := newTestHandlers(nil)
	handlers.WithService(service)
	req := renewRequest("5a17e5", `{"validDays":45}`)
	req.ContentLength = -1
	rec := httptest.NewRecorder()

	handlers.RenewCertificate(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	require.NotNil(t, service.renewReq)
	assert.Equal(t, int32(45), service.renewReq.GetValidDays())
}

func TestRenewCertificate_Error(t *testing.T) {
	t.Run("503 without the CA service", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		handlers.RenewCertificate(httptest.NewRecorder(), renewRequest("5a17e5", `{"validDays":30}`))

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	for _, serial := range []string{"", "not-a-serial", strings.Repeat("a", maxSerialHexDigits+1)} {
		t.Run("400 for malformed serial "+serial, func(t *testing.T) {
			service := &fakeCAService{}
			handlers, writer := newTestHandlers(nil)
			handlers.WithService(service)

			handlers.RenewCertificate(httptest.NewRecorder(), renewRequest(serial, `{"validDays":30}`))

			assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
			assert.Nil(t, service.renewReq, "a malformed serial must not reach the service")
		})
	}

	t.Run("400 for a body that is not JSON", func(t *testing.T) {
		service := &fakeCAService{}
		handlers, writer := newTestHandlers(nil)
		handlers.WithService(service)

		handlers.RenewCertificate(httptest.NewRecorder(), renewRequest("5a17e5", "not json"))

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
		assert.Nil(t, service.renewReq)
	})

	t.Run("404 for a serial the CA never issued", func(t *testing.T) {
		service := &fakeCAService{err: status.Error(codes.NotFound, "certificate not found")}
		handlers, writer := newTestHandlers(nil)
		handlers.WithService(service)

		handlers.RenewCertificate(httptest.NewRecorder(), renewRequest("dead0001", `{"validDays":30}`))

		assert.Equal(t, http.StatusNotFound, writer.lastStatus)
	})

	t.Run("400 when the service refuses the arguments", func(t *testing.T) {
		service := &fakeCAService{err: status.Error(codes.InvalidArgument, "valid_days must be positive")}
		handlers, writer := newTestHandlers(nil)
		handlers.WithService(service)

		handlers.RenewCertificate(httptest.NewRecorder(), renewRequest("5a17e5", ""))

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	})
}

func verifyRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestVerifyCertificate_Success(t *testing.T) {
	service := &fakeCAService{}
	handlers, writer := newTestHandlers(nil)
	handlers.WithService(service)
	rec := httptest.NewRecorder()

	// certificate_pem is a bytes field: base64 in proto JSON.
	handlers.VerifyCertificate(rec, verifyRequest(`{"certificatePem":"LS0tLS1CRUdJTg=="}`))

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	require.NotNil(t, service.verifyReq)
	assert.Equal(t, []byte("-----BEGIN"), service.verifyReq.GetCertificatePem())
	assert.Equal(t, true, decodeProtoBody(t, rec)["valid"])
}

func TestVerifyCertificate_Error(t *testing.T) {
	t.Run("503 without the CA service", func(t *testing.T) {
		handlers, writer := newTestHandlers(nil)

		handlers.VerifyCertificate(httptest.NewRecorder(), verifyRequest(`{"certificatePem":"eA=="}`))

		assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
	})

	t.Run("400 for a body that is not JSON", func(t *testing.T) {
		service := &fakeCAService{}
		handlers, writer := newTestHandlers(nil)
		handlers.WithService(service)

		handlers.VerifyCertificate(httptest.NewRecorder(), verifyRequest("not json"))

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
		assert.Nil(t, service.verifyReq)
	})

	t.Run("400 when the service cannot parse the certificate", func(t *testing.T) {
		service := &fakeCAService{err: status.Error(codes.InvalidArgument, "certificate is required")}
		handlers, writer := newTestHandlers(nil)
		handlers.WithService(service)

		handlers.VerifyCertificate(httptest.NewRecorder(), verifyRequest(`{}`))

		assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	})
}

// certificateItemRoutes are the three routes #452 puts behind a scope, with
// the scope each must demand.
var certificateItemRoutes = []struct {
	name   string
	method string
	path   string
	body   string
	scope  string
}{
	{"renew", http.MethodPost, "/api/v1/ca/certificates/5a17e5/renew", `{"validDays":30}`, RenewScope},
	{"revoke", http.MethodDelete, "/api/v1/ca/certificates/5a17e5", "", RevokeScope},
	{"verify", http.MethodPost, "/api/v1/ca/certificates/verify", `{"certificatePem":"eA=="}`, VerifyScope},
}

// scopedCARouter serves the CA surface with the given scopes granted. The CA
// knows serial 5a17e5, so revoke succeeds once past the scope check.
func scopedCARouter(granted fakeScopes) (*mux.Router, *fakeCAService) {
	logger := logging.NewLogger(slog.LevelError, os.Stdout)
	mockCA := &mockCertificateAuthority{
		initialized: true,
		certStore: &mockCertStore{
			getCertificateFn: func(string) (*x509.Certificate, error) {
				return createTestCertificate("item.example.com"), nil
			},
		},
	}
	service := &fakeCAService{}
	caRouter := NewCARouter(logger, mockCA, &mockHttpWriter{}).WithService(service)
	caRouter.SetScopeAuthorizer(granted)
	return newTestRouter(caRouter), service
}

func TestCertificateItemRoutes_ServedWithTheirScope(t *testing.T) {
	for _, tc := range certificateItemRoutes {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := scopedCARouter(fakeScopes{tc.scope: true})
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(tc.body))))

			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}
}

func TestCertificateItemRoutes_RefusedWithoutTheirScope(t *testing.T) {
	for _, tc := range certificateItemRoutes {
		t.Run(tc.name, func(t *testing.T) {
			// Every scope but the route's own: a neighbouring CA scope must not do.
			granted := fakeScopes{RenewScope: true, RevokeScope: true, VerifyScope: true, SignCSRScope: true}
			delete(granted, tc.scope)
			router, service := scopedCARouter(granted)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(tc.body))))

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Nil(t, service.renewReq, "renew reached the service without its scope")
			assert.Nil(t, service.verifyReq, "verify reached the service without its scope")
		})
	}
}

// TestPathSerial covers the serial validation every item route shares.
func TestPathSerial(t *testing.T) {
	handlers, _ := newTestHandlers(nil)
	serialOf := func(serial string) (string, error) {
		r := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"serial": serial})
		return handlers.pathSerial(r)
	}

	for _, ok := range []string{"5a17e5", "ABCDEF0123", strings.Repeat("f", maxSerialHexDigits)} {
		got, err := serialOf(ok)
		assert.NoError(t, err, ok)
		assert.Equal(t, ok, got)
	}
	for _, bad := range []string{"", "5a17e5g", "12:34", strings.Repeat("f", maxSerialHexDigits+1)} {
		_, err := serialOf(bad)
		var invalid ErrInvalidSerialNumber
		assert.True(t, errors.As(err, &invalid), "%q: got %v", bad, err)
	}
}
