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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeLifecycleService records the three CA lifecycle requests and answers
// with canned responses.
type fakeLifecycleService struct {
	platformv1.UnimplementedCAServiceServer

	initReq      *platformv1.InitCARequest
	installReq   *platformv1.InstallCACertificatesRequest
	uninstallReq *platformv1.UninstallCACertificatesRequest

	initMessage      string
	uninstallMessage string
}

func (f *fakeLifecycleService) InitCA(_ context.Context, req *platformv1.InitCARequest) (*platformv1.InitCAResponse, error) {
	f.initReq = req
	msg := f.initMessage
	if msg == "" {
		msg = "CA initialised"
	}
	return &platformv1.InitCAResponse{
		Status: &platformv1.Status{Success: true, Message: msg},
		CaInfo: &platformv1.CAInfo{IsInitialized: true},
	}, nil
}

func (f *fakeLifecycleService) InstallCACertificates(_ context.Context, req *platformv1.InstallCACertificatesRequest) (*platformv1.InstallCACertificatesResponse, error) {
	f.installReq = req
	return &platformv1.InstallCACertificatesResponse{
		Status:                &platformv1.Status{Success: true, Message: "CA certificates installed"},
		CertificatesInstalled: 1,
		InstallPath:           "/tmp/ca.crt",
	}, nil
}

func (f *fakeLifecycleService) UninstallCACertificates(_ context.Context, req *platformv1.UninstallCACertificatesRequest) (*platformv1.UninstallCACertificatesResponse, error) {
	f.uninstallReq = req
	msg := f.uninstallMessage
	if msg == "" {
		msg = "CA certificates removed"
	}
	return &platformv1.UninstallCACertificatesResponse{
		Status: &platformv1.Status{Success: true, Message: msg},
	}, nil
}

func (f *fakeLifecycleService) reached() bool {
	return f.initReq != nil || f.installReq != nil || f.uninstallReq != nil
}

var lifecycleRoutes = []struct {
	name  string
	path  string
	scope string
}{
	{"init", "/api/v1/ca/init", InitScope},
	{"trust install", "/api/v1/ca/trust/install", TrustWriteScope},
	{"trust uninstall", "/api/v1/ca/trust/uninstall", TrustWriteScope},
}

func lifecycleRouter(granted fakeScopes, service *fakeLifecycleService) *mux.Router {
	logger := logging.NewLogger(slog.LevelError, os.Stdout)
	caRouter := NewCARouter(logger, &mockCertificateAuthority{initialized: true}, &mockHttpWriter{})
	if service != nil {
		caRouter.WithService(service)
	}
	caRouter.SetScopeAuthorizer(granted)
	return newTestRouter(caRouter)
}

func TestLifecycleRoutes_ServedWithTheirScope(t *testing.T) {
	for _, tc := range lifecycleRoutes {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeLifecycleService{}
			router := lifecycleRouter(fakeScopes{tc.scope: true}, service)
			rec := httptest.NewRecorder()
			body := `{"includeIntermediates": true}`
			if tc.name == "init" {
				body = `{}`
			}

			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader([]byte(body))))

			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, service.reached(), "the request did not reach the service")
			switch tc.name {
			case "trust install":
				if assert.NotNil(t, service.installReq) {
					assert.True(t, service.installReq.IncludeIntermediates)
				}
			case "trust uninstall":
				if assert.NotNil(t, service.uninstallReq) {
					assert.True(t, service.uninstallReq.IncludeIntermediates)
				}
			}
		})
	}
}

func TestLifecycleRoutes_RefusedWithoutTheirScope(t *testing.T) {
	for _, tc := range lifecycleRoutes {
		t.Run(tc.name, func(t *testing.T) {
			// Every CA scope but the route's own.
			granted := fakeScopes{
				RenewScope: true, RevokeScope: true, VerifyScope: true, SignCSRScope: true,
				InitScope: true, TrustWriteScope: true,
			}
			delete(granted, tc.scope)
			service := &fakeLifecycleService{}
			router := lifecycleRouter(granted, service)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader([]byte(`{}`))))

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.False(t, service.reached(), "the request reached the service without its scope")
		})
	}
}

func TestLifecycleRoutes_ServiceUnavailable(t *testing.T) {
	for _, tc := range lifecycleRoutes {
		t.Run(tc.name, func(t *testing.T) {
			router := lifecycleRouter(fakeScopes{tc.scope: true}, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, nil))

			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}

func TestLifecycleRoutes_IdempotentAnswers(t *testing.T) {
	t.Run("already initialised", func(t *testing.T) {
		service := &fakeLifecycleService{initMessage: "CA already initialised"}
		router := lifecycleRouter(fakeScopes{InitScope: true}, service)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ca/init", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "already initialised")
	})
	t.Run("nothing installed", func(t *testing.T) {
		service := &fakeLifecycleService{uninstallMessage: "nothing installed"}
		router := lifecycleRouter(fakeScopes{TrustWriteScope: true}, service)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ca/trust/uninstall", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "nothing installed")
	})
}
