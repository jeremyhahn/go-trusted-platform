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

package vtpm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testableGeneratorService implements GeneratorServicer with configurable responses
type testableGeneratorService struct {
	generateFn  func(ctx context.Context, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error)
	getFn       func(ctx context.Context, id string) (*vtpm.VTPMInstance, error)
	getByProfFn func(ctx context.Context, profileID uint64) (*vtpm.VTPMInstance, error)
	deleteFn    func(ctx context.Context, id string) error
	listFn      func(ctx context.Context) ([]*vtpm.VTPMInstance, error)
	startFn     func(ctx context.Context, id string) error
	stopFn      func(ctx context.Context, id string) error
	isRunningFn func(id string) bool
	exportEKFn  func(ctx context.Context, id string) (*x509.Certificate, error)
	ekFPFn      func(ctx context.Context, id string) (string, error)
}

func (s *testableGeneratorService) Generate(ctx context.Context, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error) {
	if s.generateFn != nil {
		return s.generateFn(ctx, opts)
	}
	return &vtpm.VTPMInstance{ID: "vtpm-new", CreatedAt: time.Now()}, nil
}

func (s *testableGeneratorService) GenerateForProfile(ctx context.Context, profile *entities.DeviceProfile, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error) {
	return s.Generate(ctx, opts)
}

func (s *testableGeneratorService) Get(ctx context.Context, id string) (*vtpm.VTPMInstance, error) {
	if s.getFn != nil {
		return s.getFn(ctx, id)
	}
	return &vtpm.VTPMInstance{ID: id, SocketPath: "/run/vtpm/" + id + ".sock", CreatedAt: time.Now()}, nil
}

func (s *testableGeneratorService) GetByProfile(ctx context.Context, profileID uint64) (*vtpm.VTPMInstance, error) {
	if s.getByProfFn != nil {
		return s.getByProfFn(ctx, profileID)
	}
	return &vtpm.VTPMInstance{ID: "vtpm-profile", DeviceProfileID: profileID, CreatedAt: time.Now()}, nil
}

func (s *testableGeneratorService) Delete(ctx context.Context, id string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, id)
	}
	return nil
}

func (s *testableGeneratorService) List(ctx context.Context) ([]*vtpm.VTPMInstance, error) {
	if s.listFn != nil {
		return s.listFn(ctx)
	}
	return []*vtpm.VTPMInstance{{ID: "vtpm-1", CreatedAt: time.Now()}}, nil
}

func (s *testableGeneratorService) Start(ctx context.Context, id string) error {
	if s.startFn != nil {
		return s.startFn(ctx, id)
	}
	return nil
}

func (s *testableGeneratorService) Stop(ctx context.Context, id string) error {
	if s.stopFn != nil {
		return s.stopFn(ctx, id)
	}
	return nil
}

func (s *testableGeneratorService) IsRunning(id string) bool {
	if s.isRunningFn != nil {
		return s.isRunningFn(id)
	}
	return false
}

func (s *testableGeneratorService) ExportEKCertificate(ctx context.Context, id string) (*x509.Certificate, error) {
	if s.exportEKFn != nil {
		return s.exportEKFn(ctx, id)
	}
	return createTestX509Cert(), nil
}

func (s *testableGeneratorService) GetEKFingerprint(ctx context.Context, id string) (string, error) {
	if s.ekFPFn != nil {
		return s.ekFPFn(ctx, id)
	}
	return "AA:BB:CC:DD:EE:FF", nil
}

func (s *testableGeneratorService) Close() error { return nil }

func createTestX509Cert() *x509.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func newTestVTPMHandler(t *testing.T, svc GeneratorServicer) RestHandler {
	t.Helper()
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	h, err := NewHandler(HandlerParams{
		Logger:           logger,
		GeneratorService: svc,
		ResponseWriter:   respWriter,
	})
	require.NoError(t, err)
	return h
}

// CreateInstance tests

func TestHandler_CreateInstance_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	body := `{"config": {"hostname": "test-host"}}`
	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.CreateInstance(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestHandler_CreateInstance_EmptyBody(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances", bytes.NewBufferString(""))
	rec := httptest.NewRecorder()

	h.CreateInstance(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestHandler_CreateInstance_InvalidEKAlgorithm(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	body := `{"config": {"ek_algorithm": "DES"}}`
	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.CreateInstance(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_CreateInstance_ValidEKAlgorithm(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	body := `{"config": {"ek_algorithm": "ECC"}}`
	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	h.CreateInstance(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

// ListInstances tests

func TestHandler_ListInstances_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances", nil)
	rec := httptest.NewRecorder()

	h.ListInstances(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_ListInstances_Error(t *testing.T) {
	svc := &testableGeneratorService{
		listFn: func(ctx context.Context) ([]*vtpm.VTPMInstance, error) {
			return nil, errors.New("database error")
		},
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances", nil)
	rec := httptest.NewRecorder()

	h.ListInstances(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// GetInstance tests

func TestHandler_GetInstance_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-123", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-123"})
	rec := httptest.NewRecorder()

	h.GetInstance(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_GetInstance_NotFound(t *testing.T) {
	svc := &testableGeneratorService{
		getFn: func(ctx context.Context, id string) (*vtpm.VTPMInstance, error) {
			return nil, errors.New("not found")
		},
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/missing", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "missing"})
	rec := httptest.NewRecorder()

	h.GetInstance(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// GetInstanceByProfile tests

func TestHandler_GetInstanceByProfile_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/profile/42", nil)
	req = mux.SetURLVars(req, map[string]string{"profile_id": "42"})
	rec := httptest.NewRecorder()

	h.GetInstanceByProfile(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_GetInstanceByProfile_InvalidID(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/profile/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"profile_id": "abc"})
	rec := httptest.NewRecorder()

	h.GetInstanceByProfile(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// DeleteInstance tests

func TestHandler_DeleteInstance_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodDelete, "/vtpm/instances/vtpm-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.DeleteInstance(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_DeleteInstance_StopsRunningFirst(t *testing.T) {
	stopped := false
	svc := &testableGeneratorService{
		isRunningFn: func(id string) bool { return true },
		stopFn: func(ctx context.Context, id string) error {
			stopped = true
			return nil
		},
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodDelete, "/vtpm/instances/vtpm-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.DeleteInstance(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, stopped)
}

// StartInstance tests

func TestHandler_StartInstance_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances/vtpm-1/start", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.StartInstance(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_StartInstance_AlreadyRunning(t *testing.T) {
	svc := &testableGeneratorService{
		isRunningFn: func(id string) bool { return true },
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances/vtpm-1/start", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.StartInstance(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// StopInstance tests

func TestHandler_StopInstance_Success(t *testing.T) {
	svc := &testableGeneratorService{
		isRunningFn: func(id string) bool { return true },
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances/vtpm-1/stop", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.StopInstance(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_StopInstance_NotRunning(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodPost, "/vtpm/instances/vtpm-1/stop", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.StopInstance(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// GetInstanceStatus tests

func TestHandler_GetInstanceStatus_Running(t *testing.T) {
	svc := &testableGeneratorService{
		isRunningFn: func(id string) bool { return true },
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-1/status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.GetInstanceStatus(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_GetInstanceStatus_Stopped(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-1/status", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.GetInstanceStatus(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ExportEKCertificate tests

func TestHandler_ExportEKCertificate_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-1/ek", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.ExportEKCertificate(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/x-pem-file", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "BEGIN CERTIFICATE")
}

func TestHandler_ExportEKCertificate_NotFound(t *testing.T) {
	svc := &testableGeneratorService{
		exportEKFn: func(ctx context.Context, id string) (*x509.Certificate, error) {
			return nil, errors.New("not found")
		},
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-1/ek", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.ExportEKCertificate(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// GetEKFingerprint tests

func TestHandler_GetEKFingerprint_Success(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-1/ek/fingerprint", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.GetEKFingerprint(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_GetEKFingerprint_NotFound(t *testing.T) {
	svc := &testableGeneratorService{
		ekFPFn: func(ctx context.Context, id string) (string, error) {
			return "", errors.New("not found")
		},
	}
	h := newTestVTPMHandler(t, svc)

	req := httptest.NewRequest(http.MethodGet, "/vtpm/instances/vtpm-1/ek/fingerprint", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "vtpm-1"})
	rec := httptest.NewRecorder()

	h.GetEKFingerprint(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// Missing ID tests

func TestHandler_MissingInstanceID(t *testing.T) {
	svc := &testableGeneratorService{}
	h := newTestVTPMHandler(t, svc)

	tests := []struct {
		name    string
		method  string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"GetInstance", http.MethodGet, h.GetInstance},
		{"DeleteInstance", http.MethodDelete, h.DeleteInstance},
		{"StartInstance", http.MethodPost, h.StartInstance},
		{"StopInstance", http.MethodPost, h.StopInstance},
		{"GetInstanceStatus", http.MethodGet, h.GetInstanceStatus},
		{"ExportEKCertificate", http.MethodGet, h.ExportEKCertificate},
		{"GetEKFingerprint", http.MethodGet, h.GetEKFingerprint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/vtpm/instances/", nil)
			req = mux.SetURLVars(req, map[string]string{"id": ""})
			rec := httptest.NewRecorder()

			tt.handler(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}
