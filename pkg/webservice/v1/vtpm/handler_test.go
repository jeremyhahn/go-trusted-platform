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
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	mockService := &mockGeneratorService{}

	h, err := NewHandler(HandlerParams{
		Logger:           logger,
		GeneratorService: mockService,
		ResponseWriter:   respWriter,
	})

	require.NoError(t, err)
	assert.NotNil(t, h)
}

func TestNewHandler_MissingLogger(t *testing.T) {
	respWriter := response.NewResponseWriter(logging.DefaultLogger(), nil)
	mockService := &mockGeneratorService{}

	h, err := NewHandler(HandlerParams{
		Logger:           nil,
		GeneratorService: mockService,
		ResponseWriter:   respWriter,
	})

	require.Error(t, err)
	assert.Nil(t, h)
	var svcErr ErrServiceError
	assert.ErrorAs(t, err, &svcErr)
}

func TestNewHandler_MissingGeneratorService(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	h, err := NewHandler(HandlerParams{
		Logger:           logger,
		GeneratorService: nil,
		ResponseWriter:   respWriter,
	})

	require.Error(t, err)
	assert.Nil(t, h)
}

func TestNewHandler_MissingResponseWriter(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := &mockGeneratorService{}

	h, err := NewHandler(HandlerParams{
		Logger:           logger,
		GeneratorService: mockService,
		ResponseWriter:   nil,
	})

	require.Error(t, err)
	assert.Nil(t, h)
}

func TestToInstanceResponse(t *testing.T) {
	now := time.Now()
	profileID := uint64(42)

	instance := &vtpm.VTPMInstance{
		ID:              "vtpm-123",
		StoragePath:     "/var/lib/vtpm/123",
		SocketPath:      "/run/vtpm/123.sock",
		NVRAMPath:       "/var/lib/vtpm/123/nvram",
		EKFingerprint:   "AA:BB:CC:DD",
		SRKHandle:       0x81000001,
		Version:         "2.0",
		Running:         true,
		DeviceProfileID: profileID,
		CreatedAt:       now,
	}

	resp := ToInstanceResponse(instance)
	assert.Equal(t, "vtpm-123", resp.ID)
	assert.Equal(t, "/var/lib/vtpm/123", resp.StatePath)
	assert.Equal(t, "/run/vtpm/123.sock", resp.SocketPath)
	assert.Equal(t, "/var/lib/vtpm/123/nvram", resp.NVRAMPath)
	assert.Equal(t, "AA:BB:CC:DD", resp.EKFingerprint)
	assert.Equal(t, uint32(0x81000001), resp.SRKHandle)
	assert.Equal(t, "2.0", resp.TPMVersion)
	assert.True(t, resp.Running)
	assert.NotNil(t, resp.ProfileID)
	assert.Equal(t, profileID, *resp.ProfileID)
	assert.Equal(t, now, resp.CreatedAt)
}

func TestToInstanceResponse_NoProfile(t *testing.T) {
	instance := &vtpm.VTPMInstance{
		ID:              "vtpm-456",
		DeviceProfileID: 0,
	}

	resp := ToInstanceResponse(instance)
	assert.Nil(t, resp.ProfileID)
}

func TestToInstanceListResponse(t *testing.T) {
	t.Run("with instances", func(t *testing.T) {
		instances := []*vtpm.VTPMInstance{
			{ID: "vtpm-1"},
			{ID: "vtpm-2"},
		}
		resp := ToInstanceListResponse(instances)
		assert.Equal(t, 2, resp.Total)
		assert.Len(t, resp.Instances, 2)
	})

	t.Run("with empty list", func(t *testing.T) {
		resp := ToInstanceListResponse([]*vtpm.VTPMInstance{})
		assert.Equal(t, 0, resp.Total)
		assert.Len(t, resp.Instances, 0)
	})

	t.Run("with nil list", func(t *testing.T) {
		resp := ToInstanceListResponse(nil)
		assert.Equal(t, 0, resp.Total)
		assert.Len(t, resp.Instances, 0)
	})
}

// Error tests

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrMissingInstanceID", ErrMissingInstanceID{}, "instance ID"},
		{"ErrMissingProfileID", ErrMissingProfileID{}, "profile ID"},
		{"ErrInvalidInstanceID with ID", ErrInvalidInstanceID{ID: "bad"}, "bad"},
		{"ErrInvalidInstanceID without ID", ErrInvalidInstanceID{}, "invalid instance ID"},
		{"ErrInvalidProfileID with ID", ErrInvalidProfileID{ID: "abc"}, "abc"},
		{"ErrInvalidProfileID without ID", ErrInvalidProfileID{}, "invalid profile ID"},
		{"ErrInvalidRequestBody with reason", ErrInvalidRequestBody{Reason: "bad json"}, "bad json"},
		{"ErrInvalidRequestBody without reason", ErrInvalidRequestBody{}, "invalid request body"},
		{"ErrInvalidTPMVersion with version", ErrInvalidTPMVersion{Version: "1.0"}, "1.0"},
		{"ErrInvalidEKAlgorithm with algorithm", ErrInvalidEKAlgorithm{Algorithm: "DES"}, "DES"},
		{"ErrInstanceNotFound with ID", ErrInstanceNotFound{ID: "vtpm-1"}, "vtpm-1"},
		{"ErrInstanceNotFound without ID", ErrInstanceNotFound{}, "instance not found"},
		{"ErrProfileNotFound with ID", ErrProfileNotFound{ProfileID: 42}, "42"},
		{"ErrInstanceNotRunning with ID", ErrInstanceNotRunning{ID: "vtpm-1"}, "vtpm-1"},
		{"ErrInstanceAlreadyRunning with ID", ErrInstanceAlreadyRunning{ID: "vtpm-1"}, "vtpm-1"},
		{"ErrServiceError with cause", ErrServiceError{Operation: "create", Cause: ErrMissingInstanceID{}}, "create failed"},
		{"ErrServiceError without cause", ErrServiceError{Operation: "get"}, "get failed"},
		{"ErrMissingLogger", ErrMissingLogger{}, "logger"},
		{"ErrMissingGeneratorService", ErrMissingGeneratorService{}, "generator service"},
		{"ErrMissingResponseWriter", ErrMissingResponseWriter{}, "response writer"},
		{"ErrEKCertNotAvailable with ID", ErrEKCertNotAvailable{ID: "vtpm-1"}, "vtpm-1"},
		{"ErrEKCertNotAvailable without ID", ErrEKCertNotAvailable{}, "EK certificate not available"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
		})
	}
}

func TestErrServiceError_Unwrap(t *testing.T) {
	cause := ErrMissingInstanceID{}
	err := ErrServiceError{Operation: "test", Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

// Mock implementation

type mockGeneratorService struct{}

func (m *mockGeneratorService) Generate(ctx context.Context, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error) {
	return nil, nil
}

func (m *mockGeneratorService) GenerateForProfile(ctx context.Context, profile *entities.DeviceProfile, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error) {
	return nil, nil
}

func (m *mockGeneratorService) Get(ctx context.Context, id string) (*vtpm.VTPMInstance, error) {
	return nil, nil
}

func (m *mockGeneratorService) GetByProfile(ctx context.Context, profileID uint64) (*vtpm.VTPMInstance, error) {
	return nil, nil
}

func (m *mockGeneratorService) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockGeneratorService) List(ctx context.Context) ([]*vtpm.VTPMInstance, error) {
	return nil, nil
}

func (m *mockGeneratorService) Start(ctx context.Context, id string) error {
	return nil
}

func (m *mockGeneratorService) Stop(ctx context.Context, id string) error {
	return nil
}

func (m *mockGeneratorService) IsRunning(id string) bool {
	return false
}

func (m *mockGeneratorService) ExportEKCertificate(ctx context.Context, id string) (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockGeneratorService) GetEKFingerprint(ctx context.Context, id string) (string, error) {
	return "", nil
}

func (m *mockGeneratorService) Close() error {
	return nil
}
