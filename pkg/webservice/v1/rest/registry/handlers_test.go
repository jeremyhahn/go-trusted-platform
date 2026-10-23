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

package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// pushOnlyRegistryService answers PushStream with a fixed result; the
// handlers under test call no other RegistryService method.
type pushOnlyRegistryService struct {
	grpcapi.RegistryService
	err error
}

func (s pushOnlyRegistryService) PushStream(_ context.Context, metadata *grpcapi.RegistryPushMetadata, _ io.Reader) (*grpcapi.RegistryPushResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &grpcapi.RegistryPushResponse{
		Artifact: &grpcapi.RegistryArtifact{Repository: metadata.Repository, Tag: metadata.Tag},
	}, nil
}

func pushRequest(repository string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/images", strings.NewReader(`{"manifest":{}}`))
	req.Header.Set("X-Trusted-Platform-Repository", repository)
	req.Header.Set("X-Trusted-Platform-Tag", "v1")
	return req
}

func TestHandlers_PushImage_ValidReferenceIs200(t *testing.T) {
	h := NewHandlers(logging.DefaultLogger(), pushOnlyRegistryService{}, response.NewResponseWriter(logging.DefaultLogger(), nil))
	rec := httptest.NewRecorder()

	h.PushImage(rec, pushRequest("rest-1792717074-push-basic"))

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandlers_PushImage_InvalidReferenceIs400(t *testing.T) {
	svc := pushOnlyRegistryService{err: grpcapi.ErrInvalidArtifactReference{Reference: "REST-1:v1", Reason: "invalid format"}}
	h := NewHandlers(logging.DefaultLogger(), svc, response.NewResponseWriter(logging.DefaultLogger(), nil))
	rec := httptest.NewRecorder()

	h.PushImage(rec, pushRequest("REST-1"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandlers_WriteServiceError(t *testing.T) {
	tests := map[string]struct {
		err  error
		want int
	}{
		"not found":         {grpcapi.ErrArtifactNotFound{Repository: "apps/web", Reference: "v1"}, http.StatusNotFound},
		"already exists":    {grpcapi.ErrArtifactAlreadyExists{Repository: "apps/web", Reference: "v1"}, http.StatusBadRequest},
		"invalid reference": {grpcapi.ErrInvalidArtifactReference{Reference: "Apps/Web:v1", Reason: "invalid format"}, http.StatusBadRequest},
		"internal":          {errors.New("disk full"), http.StatusInternalServerError},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := NewHandlers(logging.DefaultLogger(), nil, response.NewResponseWriter(logging.DefaultLogger(), nil))
			rec := httptest.NewRecorder()

			h.writeServiceError(rec, httptest.NewRequest(http.MethodGet, "/", nil), tt.err)

			assert.Equal(t, tt.want, rec.Code)
		})
	}
}
