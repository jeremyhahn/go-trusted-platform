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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
)

// A negative limit or offset is refused with 400 before the registry
// service is called, so clients get a clear answer instead of one whose
// size depends on the storage backend.
func TestListImages_NegativePagingIsBadRequest(t *testing.T) {
	targets := []string{
		"/compute/images?limit=-1",
		"/compute/images?offset=-5",
		"/compute/images?limit=-1&offset=-1",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			svc := &fakeRegistryService{listResp: &grpcapi.RegistryListResponse{}}
			rec := serve(t, newImagesRouter(svc), httptest.NewRequest(http.MethodGet, target, nil))

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, ErrInvalidListPaging{}.Error(), decodeEnvelope(t, rec).Error)
			assert.Nil(t, svc.listReq, "the registry service must not be called")
		})
	}
}
