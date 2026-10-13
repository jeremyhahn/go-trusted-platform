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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// listingComputeService answers ListVMs with one VM and records the request.
// Every other compute RPC is unimplemented.
type listingComputeService struct {
	platformv1.UnimplementedComputeServiceServer

	listed *platformv1.ListVMsRequest
}

func (s *listingComputeService) ListVMs(_ context.Context, req *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	s.listed = req
	return &platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1"}}}, nil
}

func TestRESTServer_SetComputeHandlers_NilMountsNothing(t *testing.T) {
	t.Parallel()
	server := newTPMTestRESTServer(t)

	server.SetComputeHandlers(nil, restapi.NewScopeGuard(nil, nil, slog.Default()))

	assert.Equal(t, http.StatusNotFound, serveTPMRoute(server, http.MethodGet, "/api/v1/compute/vms", "token").Code)
}

func TestRESTServer_SetComputeHandlers_ServesAScopedToken(t *testing.T) {
	t.Parallel()
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	reader := key.sign(t, "operator", "", []string{"vm:read"})
	containers := key.sign(t, "operator", "", []string{"container:read"})

	server := newTPMTestRESTServer(t)
	compute := &listingComputeService{}
	server.SetComputeHandlers(compute, restapi.NewScopeGuard(validator, nil, slog.Default()))

	t.Run("a vm:read token lists through the compute service", func(t *testing.T) {
		w := serveTPMRoute(server, http.MethodGet, "/api/v1/compute/vms?pagination.pageSize=5", reader)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), `"vms"`)
		require.NotNil(t, compute.listed)
		assert.Equal(t, uint32(5), compute.listed.GetPagination().GetPageSize())
	})

	t.Run("a token without vm:read is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, serveTPMRoute(server, http.MethodGet, "/api/v1/compute/vms", containers).Code)
	})

	t.Run("no token is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, serveTPMRoute(server, http.MethodGet, "/api/v1/compute/vms", "").Code)
	})
}
