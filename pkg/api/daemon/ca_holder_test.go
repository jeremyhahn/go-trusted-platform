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
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCAHolder_GetSet(t *testing.T) {
	var none *CAHolder
	assert.Nil(t, none.Get())
	assert.False(t, none.Initialized())

	holder := NewCAHolder(nil)
	assert.Nil(t, holder.Get())
	assert.False(t, holder.Initialized())

	notReady := &configurableMockCA{isInitialized: false}
	holder.Set(notReady)
	assert.Equal(t, notReady, holder.Get())
	assert.False(t, holder.Initialized())

	ca := lifecycleCA(t)
	holder.Set(ca)
	assert.Equal(t, ca, holder.Get())
	assert.True(t, holder.Initialized())
}

func TestCAHolder_Concurrent(t *testing.T) {
	holder := NewCAHolder(nil)
	ca := lifecycleCA(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := holder.Get(); got != nil && got != ca {
					t.Error("Get returned a CA nobody set")
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			holder.Set(ca)
		}()
	}
	wg.Wait()
	assert.Equal(t, ca, holder.Get())
}

func caInfoOverREST(t *testing.T, server *RESTServer) (int, restapi.CAInfoResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	var resp restapi.CAInfoResponse
	if w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	}
	return w.Code, resp
}

func TestCAHolder_SharedByGRPCAndREST(t *testing.T) {
	ctx := context.Background()
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	holder := NewCAHolder(nil)
	rec := &countingInitializer{}
	svc := NewCAGRPCService(nil, nil, nil).
		WithCAHolder(holder).
		WithCAInitializer(rec.init).
		WithTrustInstallPath(filepath.Join(t.TempDir(), "ca.crt"))
	server.SetCAHolder(holder, nil)
	assert.Equal(t, holder, svc.CAHolder())

	code, _ := caInfoOverREST(t, server)
	assert.Equal(t, http.StatusServiceUnavailable, code)
	_, err = svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	ca := lifecycleCA(t)
	rec.ca = ca
	resp, err := svc.InitCA(ctx, &platformv1.InitCARequest{})
	require.NoError(t, err)
	assert.Equal(t, initCASwapMessage, resp.Status.Message)

	info, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-ca", info.GetCaInfo().GetCommonName())
	assert.Equal(t, ca, holder.Get())

	code, restInfo := caInfoOverREST(t, server)
	require.Equal(t, http.StatusOK, code)
	assert.True(t, restInfo.IsInitialized)
	assert.Equal(t, "lifecycle-ca", restInfo.CommonName)

	assert.NotNil(t, svc.TrustAnchor())
}

func TestCAHolder_ServiceWithoutHolderKeepsItsCA(t *testing.T) {
	svc := NewCAGRPCService(nil, lifecycleCA(t), nil)
	assert.Nil(t, svc.CAHolder())
	info, err := svc.GetCAInfo(context.Background(), &platformv1.GetCAInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-ca", info.GetCaInfo().GetCommonName())
}

func TestCAHolder_WithCAHolderSeedsAnEmptyHolder(t *testing.T) {
	ca := lifecycleCA(t)
	holder := NewCAHolder(nil)
	svc := NewCAGRPCService(nil, ca, nil).WithCAHolder(holder)
	assert.Equal(t, ca, holder.Get())
	info, err := svc.GetCAInfo(context.Background(), &platformv1.GetCAInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-ca", info.GetCaInfo().GetCommonName())
}
