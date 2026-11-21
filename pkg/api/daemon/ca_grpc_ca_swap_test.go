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

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// countingInitializer is a race-safe CAInitializer: calls is atomic, and
// ca/err are set before the service is shared between goroutines.
type countingInitializer struct {
	calls atomic.Int32
	ca    quicbaasca.CACertificateAuthority
	err   error
}

func (c *countingInitializer) init(context.Context) (quicbaasca.CACertificateAuthority, error) {
	c.calls.Add(1)
	return c.ca, c.err
}

func swapService(t *testing.T, rec *countingInitializer) (*CAGRPCService, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted-platform-ca.crt")
	return NewCAGRPCService(nil, nil, nil).WithCAInitializer(rec.init).WithTrustInstallPath(path), path
}

const initCASwapMessage = "CA initialised; the gRPC and REST CA services serve it now; restart platformd to serve it over QUIC"

func TestCAGRPCService_InitCA_SwapsTheServedCA(t *testing.T) {
	ctx := context.Background()

	t.Run("before InitCA the CA is unset", func(t *testing.T) {
		svc, _ := swapService(t, &countingInitializer{})
		_, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.Nil(t, svc.TrustAnchor())
	})

	t.Run("after InitCA every RPC serves the new CA", func(t *testing.T) {
		ca := lifecycleCA(t)
		rec := &countingInitializer{ca: ca}
		svc, path := swapService(t, rec)

		resp, err := svc.InitCA(ctx, &platformv1.InitCARequest{})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		require.NotNil(t, resp.CaInfo)
		assert.True(t, resp.CaInfo.IsInitialized)
		assert.Equal(t, initCASwapMessage, resp.Status.Message)

		info, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
		require.NoError(t, err)
		assert.True(t, info.GetCaInfo().GetIsInitialized())
		assert.Equal(t, "lifecycle-ca", info.GetCaInfo().GetCommonName())

		anchor := svc.TrustAnchor()
		require.NotNil(t, anchor)
		root, err := anchor.TrustedRoot()
		require.NoError(t, err)
		assert.Equal(t, ca.trustedRoot, root)

		_, err = svc.InstallCACertificates(ctx, &platformv1.InstallCACertificatesRequest{})
		require.NoError(t, err)
		written, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, pemOf(ca.trustedRoot.Raw), written)

		t.Run("a second InitCA is already initialised", func(t *testing.T) {
			resp, err := svc.InitCA(ctx, &platformv1.InitCARequest{})
			require.NoError(t, err)
			assert.True(t, resp.Status.Success)
			assert.Contains(t, resp.Status.Message, "already initialised")
			assert.Equal(t, int32(1), rec.calls.Load())
		})
	})

	t.Run("an initializer error leaves the CA unset, a retry swaps", func(t *testing.T) {
		rec := &countingInitializer{err: errors.New("bring-up failed")}
		svc, _ := swapService(t, rec)

		_, err := svc.InitCA(ctx, &platformv1.InitCARequest{})
		assert.Equal(t, codes.Internal, status.Code(err))
		_, err = svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))

		rec.err = nil
		rec.ca = lifecycleCA(t)
		resp, err := svc.InitCA(ctx, &platformv1.InitCARequest{})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		info, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
		require.NoError(t, err)
		assert.Equal(t, "lifecycle-ca", info.GetCaInfo().GetCommonName())
	})

	for name, ca := range map[string]quicbaasca.CACertificateAuthority{
		"nil CA":             nil,
		"not initialised CA": &configurableMockCA{isInitialized: false},
	} {
		t.Run("initializer returns "+name, func(t *testing.T) {
			svc, _ := swapService(t, &countingInitializer{ca: ca})
			_, err := svc.InitCA(ctx, &platformv1.InitCARequest{})
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "returned no initialised CA")
			_, err = svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		})
	}
}

func TestCAGRPCService_CASwap_Concurrent(t *testing.T) {
	ctx := context.Background()
	rec := &countingInitializer{ca: lifecycleCA(t)}
	svc, _ := swapService(t, rec)

	var wg sync.WaitGroup
	errs := make(chan string, 16*50+4)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				info, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
				switch status.Code(err) {
				case codes.OK:
					if !info.GetCaInfo().GetIsInitialized() {
						errs <- "GetCAInfo OK but not initialised"
					}
				case codes.FailedPrecondition:
				default:
					errs <- "GetCAInfo: " + err.Error()
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.InitCA(ctx, &platformv1.InitCARequest{}); err != nil {
				errs <- "InitCA: " + err.Error()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}

	assert.Equal(t, int32(1), rec.calls.Load())
	info, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-ca", info.GetCaInfo().GetCommonName())
}
