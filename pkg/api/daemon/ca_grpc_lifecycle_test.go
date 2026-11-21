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
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// lifecycleCA is an initialised CA with a real root and intermediate.
func lifecycleCA(t *testing.T) *configurableMockCA {
	t.Helper()
	root := createTestCAWithKey(t, "Lifecycle Root CA")
	inter := createIntermediateCAWithKey(t, "Lifecycle Intermediate CA", root)
	return &configurableMockCA{
		isInitialized: true,
		identity:      "lifecycle-ca",
		trustedRoot:   root.cert,
		trustedInter:  inter.cert,
	}
}

func pemOf(certs ...[]byte) []byte {
	var out []byte
	for _, der := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// recordingInitializer counts its calls and returns ca, err.
type recordingInitializer struct {
	calls int
	ca    quicbaasca.CACertificateAuthority
	err   error
}

func (r *recordingInitializer) init(context.Context) (quicbaasca.CACertificateAuthority, error) {
	r.calls++
	return r.ca, r.err
}

func TestCAGRPCService_InitCA_AlreadyInitialised(t *testing.T) {
	rec := &recordingInitializer{}
	svc := NewCAGRPCService(nil, lifecycleCA(t), nil).WithCAInitializer(rec.init)

	resp, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.Status)
	assert.True(t, resp.Status.Success)
	assert.Contains(t, resp.Status.Message, "already initialised")
	require.NotNil(t, resp.CaInfo)
	assert.True(t, resp.CaInfo.IsInitialized)
	assert.Equal(t, 0, rec.calls, "the initializer ran on an initialised CA")
}

func TestCAGRPCService_InitCA_RunsTheAppInitPath(t *testing.T) {
	rec := &recordingInitializer{ca: lifecycleCA(t)}
	svc := NewCAGRPCService(nil, nil, nil).WithCAInitializer(rec.init)

	resp, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	require.NotNil(t, resp.CaInfo)
	assert.True(t, resp.CaInfo.IsInitialized)
	assert.Equal(t, 1, rec.calls)
}

// The first InitCA response carries the same CA information GetCAInfo
// answers afterwards, so an intermediate CA shows its real properties
// right after creation.
func TestCAGRPCService_InitCA_FirstResponseIsFullCAInfo(t *testing.T) {
	rec := &recordingInitializer{ca: lifecycleCA(t)}
	svc := NewCAGRPCService(nil, nil, nil).WithCAInitializer(rec.init)

	resp, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.CaInfo)
	assert.True(t, resp.CaInfo.IsIntermediate)
	assert.NotEmpty(t, resp.CaInfo.DefaultAlgorithm)
	assert.NotNil(t, resp.CaInfo.RootCert)
	assert.Len(t, resp.CaInfo.Intermediates, 1)

	info, err := svc.GetCAInfo(context.Background(), &platformv1.GetCAInfoRequest{})
	require.NoError(t, err)
	assert.True(t, proto.Equal(info.GetCaInfo(), resp.CaInfo),
		"InitCA CaInfo %v differs from GetCAInfo %v", resp.CaInfo, info.GetCaInfo())
}

// A health checker on a service built with an empty holder reports the CA
// InitCA brings up.
func TestCAServiceHealthChecker_FollowsInitCAOnEmptyHolder(t *testing.T) {
	ca := lifecycleCA(t)
	rec := &recordingInitializer{ca: ca}
	svc := NewCAGRPCService(nil, nil, nil).WithCAHolder(NewCAHolder(nil)).WithCAInitializer(rec.init)

	_, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.NoError(t, err)

	got := NewCAServiceHealthChecker(svc).Check(context.Background())
	assert.Equal(t, health.StatusHealthy, got.Status, got.Message)
	assert.Equal(t, ca.Identity(), got.Details["identity"])
}

// A checker created before InitCA on an empty holder reports unhealthy
// first and healthy once InitCA swaps the CA in.
func TestCAServiceHealthChecker_BeforeAndAfterInitCA(t *testing.T) {
	rec := &recordingInitializer{ca: lifecycleCA(t)}
	svc := NewCAGRPCService(nil, nil, nil).WithCAHolder(NewCAHolder(nil)).WithCAInitializer(rec.init)
	checker := NewCAServiceHealthChecker(svc)

	before := checker.Check(context.Background())
	assert.Equal(t, health.StatusUnhealthy, before.Status)

	_, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.NoError(t, err)

	after := checker.Check(context.Background())
	assert.Equal(t, health.StatusHealthy, after.Status, after.Message)
}

func TestCAGRPCService_InitCA_Refusals(t *testing.T) {
	t.Run("not wired", func(t *testing.T) {
		_, err := NewCAGRPCService(nil, nil, nil).InitCA(context.Background(), &platformv1.InitCARequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
	t.Run("initializer error", func(t *testing.T) {
		rec := &recordingInitializer{err: errors.New("boom")}
		_, err := NewCAGRPCService(nil, nil, nil).WithCAInitializer(rec.init).
			InitCA(context.Background(), &platformv1.InitCARequest{})
		assert.Equal(t, codes.Internal, status.Code(err))
		assert.Equal(t, 1, rec.calls)
	})
	t.Run("force on an initialised CA", func(t *testing.T) {
		rec := &recordingInitializer{}
		_, err := NewCAGRPCService(nil, lifecycleCA(t), nil).WithCAInitializer(rec.init).
			InitCA(context.Background(), &platformv1.InitCARequest{Force: true})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.Equal(t, 0, rec.calls)
	})
}

func TestCAGRPCService_InstallCACertificates(t *testing.T) {
	ca := lifecycleCA(t)

	t.Run("root only, then already installed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		resp, err := svc.InstallCACertificates(context.Background(), &platformv1.InstallCACertificatesRequest{})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, int32(1), resp.CertificatesInstalled)
		assert.Equal(t, path, resp.InstallPath)
		written, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, pemOf(ca.trustedRoot.Raw), written)

		resp, err = svc.InstallCACertificates(context.Background(), &platformv1.InstallCACertificatesRequest{})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, int32(0), resp.CertificatesInstalled)
		assert.Contains(t, resp.Status.Message, "already installed")
	})

	t.Run("with intermediates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		resp, err := svc.InstallCACertificates(context.Background(),
			&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		assert.Equal(t, int32(2), resp.CertificatesInstalled)
		written, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, pemOf(ca.trustedRoot.Raw, ca.trustedInter.Raw), written)

		resp, err = svc.InstallCACertificates(context.Background(),
			&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		assert.Equal(t, int32(0), resp.CertificatesInstalled)
		assert.Contains(t, resp.Status.Message, "already installed")
	})

	t.Run("no CA", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		_, err := NewCAGRPCService(nil, nil, nil).WithTrustInstallPath(path).
			InstallCACertificates(context.Background(), &platformv1.InstallCACertificatesRequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))
	})
}

func TestCAGRPCService_UninstallCACertificates(t *testing.T) {
	ca := lifecycleCA(t)

	t.Run("removes what the install wrote, then nothing installed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)
		inst, err := svc.InstallCACertificates(context.Background(),
			&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)

		resp, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, inst.CertificatesInstalled, resp.CertificatesRemoved)
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))

		resp, err = svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, int32(0), resp.CertificatesRemoved)
		assert.Contains(t, resp.Status.Message, "nothing installed")
	})

	t.Run("refuses a file it did not write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		other := []byte("-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----\n")
		require.NoError(t, os.WriteFile(path, other, 0o644))
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		_, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		kept, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, other, kept)
	})

	t.Run("no CA", func(t *testing.T) {
		_, err := NewCAGRPCService(nil, nil, nil).WithTrustInstallPath(filepath.Join(t.TempDir(), "ca.crt")).
			UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
}

func TestCALifecycle_RequiresTheAdminScope(t *testing.T) {
	assert.Equal(t, "ca:create", grpcapi.ScopeForMethod("/platform.v1.CAService/InitCA"))
	assert.Equal(t, "trust:write", grpcapi.ScopeForMethod("/platform.v1.CAService/InstallCACertificates"))
	assert.Equal(t, "trust:write", grpcapi.ScopeForMethod("/platform.v1.CAService/UninstallCACertificates"))
}
