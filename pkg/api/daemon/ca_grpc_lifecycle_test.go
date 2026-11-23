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

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

// onePEMCert requires b to hold exactly one PEM CERTIFICATE block and nothing
// else, the only shape openssl rehash trusts, and returns its DER.
func onePEMCert(t *testing.T, b []byte) []byte {
	t.Helper()
	block, rest := pem.Decode(b)
	require.NotNil(t, block, "no PEM block")
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Empty(t, rest, "more than one PEM block")
	return block.Bytes
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
		dir := t.TempDir()
		path := filepath.Join(dir, "ca.crt")
		interPath := filepath.Join(dir, "ca-intermediate-1.crt")
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		resp, err := svc.InstallCACertificates(context.Background(),
			&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		assert.Equal(t, int32(2), resp.CertificatesInstalled)
		assert.Equal(t, path, resp.InstallPath)
		written, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, pemOf(ca.trustedRoot.Raw), written)
		assert.Equal(t, ca.trustedRoot.Raw, onePEMCert(t, written))
		writtenInter, err := os.ReadFile(interPath)
		require.NoError(t, err)
		assert.Equal(t, pemOf(ca.trustedInter.Raw), writtenInter)
		assert.Equal(t, ca.trustedInter.Raw, onePEMCert(t, writtenInter))

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

		resp, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, inst.CertificatesInstalled, resp.CertificatesRemoved)
		assert.Equal(t, int32(2), resp.CertificatesRemoved)
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))
		_, statErr = os.Stat(filepath.Join(filepath.Dir(path), "ca-intermediate-1.crt"))
		assert.True(t, os.IsNotExist(statErr))

		resp, err = svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
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

		_, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		kept, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, other, kept)
	})

	t.Run("refuses a foreign intermediate file and removes nothing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		interPath := filepath.Join(filepath.Dir(path), "ca-intermediate-1.crt")
		other := []byte("-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----\n")
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)
		_, err := svc.InstallCACertificates(context.Background(),
			&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(interPath, other, 0o644))

		_, err = svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		keptRoot, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, pemOf(ca.trustedRoot.Raw), keptRoot)
		keptInter, readErr := os.ReadFile(interPath)
		require.NoError(t, readErr)
		assert.Equal(t, other, keptInter)
	})

	t.Run("removes a two-certificate bundle an earlier install wrote", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		require.NoError(t, os.WriteFile(path, pemOf(ca.trustedRoot.Raw, ca.trustedInter.Raw), 0o644))
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		resp, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, int32(2), resp.CertificatesRemoved)
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))
	})

	t.Run("no CA", func(t *testing.T) {
		_, err := NewCAGRPCService(nil, nil, nil).WithTrustInstallPath(filepath.Join(t.TempDir(), "ca.crt")).
			UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
}

// TestCAGRPCService_UninstallCACertificates_WithoutIntermediatesKeepsTheIntermediateFile pins the
// include_intermediates contract: without it the uninstall removes the root file only.
func TestCAGRPCService_UninstallCACertificates_WithoutIntermediatesKeepsTheIntermediateFile(t *testing.T) {
	ca := lifecycleCA(t)
	path := filepath.Join(t.TempDir(), "ca.crt")
	interPath := filepath.Join(filepath.Dir(path), "ca-intermediate-1.crt")
	svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)
	_, err := svc.InstallCACertificates(context.Background(),
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)

	resp, err := svc.UninstallCACertificates(context.Background(),
		&platformv1.UninstallCACertificatesRequest{IncludeIntermediates: false})
	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, int32(1), resp.CertificatesRemoved)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
	keptInter, readErr := os.ReadFile(interPath)
	require.NoError(t, readErr)
	assert.Equal(t, pemOf(ca.trustedInter.Raw), keptInter)
}

// TestCAGRPCService_UninstallCACertificates_WithoutIntermediatesRefusesTheCombinedBundle: a legacy
// root-plus-intermediate bundle cannot be split, so without include_intermediates it is refused
// and left in place.
func TestCAGRPCService_UninstallCACertificates_WithoutIntermediatesRefusesTheCombinedBundle(t *testing.T) {
	ca := lifecycleCA(t)
	path := filepath.Join(t.TempDir(), "ca.crt")
	bundle := pemOf(ca.trustedRoot.Raw, ca.trustedInter.Raw)
	require.NoError(t, os.WriteFile(path, bundle, 0o644))
	svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

	_, err := svc.UninstallCACertificates(context.Background(),
		&platformv1.UninstallCACertificatesRequest{IncludeIntermediates: false})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	kept, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, bundle, kept)
}

// TestCAGRPCService_UninstallCACertificates_IntermediateFirstBundle pins that the
// intermediate-first bundle (the order the CA bundle and the bootstrap write) is the
// same combined bundle as the root-first one: removed with include_intermediates and
// refused, byte for byte kept, without it.
func TestCAGRPCService_UninstallCACertificates_IntermediateFirstBundle(t *testing.T) {
	ca := lifecycleCA(t)

	t.Run("removed with include_intermediates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		require.NoError(t, os.WriteFile(path, pemOf(ca.trustedInter.Raw, ca.trustedRoot.Raw), 0o644))
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		resp, err := svc.UninstallCACertificates(context.Background(),
			&platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
		require.NoError(t, err)
		assert.True(t, resp.Status.Success)
		assert.Equal(t, int32(2), resp.CertificatesRemoved)
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))
	})

	t.Run("refused without include_intermediates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		bundle := pemOf(ca.trustedInter.Raw, ca.trustedRoot.Raw)
		require.NoError(t, os.WriteFile(path, bundle, 0o644))
		svc := NewCAGRPCService(nil, ca, nil).WithTrustInstallPath(path)

		_, err := svc.UninstallCACertificates(context.Background(),
			&platformv1.UninstallCACertificatesRequest{IncludeIntermediates: false})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "include_intermediates")
		kept, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, bundle, kept)
	})
}

// TestCAGRPCService_TrustLifecycle_Concurrent runs an uninstall and an
// install at once: neither may fail because the other replaced or removed
// the bundle between its read and its write or remove.
func TestCAGRPCService_TrustLifecycle_Concurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	svc := NewCAGRPCService(nil, lifecycleCA(t), nil).WithTrustInstallPath(path)
	install := &platformv1.InstallCACertificatesRequest{IncludeIntermediates: true}

	for round := 0; round < 20; round++ {
		_, err := svc.InstallCACertificates(context.Background(), install)
		require.NoError(t, err)

		errs := make(chan error, 2)
		go func() {
			_, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
			errs <- err
		}()
		go func() {
			_, err := svc.InstallCACertificates(context.Background(), install)
			errs <- err
		}()
		require.NoError(t, <-errs, "round %d", round)
		require.NoError(t, <-errs, "round %d", round)
	}

	_, err := svc.UninstallCACertificates(context.Background(), &platformv1.UninstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(filepath.Join(filepath.Dir(path), "ca-intermediate-1.crt"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestCAGRPCService_InstallCACertificates_OneCertificatePerTrustFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	svc := NewCAGRPCService(nil, lifecycleCA(t), nil).WithTrustInstallPath(path)

	_, err := svc.InstallCACertificates(context.Background(),
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.ElementsMatch(t, []string{"ca.crt", "ca-intermediate-1.crt"}, names)
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		onePEMCert(t, b)
	}
}

func TestCAGRPCService_InstallCACertificates_CountsOnlyFilesWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	svc := NewCAGRPCService(nil, lifecycleCA(t), nil).WithTrustInstallPath(path)
	ctx := context.Background()

	resp, err := svc.InstallCACertificates(ctx,
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: false})
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.GetCertificatesInstalled(), "root-only install writes one file")

	resp, err = svc.InstallCACertificates(ctx,
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.GetCertificatesInstalled(), "root already installed: only the intermediate is written")

	resp, err = svc.InstallCACertificates(ctx,
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.GetCertificatesInstalled())
	assert.Contains(t, resp.GetStatus().GetMessage(), "already installed")

	require.NoError(t, os.Remove(filepath.Join(dir, "ca-intermediate-1.crt")))
	resp, err = svc.InstallCACertificates(ctx,
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.GetCertificatesInstalled(), "repairing the intermediate writes one file")

	require.NoError(t, os.Remove(path))
	resp, err = svc.InstallCACertificates(ctx,
		&platformv1.InstallCACertificatesRequest{IncludeIntermediates: true})
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.GetCertificatesInstalled(), "repairing the root writes one file")
}

func TestCALifecycle_RequiresTheAdminScope(t *testing.T) {
	assert.Equal(t, "ca:create", grpcapi.ScopeForMethod("/platform.v1.CAService/InitCA"))
	assert.Equal(t, "trust:write", grpcapi.ScopeForMethod("/platform.v1.CAService/InstallCACertificates"))
	assert.Equal(t, "trust:write", grpcapi.ScopeForMethod("/platform.v1.CAService/UninstallCACertificates"))
}

// A daemon with no CA loaded and no CA configuration has nothing InitCA can
// bring up, so it must not report CA readiness: an empty-holder checker would
// keep /health/ready at 503 for good.
func TestRegisterHealthCheckers_NoCAConfiguredOmitsCAChecker(t *testing.T) {
	d, err := New(testConfig("/tmp/test-reg-health-no-ca.sock"))
	require.NoError(t, err)

	d.healthRegistry = health.NewRegistry()
	d.caService = NewCAGRPCService(nil, nil, nil).
		WithCAHolder(NewCAHolder(nil)).
		WithCAInitializer(AppCAInitializer(&app.App{}))

	d.registerHealthCheckers()

	assert.NotContains(t, d.healthRegistry.List(), "ca")
}

// A daemon with a CA configuration can bring its CA up through InitCA, so the
// CA readiness check stays registered and follows the holder.
func TestRegisterHealthCheckers_ConfiguredCAKeepsCAChecker(t *testing.T) {
	d, err := New(testConfig("/tmp/test-reg-health-cfg-ca.sock"))
	require.NoError(t, err)

	d.healthRegistry = health.NewRegistry()
	d.caService = NewCAGRPCService(nil, nil, nil).
		WithCAHolder(NewCAHolder(nil)).
		WithCAInitializer(AppCAInitializer(&app.App{CAConfig: &trustedca.CAConfig{}}))

	d.registerHealthCheckers()

	assert.Contains(t, d.healthRegistry.List(), "ca")
}

// quicBaaSCARecorder stands in for injectQuicBaaSCA: it records the app
// and CA InitCA hands to the embedded QuicBaaS and returns err.
type quicBaaSCARecorder struct {
	calls int
	app   *app.App
	ca    quicbaasca.CACertificateAuthority
	err   error
}

func (r *quicBaaSCARecorder) install(t *testing.T) {
	t.Helper()
	saved := injectQuicBaaSCA
	t.Cleanup(func() { injectQuicBaaSCA = saved })
	injectQuicBaaSCA = func(a *app.App, ca quicbaasca.CACertificateAuthority) error {
		r.calls++
		r.app = a
		r.ca = ca
		return r.err
	}
}

func TestAppCAInitializer_HandsTheCAToTheEmbeddedQuicBaaS(t *testing.T) {
	rec := &quicBaaSCARecorder{}
	rec.install(t)
	ca := lifecycleCA(t)
	// A loaded CA: LoadOrInitCA keeps it, so the initializer returns it.
	a := &app.App{CAConfig: &trustedca.CAConfig{}, CA: ca}
	svc := NewCAGRPCService(nil, nil, nil).WithCAInitializer(AppCAInitializer(a))

	resp, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, 1, rec.calls, "InitCA did not hand the CA to the embedded QuicBaaS")
	assert.Same(t, a, rec.app)
	assert.Same(t, ca, rec.ca)
}

func TestAppCAInitializer_QuicBaaSRefusalFailsInitCA(t *testing.T) {
	rec := &quicBaaSCARecorder{err: errors.New("embedded CA adapter not ready")}
	rec.install(t)
	a := &app.App{CAConfig: &trustedca.CAConfig{}, CA: lifecycleCA(t)}
	svc := NewCAGRPCService(nil, nil, nil).WithCAInitializer(AppCAInitializer(a))

	_, err := svc.InitCA(context.Background(), &platformv1.InitCARequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "embedded CA adapter not ready")
	assert.Nil(t, svc.authority(), "a CA the embedded QuicBaaS refused was swapped in")
}

func TestNew_NoStartupCAMountsTheQUICCAHandler(t *testing.T) {
	config := testConfig("/tmp/test-quic-ca-holder.sock")
	config.EnableQUIC = true
	config.CAService = nil
	d, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, d.quicHandler)
	require.NotNil(t, d.quicHandler.caHandler, "no QUIC CA handler with no start-up CA")

	ctx := context.Background()
	resp := d.quicHandler.handleCA(ctx, &quicwire.Request{Opcode: quicwire.OpCAInfo})
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)

	d.caService.setAuthority(lifecycleCA(t))
	resp = d.quicHandler.handleCA(ctx, &quicwire.Request{Opcode: quicwire.OpCAInfo})
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}
