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

package commands

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestWireAttestationOnConfig_SetsBackend proves the helper both run paths
// call leaves the daemon config with a real attestation backend (#544):
// the gRPC server daemon.New builds from it answers from the store rather
// than with the FailedPrecondition stub.
func TestWireAttestationOnConfig_SetsBackend(t *testing.T) {
	a := &app.App{PlatformDir: t.TempDir()}
	cfg := daemon.DefaultConfig()

	w := wireAttestationOnConfig(context.Background(), newTestLogger(), a, cfg)
	t.Cleanup(w.Stop)

	require.NotNil(t, w.Services)
	require.NotNil(t, cfg.AttestationService, "the daemon config must carry the attestation backend")
	assert.Same(t, w.Services.Service, cfg.AttestationService)

	server := daemon.NewAttestationServiceServer(cfg.AttestationService, slog.Default())
	_, err := server.GetManifest(context.Background(), &platformv1.GetManifestRequest{Id: "absent"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "a configured backend answers from its store, not with the stub")
}

// TestWireAttestationOnConfig_WithoutTPM proves a node with no TPM still
// gets the backend, and that quote production answers the documented
// ErrTPMSessionNotConfigured (#387) instead of the unconfigured stub.
func TestWireAttestationOnConfig_WithoutTPM(t *testing.T) {
	a := &app.App{PlatformDir: t.TempDir()}
	cfg := daemon.DefaultConfig()

	w := wireAttestationOnConfig(context.Background(), newTestLogger(), a, cfg)
	t.Cleanup(w.Stop)
	require.NotNil(t, cfg.AttestationService)

	_, err := w.Services.Service.CollectHostAttestation(context.Background(), &daemon.QuoteConfig{}, []byte("nonce"))
	var notConfigured attestationsvc.ErrTPMSessionNotConfigured
	require.ErrorAs(t, err, &notConfigured)

	server := daemon.NewAttestationServiceServer(cfg.AttestationService, slog.Default())
	// A request over a real TLS connection, so the refusal under test is the
	// TPM session's, not the channel binding's (#482).
	restCtx := channelbind.WithConnectionTLS(context.Background(), channelbind.TransportREST, testutil.ServerConnectionState(t))
	_, err = server.CollectHostAttestation(restCtx,
		&platformv1.CollectHostAttestationRequest{Nonce: []byte("nonce")})
	require.Error(t, err)
	assert.NotEqual(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "TPM session")
}

// TestWireAttestationOnConfig_StoreUnavailable proves an unopenable store
// is non-fatal and leaves the config without a backend, so the daemon
// serves the documented FailedPrecondition surface.
func TestWireAttestationOnConfig_StoreUnavailable(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "platform")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	cfg := daemon.DefaultConfig()

	w := wireAttestationOnConfig(context.Background(), newTestLogger(), &app.App{PlatformDir: notADir}, cfg)
	t.Cleanup(w.Stop)

	assert.Nil(t, w.Services)
	assert.Nil(t, cfg.AttestationService)
	server := daemon.NewAttestationServiceServer(cfg.AttestationService, slog.Default())
	_, err := server.GetManifest(context.Background(), &platformv1.GetManifestRequest{Id: "absent"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestWireAttestationOnConfig_NilInputs(t *testing.T) {
	w := wireAttestationOnConfig(context.Background(), newTestLogger(), nil, daemon.DefaultConfig())
	require.NotNil(t, w)
	assert.Nil(t, w.Services)

	w = wireAttestationOnConfig(context.Background(), newTestLogger(), &app.App{PlatformDir: t.TempDir()}, nil)
	require.NotNil(t, w)
	assert.Nil(t, w.Services)
}

func TestInitAttestationServices_Works(t *testing.T) {
	svcs, err := initAttestationServices(newTestLogger(), &app.App{PlatformDir: t.TempDir()})
	require.NoError(t, err)
	require.NotNil(t, svcs)
	assert.NotNil(t, svcs.Service)
	assert.NotNil(t, svcs.GRPC)
}

func TestInitAttestationServices_StoreErrors(t *testing.T) {
	t.Run("no platform directory", func(t *testing.T) {
		for _, a := range []*app.App{nil, {}} {
			svcs, err := initAttestationServices(newTestLogger(), a)
			assert.Nil(t, svcs)
			var unavailable ErrAttestationStoreUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Empty(t, unavailable.Root)
			assert.ErrorIs(t, err, ErrAttestationPlatformDirUnset{})
			assert.Equal(t, "attestation: store unavailable: attestation: no platform directory is configured", err.Error())
		}
	})
	t.Run("store root cannot be created", func(t *testing.T) {
		notADir := filepath.Join(t.TempDir(), "platform")
		require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))

		svcs, err := initAttestationServices(newTestLogger(), &app.App{PlatformDir: notADir})
		assert.Nil(t, svcs)
		var unavailable ErrAttestationStoreUnavailable
		require.ErrorAs(t, err, &unavailable)
		root := filepath.Join(notADir, "attestation")
		assert.Equal(t, root, unavailable.Root)
		require.Error(t, errors.Unwrap(err))
		assert.Contains(t, err.Error(), "attestation: store "+root+" unavailable: ")
	})
}

func TestAttestationWiringStop(t *testing.T) {
	stopped := false
	(&attestationWiring{stop: func() { stopped = true }}).Stop()
	assert.True(t, stopped)

	assert.NotPanics(t, func() {
		var nilWiring *attestationWiring
		nilWiring.Stop()
		(&attestationWiring{}).Stop()
	})
}

// TestRunPaths_ShareAttestationAndRegistryWiring pins #544 at the source:
// both run paths build the attestation backend and the registry through
// the same helpers, so neither path can again serve them from a stub.
// runDaemonOnly blocks on a signal and binds listeners, so it cannot be
// exercised as a unit; see TestRunDaemonOnly_InvokesBarrierGate.
func TestRunPaths_ShareAttestationAndRegistryWiring(t *testing.T) {
	for _, fn := range []string{"runDaemonOnly", "runWithWebservices"} {
		for _, helper := range []string{"wireAttestationOnConfig", "initRegistryServiceOnConfig"} {
			assert.Truef(t, functionCallsHelper(t, fn, helper), "%s does not call %s", fn, helper)
		}
	}
}
