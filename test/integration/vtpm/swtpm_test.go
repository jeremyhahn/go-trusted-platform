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

//go:build integration

package vtpm_test

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pkg/swtpm unit tests replace the swtpm binaries with a fake. These
// tests drive the real swtpm and swtpm_setup from the devcontainer, so a
// missing binary fails them.

// initializedSWTPM returns an swtpm whose state the real swtpm_setup created.
func initializedSWTPM(t *testing.T, ctx context.Context, pcrBanks ...string) *swtpm.SWTPM {
	t.Helper()

	sw, err := swtpm.NewSWTPM(&swtpm.Config{StateDir: t.TempDir(), PCRBanks: pcrBanks}, nil)
	require.NoError(t, err, "swtpm and swtpm_setup must be installed")
	require.False(t, sw.IsInitialized())
	require.NoError(t, sw.Initialize(ctx))
	require.True(t, sw.IsInitialized())
	return sw
}

func TestSWTPMDaemon_InitializeMultiplePCRBanks(t *testing.T) {
	initializedSWTPM(t, context.Background(), "sha256", "sha384", "sha512")
}

func TestSWTPMDaemon_StartStop(t *testing.T) {
	ctx := context.Background()
	sw := initializedSWTPM(t, ctx)

	require.NoError(t, sw.Start(ctx))
	assert.True(t, sw.IsRunning())
	assert.Greater(t, sw.PID(), 0)

	require.NoError(t, sw.WaitForSocket(5*time.Second))
	_, err := os.Stat(sw.SocketPath())
	require.NoError(t, err)

	require.NoError(t, sw.Stop())
	assert.False(t, sw.IsRunning())
	assert.Equal(t, 0, sw.PID())
}

// TestSWTPMDaemon_RestartKeepsInjectedEKCertificates stops the swtpm process
// holding the injected RSA and ECC EK certificates and starts a new one on
// the same state directory: the VM's identity lives in that directory, so
// both certificates must come back byte for byte. The pkg/vtpm simulator
// test only resets an in-memory TPM; this one reloads swtpm's state from disk.
func TestSWTPMDaemon_RestartKeepsInjectedEKCertificates(t *testing.T) {
	ctx := context.Background()
	first := initializedSWTPM(t, ctx)
	require.NoError(t, first.Start(ctx))
	require.NoError(t, first.WaitForSocket(5*time.Second))

	certs := map[vtpm.EKAlgorithm]*x509.Certificate{
		vtpm.EKAlgorithmRSA: generateIdentifiableEKCert(t, "RESTART-RSA-EK"),
		vtpm.EKAlgorithmECC: generateIdentifiableEKCert(t, "RESTART-ECC-EK"),
	}
	injector := vtpm.NewEKCertInjector(first.SocketPath(), nil)
	for algorithm, cert := range certs {
		require.NoError(t, injector.InjectCertificate(ctx, cert, algorithm))
	}

	// Stop returns once the process has exited.
	firstPID := first.PID()
	require.NoError(t, first.Stop())
	require.False(t, first.IsRunning())

	second, err := swtpm.NewSWTPM(&swtpm.Config{StateDir: first.StateDir()}, nil)
	require.NoError(t, err)
	require.True(t, second.IsInitialized(), "the restarted swtpm must find the stopped one's state")
	require.NoError(t, second.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, second.Stop()) })
	require.NoError(t, second.WaitForSocket(5*time.Second))
	require.NotEqual(t, firstPID, second.PID(), "the certificates must be read from a new swtpm process")

	restarted := vtpm.NewEKCertInjector(second.SocketPath(), nil)
	for algorithm, cert := range certs {
		exists, persisted, err := restarted.CheckEKCertificateExists(ctx, algorithm)
		require.NoError(t, err)
		require.True(t, exists, "the %s EK certificate must survive an swtpm restart", algorithm)
		assert.Equal(t, cert.Raw, persisted.Raw, "the %s EK certificate must be unchanged by an swtpm restart", algorithm)
	}
}
