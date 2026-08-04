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

package compute

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIncomingReceiver is a scripted incomingReceiver so ReceiveIncoming /
// FinalizeIncoming can be exercised without a real QEMU process.
type fakeIncomingReceiver struct {
	port      int
	committed bool
	aborted   bool
	commitErr error
	abortErr  error
}

func (f *fakeIncomingReceiver) Port() int { return f.port }

func (f *fakeIncomingReceiver) Commit(context.Context) error {
	f.committed = true
	return f.commitErr
}

func (f *fakeIncomingReceiver) Abort(context.Context) error {
	f.aborted = true
	return f.abortErr
}

// fakeServerTLS satisfies BOTH the source (MigrationTLSProvider) and the
// destination (MigrationServerTLSProvider) migration TLS seams, mirroring the
// production caMigrationTLS concrete.
type fakeServerTLS struct {
	dir          string
	materialized bool
	cleanedUp    bool
	err          error
}

func (f *fakeServerTLS) EnsureTLSCreds(context.Context, MigrationSession, *IncomingEndpoint) (string, error) {
	return "migtls-client", nil
}

func (f *fakeServerTLS) MaterializeServerCreds(context.Context, string) (string, func(), error) {
	if f.err != nil {
		return "", func() {}, f.err
	}
	f.materialized = true
	return f.dir, func() { f.cleanedUp = true }, nil
}

// sourceOnlyTLS implements only the source seam, so ReceiveIncoming's
// type-assertion for the server capability fails.
type sourceOnlyTLS struct{}

func (sourceOnlyTLS) EnsureTLSCreds(context.Context, MigrationSession, *IncomingEndpoint) (string, error) {
	return "x", nil
}

// swapReceiverLauncher installs a fake incoming-receiver launcher and restores
// the original on cleanup.
func swapReceiverLauncher(t *testing.T, fn func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error)) {
	t.Helper()
	orig := newIncomingReceiver
	newIncomingReceiver = fn
	t.Cleanup(func() { newIncomingReceiver = orig })
}

func TestReceiveIncoming_HappyPath(t *testing.T) {
	orch := newOpsOrchestrator(t)
	tlsProv := &fakeServerTLS{dir: t.TempDir()}
	orch.config.MigrationTLS = tlsProv

	recv := &fakeIncomingReceiver{port: 49200}
	var gotParams *incomingReceiverParams
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		gotParams = p
		return recv, nil
	})

	spec := MigrationSpec{
		InstanceID: "vm1",
		VMName:     "guest",
		Mode:       MigrateModeCold,
		Config:     &InstanceConfig{Memory: 2048, CPUs: 2, DiskSize: "20G"},
	}
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)
	require.NotNil(t, handle)

	assert.Equal(t, 49200, handle.Port)
	assert.NotEmpty(t, handle.ReceiverID)
	hostname, _ := os.Hostname()
	assert.Equal(t, hostname, handle.TLSHostname)
	assert.True(t, tlsProv.materialized, "server creds must be materialized")
	require.NotNil(t, gotParams)
	assert.Equal(t, tlsProv.dir, gotParams.credsDir)
	assert.Equal(t, "guest", gotParams.spec.VMName)
}

func TestReceiveIncoming_MissingSpecConfig(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{VMName: "guest"})
	require.ErrorIs(t, err, ErrMigrationSpecRequired)
}

func TestReceiveIncoming_NoServerTLS(t *testing.T) {
	orch := newOpsOrchestrator(t)
	// MigrationTLS unset entirely.
	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.ErrorIs(t, err, ErrMigrationServerTLSNotConfigured)
}

func TestReceiveIncoming_TLSProviderLacksServerCapability(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = sourceOnlyTLS{}
	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.ErrorIs(t, err, ErrMigrationServerTLSNotConfigured)
}

func TestReceiveIncoming_LauncherFailsAndCleansUp(t *testing.T) {
	orch := newOpsOrchestrator(t)
	tlsProv := &fakeServerTLS{dir: t.TempDir()}
	orch.config.MigrationTLS = tlsProv

	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return nil, errors.New("qemu boom")
	})

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.ErrorIs(t, err, ErrMigrationReceiveFailed)
	assert.True(t, tlsProv.cleanedUp, "server creds must be cleaned up when the launcher fails")
}

func TestFinalizeIncoming_Commit(t *testing.T) {
	orch := newOpsOrchestrator(t)
	tlsProv := &fakeServerTLS{dir: t.TempDir()}
	orch.config.MigrationTLS = tlsProv

	recv := &fakeIncomingReceiver{port: 5000}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))
	assert.True(t, recv.committed)
	assert.False(t, recv.aborted)
	assert.True(t, tlsProv.cleanedUp, "creds released on commit")

	// The receiver is consumed; a second finalize reports not-found.
	err = orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	require.ErrorIs(t, err, ErrReceiverNotFound)
}

func TestFinalizeIncoming_Abort(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &fakeIncomingReceiver{port: 5000}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, false))
	assert.True(t, recv.aborted)
	assert.False(t, recv.committed)
}

func TestFinalizeIncoming_UnknownReceiver(t *testing.T) {
	orch := newOpsOrchestrator(t)
	require.ErrorIs(t, orch.FinalizeIncoming(context.Background(), "does-not-exist", true), ErrReceiverNotFound)
	require.ErrorIs(t, orch.FinalizeIncoming(context.Background(), "", true), ErrReceiverNotFound)
}

func TestFinalizeIncoming_CommitErrorWrapped(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &fakeIncomingReceiver{port: 5000, commitErr: errors.New("resume failed")}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	err = orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	require.ErrorIs(t, err, ErrMigrationReceiveFailed)
}
