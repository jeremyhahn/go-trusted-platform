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
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/spf13/viper"
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
	vm        *qemu.VM
}

func (f *fakeIncomingReceiver) VM() *qemu.VM { return f.vm }

func (f *fakeIncomingReceiver) Transferring(context.Context) bool { return false }

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
		Arch:       orch.config.Arch,
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
	assert.Equal(t, netip.MustParseAddrPort(DefaultMigrationListenAddress), gotParams.listen)
}

// The receiver serves a separate transfer after the prepare request has
// returned, so its QEMU process must not be bound to that request's context:
// it lives until FinalizeIncoming commits or aborts it.
func TestReceiveIncoming_ReceiverOutlivesTheRequest(t *testing.T) {
	orch := newOpsOrchestrator(t)
	tlsProv := &fakeServerTLS{dir: t.TempDir()}
	orch.config.MigrationTLS = tlsProv

	recv := &fakeIncomingReceiver{port: 49201}
	var launchCtx context.Context
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		launchCtx = ctx
		return recv, nil
	})

	reqCtx, cancel := context.WithCancel(context.Background())
	handle, err := orch.ReceiveIncoming(reqCtx, MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
	cancel()

	require.NotNil(t, launchCtx)
	assert.NoError(t, launchCtx.Err(), "the receiver must outlive the prepare request")
	assert.False(t, recv.aborted)
	assert.False(t, tlsProv.cleanedUp)

	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, false))
	assert.True(t, recv.aborted)
	assert.True(t, tlsProv.cleanedUp, "finalize must clean the receiver's creds up")
}

// signalReceiver counts aborts and commits and signals the first abort, so a
// receiver reaped on another goroutine can be awaited without a data race.
type signalReceiver struct {
	aborts   atomic.Int32
	commits  atomic.Int32
	abortedC chan struct{}
	once     sync.Once
	// transferring is what Transferring reports: an active migration
	// stream renews the receiver lifetime.
	transferring atomic.Bool
	// completed marks a stream that finished and awaits finalize.
	completed atomic.Bool
	// vm is the receiving QEMU a commit hands over (never started).
	vm *qemu.VM
}

func (s *signalReceiver) VM() *qemu.VM { return s.vm }

func (s *signalReceiver) Transferring(context.Context) bool {
	return s.transferring.Load() || s.completed.Load()
}

func newSignalReceiver() *signalReceiver {
	return &signalReceiver{abortedC: make(chan struct{})}
}

func (s *signalReceiver) Port() int { return 49301 }

func (s *signalReceiver) Commit(context.Context) error {
	s.commits.Add(1)
	return nil
}

func (s *signalReceiver) Abort(context.Context) error {
	s.aborts.Add(1)
	s.once.Do(func() { close(s.abortedC) })
	return nil
}

// signalServerTLS counts and signals the release of the receiver's creds.
type signalServerTLS struct {
	dir       string
	cleanups  atomic.Int32
	cleanedUp chan struct{}
	once      sync.Once
}

func newSignalServerTLS(dir string) *signalServerTLS {
	return &signalServerTLS{dir: dir, cleanedUp: make(chan struct{})}
}

func (s *signalServerTLS) EnsureTLSCreds(context.Context, MigrationSession, *IncomingEndpoint) (string, error) {
	return "migtls-client", nil
}

func (s *signalServerTLS) MaterializeServerCreds(context.Context, string) (string, func(), error) {
	return s.dir, func() {
		s.cleanups.Add(1)
		s.once.Do(func() { close(s.cleanedUp) })
	}, nil
}

// swapReceiverLifetime shortens the prepared receiver's lifetime for a test.
func swapReceiverLifetime(t *testing.T, d time.Duration) {
	t.Helper()
	orig := receiverLifetime
	receiverLifetime = d
	t.Cleanup(func() { receiverLifetime = orig })
}

func awaitSignal(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestReceiveIncoming_UnfinalizedReceiverExpires(t *testing.T) {
	swapReceiverLifetime(t, 20*time.Millisecond)
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	recv := newSignalReceiver()
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	// The prepare reply is "lost": nobody finalizes. The lifetime reaps it.
	awaitSignal(t, recv.abortedC, "the expired receiver to be aborted")
	awaitSignal(t, tlsProv.cleanedUp, "the expired receiver's creds to be released")
	assert.Equal(t, int32(0), recv.commits.Load())

	err = orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	assert.ErrorIs(t, err, ErrReceiverNotFound, "an expired receiver can no longer be finalized")
}

// An active transfer renews the receiver lifetime: a long migration is not
// stopped mid-stream, and the receiver is reaped once the stream is no longer
// active (#2021 Codex P1).
func TestReceiveIncoming_ActiveTransferRenewsTheLifetime(t *testing.T) {
	swapReceiverLifetime(t, 20*time.Millisecond)
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	recv := newSignalReceiver()
	recv.transferring.Store(true)
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	select {
	case <-recv.abortedC:
		t.Fatal("a receiver with an active transfer must not be reaped")
	case <-time.After(150 * time.Millisecond):
	}
	assert.Equal(t, int32(0), recv.aborts.Load())

	recv.transferring.Store(false)
	awaitSignal(t, recv.abortedC, "the idle receiver to be aborted")
	awaitSignal(t, tlsProv.cleanedUp, "the idle receiver's creds to be released")
}

// A completed transfer that is never finalized (the source crashed after the
// stream) gets a bounded finalization grace, not endless renewal: the receiver
// is reaped and its creds released (#2021 Codex P1).
func TestReceiveIncoming_CompletedTransferIsReapedAfterGrace(t *testing.T) {
	swapReceiverLifetime(t, 20*time.Millisecond)
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	recv := newSignalReceiver()
	recv.completed.Store(true)
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	awaitSignal(t, recv.abortedC, "the completed, unfinalized receiver to be aborted")
	awaitSignal(t, tlsProv.cleanedUp, "the completed receiver's creds to be released")
	assert.Equal(t, int32(0), recv.commits.Load())
}

// newReceivedVM builds a qemu.VM that is never started, standing in for the
// receiving QEMU a committed migration hands over.
func newReceivedVM(t *testing.T, orch *QEMUOrchestrator) *qemu.VM {
	t.Helper()
	fw := t.TempDir()
	cfg := orch.config.qemuBase()
	cfg.Arch = qemu.ArchX86_64
	cfg.OVMFCode = filepath.Join(fw, "OVMF_CODE.fd")
	cfg.OVMFVars = filepath.Join(fw, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(cfg.OVMFCode, nil, 0o600))
	require.NoError(t, os.WriteFile(cfg.OVMFVars, nil, 0o600))
	cfg.WorkDir = filepath.Join(orch.config.WorkDir, "incoming-test")
	cfg.DiskPath = filepath.Join(cfg.WorkDir, "disk.qcow2")
	cfg.DiskSize = "1G"
	cfg.Memory = 512
	cfg.CPUs = 1
	vm, err := qemu.NewVM(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	return vm
}

// A committed receiver becomes a normal instance: listed, readable and
// owned by Close (#2021 Codex P1).
func TestFinalizeIncoming_CommitAdoptsTheGuest(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &fakeIncomingReceiver{port: 5000, vm: newReceivedVM(t, orch)}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	spec := MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	}
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)
	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))

	got, err := orch.Get(context.Background(), spec.InstanceID)
	require.NoError(t, err)
	assert.Equal(t, spec.VMName, got.Name)
	assert.Equal(t, StateRunning, got.State)

	list, err := orch.List(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, spec.InstanceID, list[0].ID)
	assert.Equal(t, StateRunning, list[0].State)

	state, err := orch.GetState(context.Background(), spec.InstanceID)
	require.NoError(t, err)
	assert.Equal(t, StateRunning, state)

	_, err = orch.Get(context.Background(), spec.InstanceID)
	require.NoError(t, err, "the instance stays known until Close")
	require.NoError(t, orch.Close())
}

// startReceivedVM returns a received VM whose QEMU is a running fake process.
func startReceivedVM(t *testing.T, orch *QEMUOrchestrator) *qemu.VM {
	t.Helper()
	orch.config.QEMUBinary = filepath.Join(t.TempDir(), "qemu-system-x86_64")
	require.NoError(t, os.WriteFile(orch.config.QEMUBinary, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755))
	vm := newReceivedVM(t, orch)
	cfg := vm.GetConfig()
	require.NoError(t, os.MkdirAll(cfg.WorkDir, 0o755))
	require.NoError(t, os.WriteFile(cfg.DiskPath, []byte("disk"), 0o600))
	nvram := cfg.GetNVRAMPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(nvram), 0o755))
	require.NoError(t, os.WriteFile(nvram, []byte("vars"), 0o600))
	_, err := vm.StartIncoming(context.Background(), "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Stop() })
	return vm
}

// A forced stop that lands as soon as the received instance is published
// must find the run and its exit watcher: the exit is recorded and the
// process reaped (Codex P1, PR #2021).
func TestFinalizeIncoming_StopRightAfterAdoptionRecordsTheExit(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &fakeIncomingReceiver{port: 5000, vm: startReceivedVM(t, orch)}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})
	var stopErr error
	receiverAdoptedHook = func(id string) {
		stopErr = orch.StopWithOptions(context.Background(), id, StopOptions{Force: true})
	}
	t.Cleanup(func() { receiverAdoptedHook = nil })

	spec := MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	}
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)
	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))
	require.NoError(t, stopErr)

	require.Eventually(t, func() bool {
		state, err := orch.GetState(context.Background(), spec.InstanceID)
		return err == nil && state == StateStopped
	}, 10*time.Second, 20*time.Millisecond, "the forced stop's exit must be recorded")
	require.NoError(t, orch.Close())
}

// The adopted instance carries the destination's work directory and disk, so
// disk operations find the migrated image and Delete removes the receiver's
// directory (Codex P1, PR #2021).
func TestFinalizeIncoming_AdoptedConfigCarriesTheDestinationPaths(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	vm := startReceivedVM(t, orch)
	qcfg := vm.GetConfig()
	recv := &fakeIncomingReceiver{port: 5000, vm: vm}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	spec := MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	}
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)
	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))

	got, err := orch.Get(context.Background(), spec.InstanceID)
	require.NoError(t, err)
	assert.Equal(t, qcfg.WorkDir, got.Config.WorkDir)
	assert.Equal(t, qcfg.DiskPath, got.Config.DiskPath)
	assert.Empty(t, spec.Config.WorkDir, "the caller's spec is not modified")

	require.NoError(t, orch.StopWithOptions(context.Background(), spec.InstanceID, StopOptions{Force: true}))
	require.NoError(t, orch.Delete(context.Background(), spec.InstanceID))
	_, statErr := os.Stat(qcfg.WorkDir)
	assert.True(t, os.IsNotExist(statErr), "Delete must remove the receiver's work directory")
}

// A failed commit registers nothing.
func TestFinalizeIncoming_FailedCommitAdoptsNothing(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &fakeIncomingReceiver{port: 5000, commitErr: errors.New("resume failed"), vm: newReceivedVM(t, orch)}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
	require.ErrorIs(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true), ErrMigrationReceiveFailed)

	// The failed finalize reaps the receiver's process: nothing is left
	// running without an owner, and a retry finds no receiver.
	assert.True(t, recv.aborted, "a failed commit must abort the receiver so its process is killed and waited")
	require.ErrorIs(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true), ErrReceiverNotFound)

	_, err = orch.Get(context.Background(), "vm-migrated")
	require.ErrorIs(t, err, ErrInstanceNotFound)
	list, err := orch.List(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestFinalizeIncoming_EndsTheReceiverLifetime(t *testing.T) {
	swapReceiverLifetime(t, 30*time.Millisecond)
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	recv := newSignalReceiver()
	recv.vm = newReceivedVM(t, orch)
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))

	// Past the deadline the committed receiver is left alone.
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int32(1), recv.commits.Load())
	assert.Equal(t, int32(0), recv.aborts.Load(), "a finalized receiver must not be reaped")
	assert.Equal(t, int32(1), tlsProv.cleanups.Load(), "creds are released exactly once")
}

func TestReceiveIncoming_CancelledBeforeReplyAbortsTheReceiver(t *testing.T) {
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recv := newSignalReceiver()
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		// The caller goes away while the receiver is being launched.
		cancel()
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(reqCtx, MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.Error(t, err)
	assert.Nil(t, handle)
	assert.ErrorIs(t, err, ErrMigrationReceiveFailed)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(1), recv.aborts.Load(), "a receiver whose token never reached the caller is aborted")
	assert.Equal(t, int32(1), tlsProv.cleanups.Load())
}

func TestClose_ReapsPendingReceivers(t *testing.T) {
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	recv := newSignalReceiver()
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	require.NoError(t, orch.Close())
	assert.Equal(t, int32(1), recv.aborts.Load(), "shutdown must abort a pending receiver")
	assert.Equal(t, int32(1), tlsProv.cleanups.Load(), "shutdown must release a pending receiver's creds")

	err = orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	assert.ErrorIs(t, err, ErrReceiverNotFound)
}

func TestReceiveIncoming_ListensOnTheConfiguredAddress(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
	orch.config.MigrationListenAddress = "10.20.0.11:49152"

	var gotParams *incomingReceiverParams
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		gotParams = p
		return &fakeIncomingReceiver{port: 49152}, nil
	})

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
	require.NotNil(t, gotParams)
	assert.Equal(t, netip.MustParseAddrPort("10.20.0.11:49152"), gotParams.listen)
}

func TestReceiveIncoming_RefusesAnUndeterminedListenAddress(t *testing.T) {
	for _, address := range []string{"", "eth0:49152", "10.20.0.11", "224.0.0.1:49152"} {
		t.Run(address, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			tlsProv := &fakeServerTLS{dir: t.TempDir()}
			orch.config.MigrationTLS = tlsProv
			orch.config.MigrationListenAddress = address
			swapReceiverLauncher(t, func(context.Context, *incomingReceiverParams) (incomingReceiver, error) {
				t.Fatal("a receiver was launched without a listen address")
				return nil, nil
			})

			_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
				Arch:   orch.config.Arch,
				VMName: "guest",
				Config: &InstanceConfig{Memory: 1024},
			})
			var listenErr *MigrationListenAddressError
			require.ErrorAs(t, err, &listenErr)
			assert.Equal(t, address, listenErr.Address)
			assert.False(t, tlsProv.materialized, "no credentials are issued for a receiver that cannot listen")
		})
	}
}

func TestMigrationListenAddressError_Message(t *testing.T) {
	assert.Equal(t,
		"compute: migration receiver listen address undetermined: set compute.migration_listen_address",
		(&MigrationListenAddressError{}).Error())
	assert.Equal(t,
		`compute: compute.migration_listen_address "eth0:1" is not an IP:port address`,
		(&MigrationListenAddressError{Address: "eth0:1", Reason: "is not an IP:port address"}).Error())
}

func TestReceiverPort_ConfiguredPortIsNotProbed(t *testing.T) {
	// 192.0.2.1 (TEST-NET-1) is on no interface: binding it would fail.
	port, err := receiverPort(netip.MustParseAddrPort("192.0.2.1:49152"))
	require.NoError(t, err)
	assert.Equal(t, 49152, port)
}

func TestReceiverPort_EphemeralPortOnTheListenAddress(t *testing.T) {
	port, err := receiverPort(netip.MustParseAddrPort("127.0.0.1:0"))
	require.NoError(t, err)
	assert.Positive(t, port)
}

func TestReceiverPort_UnbindableListenAddress(t *testing.T) {
	_, err := receiverPort(netip.MustParseAddrPort("192.0.2.1:0"))
	require.Error(t, err)
}

func TestMigrateIncomingURI(t *testing.T) {
	assert.Equal(t, "tcp:10.20.0.11:49152", migrateIncomingURI(netip.MustParseAddr("10.20.0.11"), 49152))
	assert.Equal(t, "tcp:[fd00::11]:49152", migrateIncomingURI(netip.MustParseAddr("fd00::11"), 49152))
}

func TestMigrationListenAddress_Defaults(t *testing.T) {
	assert.Equal(t, DefaultMigrationListenAddress, DefaultOrchestratorConfig(ComputeTypeVM).MigrationListenAddress)
	assert.Empty(t, DefaultOrchestratorConfig(ComputeTypeContainer).MigrationListenAddress,
		"containers do not receive VM migrations")

	unset := &OrchestratorConfig{}
	require.NoError(t, unset.applyLocalQEMUDefaults("amd64"))
	assert.Equal(t, DefaultMigrationListenAddress, unset.MigrationListenAddress)

	configured := &OrchestratorConfig{MigrationListenAddress: "10.20.0.11:0"}
	require.NoError(t, configured.applyLocalQEMUDefaults("amd64"))
	assert.Equal(t, "10.20.0.11:0", configured.MigrationListenAddress, "the defaults never replace a configured value")
}

func TestMigrationListenAddress_DecodesFromTheComputeSection(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("compute:\n  migration_listen_address: 10.20.0.11:49152\n")))
	var file struct {
		Compute *OrchestratorConfig `mapstructure:"compute"`
	}
	require.NoError(t, v.Unmarshal(&file))
	require.NotNil(t, file.Compute)
	assert.Equal(t, "10.20.0.11:49152", file.Compute.MigrationListenAddress)
}

func TestReceiveIncoming_MissingSpecConfig(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{VMName: "guest"})
	require.ErrorIs(t, err, ErrMigrationSpecRequired)
}

func TestReceiveIncoming_AcceptsTheSourceGuestArch(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.Arch = qemu.ArchAArch64
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
	launched := false
	swapReceiverLauncher(t, func(context.Context, *incomingReceiverParams) (incomingReceiver, error) {
		launched = true
		return &fakeIncomingReceiver{port: 49200}, nil
	})

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   qemu.ArchAArch64,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
	assert.True(t, launched)
}

// A receiver of another architecture cannot load the source's guest state, so
// ReceiveIncoming refuses it before any credential is issued or QEMU started.
// An empty source arch is x86_64, the guest qemu.Config builds for "".
func TestReceiveIncoming_RefusesAMismatchedGuestArch(t *testing.T) {
	cases := []struct {
		name       string
		sourceArch qemu.Arch
		wantSource qemu.Arch
	}{
		{"x86_64", qemu.ArchX86_64, qemu.ArchX86_64},
		{"empty-is-x86_64", "", qemu.ArchX86_64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			orch.config.Arch = qemu.ArchAArch64
			tlsProv := &fakeServerTLS{dir: t.TempDir()}
			orch.config.MigrationTLS = tlsProv
			swapReceiverLauncher(t, func(context.Context, *incomingReceiverParams) (incomingReceiver, error) {
				t.Fatal("a receiver was launched for a guest of another architecture")
				return nil, nil
			})

			_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
				Arch:   tc.sourceArch,
				VMName: "guest",
				Config: &InstanceConfig{Memory: 1024},
			})
			var archErr *MigrationArchMismatchError
			require.ErrorAs(t, err, &archErr)
			assert.Equal(t, tc.wantSource, archErr.Source)
			assert.Equal(t, qemu.ArchAArch64, archErr.Destination)
			assert.False(t, tlsProv.materialized, "no credentials are issued for a receiver that cannot run the guest")
		})
	}
}

func TestReceiveIncoming_EmptySourceArchMatchesAnX86_64Host(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.Arch = qemu.ArchX86_64
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
	swapReceiverLauncher(t, func(context.Context, *incomingReceiverParams) (incomingReceiver, error) {
		return &fakeIncomingReceiver{port: 49200}, nil
	})

	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
}

func TestMigrationArchMismatchError_Message(t *testing.T) {
	err := &MigrationArchMismatchError{Source: qemu.ArchX86_64, Destination: qemu.ArchAArch64}
	assert.Equal(t, `compute: migration source guest arch "x86_64" does not match this host's guest arch "aarch64"`, err.Error())
}

func TestReceiveIncoming_NoServerTLS(t *testing.T) {
	orch := newOpsOrchestrator(t)
	// MigrationTLS unset entirely.
	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.ErrorIs(t, err, ErrMigrationServerTLSNotConfigured)
}

func TestReceiveIncoming_TLSProviderLacksServerCapability(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = sourceOnlyTLS{}
	_, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
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
		Arch:   orch.config.Arch,
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

	recv := &fakeIncomingReceiver{port: 5000, vm: newReceivedVM(t, orch)}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		Arch:   orch.config.Arch,
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
		Arch:   orch.config.Arch,
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
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)

	err = orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	require.ErrorIs(t, err, ErrMigrationReceiveFailed)
}
