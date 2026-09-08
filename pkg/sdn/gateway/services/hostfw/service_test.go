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

package hostfw

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeApplier records applies and lets a test fail a chosen one.
type fakeApplier struct {
	applied       []string
	present       bool
	failApply     map[int]error // by apply ordinal (0-based)
	failRemove    error
	failInstalled error
}

func (f *fakeApplier) Apply(_ context.Context, r *Rendered) error {
	if err, ok := f.failApply[len(f.applied)]; ok {
		f.applied = append(f.applied, "FAILED:"+r.Fingerprint)
		return err
	}
	f.applied = append(f.applied, r.Fingerprint)
	f.present = true
	return nil
}

func (f *fakeApplier) Remove(_ context.Context) error {
	if f.failRemove != nil {
		return f.failRemove
	}
	f.present = false
	return nil
}

func (f *fakeApplier) Installed(_ context.Context) (bool, error) {
	if f.failInstalled != nil {
		return false, f.failInstalled
	}
	return f.present, nil
}

// mutableInventory lets a test change what the daemon reports between
// reconciles.
type mutableInventory struct{ listeners []Listener }

func (m *mutableInventory) Listeners() []Listener { return m.listeners }

func newService(t *testing.T, applier *fakeApplier, inv ListenerInventory, cfg Config) *Service {
	t.Helper()
	clock := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	svc, err := New(Deps{Applier: applier, Inventory: inv, Config: cfg, Now: func() time.Time { return clock }})
	require.NoError(t, err)
	return svc
}

func TestNew_ValidatesDeps(t *testing.T) {
	_, err := New(Deps{Inventory: StaticInventory{}})
	assert.ErrorIs(t, err, ErrNilApplier)
	_, err = New(Deps{Applier: &fakeApplier{}})
	assert.ErrorIs(t, err, ErrNilInventory)
	_, err = New(Deps{Applier: &fakeApplier{}, Inventory: StaticInventory{}, Config: Config{Tunnels: []string{""}}})
	assert.ErrorIs(t, err, ErrEmptyInterface)
	svc, err := New(Deps{Applier: &fakeApplier{}, Inventory: StaticInventory{}})
	require.NoError(t, err)
	assert.False(t, svc.Active())
	assert.NotNil(t, svc.logger)
}

func TestService_StartAppliesMergedRuleset(t *testing.T) {
	applier := &fakeApplier{}
	inv := StaticInventory{{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443, Comment: "tls"}}
	cfg := Config{Extra: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 22, Comment: "sshd"}}, Tunnels: []string{"gre1"}}
	svc := newService(t, applier, inv, cfg)

	require.NoError(t, svc.Start(context.Background()))
	assert.True(t, svc.Active())
	require.Len(t, applier.applied, 1)
	rendered := svc.Rendered()
	require.NotNil(t, rendered)
	assert.Equal(t, applier.applied[0], rendered.Fingerprint)
	assert.Contains(t, rendered.Text, "dport 8443")
	assert.Contains(t, rendered.Text, "dport 22")
	assert.Contains(t, rendered.Text, `iifname "gre1" tcp dport 179`)

	h := svc.Health()
	assert.True(t, h.Active)
	assert.True(t, h.Installed)
	assert.Equal(t, rendered.Fingerprint, h.Fingerprint)
	assert.Equal(t, len(rendered.Rules), h.RuleCount)
	assert.NoError(t, h.LastError)
	assert.False(t, h.LastReconcile.IsZero())

	assert.ErrorIs(t, svc.Start(context.Background()), ErrAlreadyStarted)
}

func TestService_StartFailsClosed(t *testing.T) {
	t.Run("apply failure leaves it inactive", func(t *testing.T) {
		applier := &fakeApplier{failApply: map[int]error{0: errors.New("EPERM")}}
		svc := newService(t, applier, StaticInventory{}, Config{})
		err := svc.Start(context.Background())
		require.Error(t, err)
		assert.False(t, svc.Active())
		assert.Error(t, svc.Health().LastError)
	})
	t.Run("inventory that does not validate", func(t *testing.T) {
		applier := &fakeApplier{}
		svc := newService(t, applier, StaticInventory{{Protocol: ProtocolTCP}}, Config{})
		assert.ErrorIs(t, svc.Start(context.Background()), ErrZeroPort)
		assert.Empty(t, applier.applied)
	})
	t.Run("duplicate between inventory and extra", func(t *testing.T) {
		svc := newService(t, &fakeApplier{},
			StaticInventory{{Interface: "eth0", Protocol: ProtocolTCP, Port: 22}},
			Config{Extra: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 22}}})
		assert.ErrorIs(t, svc.Start(context.Background()), ErrDuplicateListener)
	})
}

func TestService_StopRemovesTheTable(t *testing.T) {
	applier := &fakeApplier{}
	svc := newService(t, applier, StaticInventory{}, Config{})
	assert.ErrorIs(t, svc.Stop(context.Background()), ErrNotStarted)
	require.NoError(t, svc.Start(context.Background()))
	require.NoError(t, svc.Stop(context.Background()))
	assert.False(t, svc.Active())
	assert.False(t, applier.present)
	assert.Nil(t, svc.Rendered())

	applier.failRemove = errors.New("busy")
	require.NoError(t, svc.Start(context.Background()))
	assert.Error(t, svc.Stop(context.Background()))
	assert.True(t, svc.Active(), "a table that would not go away is still ours")
}

func TestService_ReconcileAppliesOnlyChanges(t *testing.T) {
	applier := &fakeApplier{}
	inv := &mutableInventory{listeners: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443}}}
	svc := newService(t, applier, inv, Config{})
	assert.ErrorIs(t, svc.Reconcile(context.Background()), ErrNotStarted)
	require.NoError(t, svc.Start(context.Background()))
	first := svc.Rendered().Fingerprint

	require.NoError(t, svc.Reconcile(context.Background()))
	assert.Len(t, applier.applied, 1, "an unchanged inventory applies nothing")

	inv.listeners = append(inv.listeners, Listener{Interface: "eth0", Protocol: ProtocolTCP, Port: 9445})
	require.NoError(t, svc.Reconcile(context.Background()))
	assert.Len(t, applier.applied, 2)
	assert.NotEqual(t, first, svc.Rendered().Fingerprint)
	assert.Contains(t, svc.Rendered().Text, "dport 9445")

	// A table removed underneath the service is reinstalled unchanged.
	applier.present = false
	require.NoError(t, svc.Reconcile(context.Background()))
	assert.Len(t, applier.applied, 3)
	assert.True(t, svc.Health().Installed)
}

func TestService_ReconcileRollsBack(t *testing.T) {
	t.Run("rollback succeeds", func(t *testing.T) {
		applier := &fakeApplier{failApply: map[int]error{1: errors.New("EINVAL")}}
		inv := &mutableInventory{listeners: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443}}}
		svc := newService(t, applier, inv, Config{})
		require.NoError(t, svc.Start(context.Background()))
		good := svc.Rendered().Fingerprint

		inv.listeners = append(inv.listeners, Listener{Interface: "eth0", Protocol: ProtocolUDP, Port: 53})
		err := svc.Reconcile(context.Background())
		var op *OpError
		require.True(t, errors.As(err, &op), "got %v", err)
		assert.Equal(t, "rollback", op.Op)
		require.Len(t, applier.applied, 3, "attempt, then the rollback apply")
		assert.Equal(t, good, applier.applied[2])
		assert.Equal(t, good, svc.Rendered().Fingerprint, "the previous ruleset stays the applied one")
		assert.Error(t, svc.Health().LastError)
		assert.True(t, svc.Health().Installed)
	})
	t.Run("rollback fails too", func(t *testing.T) {
		applier := &fakeApplier{failApply: map[int]error{1: errors.New("EINVAL"), 2: errors.New("EPERM")}}
		inv := &mutableInventory{listeners: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443}}}
		svc := newService(t, applier, inv, Config{})
		require.NoError(t, svc.Start(context.Background()))
		inv.listeners = append(inv.listeners, Listener{Interface: "eth0", Protocol: ProtocolUDP, Port: 53})
		err := svc.Reconcile(context.Background())
		var rb *RollbackError
		require.True(t, errors.As(err, &rb), "got %v", err)
		assert.False(t, svc.Health().Installed, "state unknown until a reconcile succeeds")
		assert.ErrorIs(t, svc.Health().LastError, rb.Apply)
	})
	t.Run("render failure is reported", func(t *testing.T) {
		inv := &mutableInventory{listeners: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443}}}
		svc := newService(t, &fakeApplier{}, inv, Config{})
		require.NoError(t, svc.Start(context.Background()))
		inv.listeners[0].Port = 0
		assert.ErrorIs(t, svc.Reconcile(context.Background()), ErrZeroPort)
		assert.Error(t, svc.Health().LastError)
	})
	t.Run("inspect failure is reported", func(t *testing.T) {
		applier := &fakeApplier{}
		svc := newService(t, applier, StaticInventory{}, Config{})
		require.NoError(t, svc.Start(context.Background()))
		applier.failInstalled = errors.New("netlink down")
		assert.Error(t, svc.Reconcile(context.Background()))
	})
}

func TestService_WritesTheBaseRuleset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nftables.d", "tp-host.nft")
	applier := &fakeApplier{}
	inv := &mutableInventory{listeners: []Listener{{Interface: "eth0", Protocol: ProtocolTCP, Port: 8443}}}
	svc := newService(t, applier, inv, Config{BaseRulesetPath: path})

	require.NoError(t, svc.Start(context.Background()))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, svc.Rendered().Text, string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	inv.listeners = append(inv.listeners, Listener{Interface: "eth0", Protocol: ProtocolTCP, Port: 22})
	require.NoError(t, svc.Reconcile(context.Background()))
	got, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(got), "dport 22", "the boot file follows the live table")
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temp files left behind")
}

func TestService_BaseRulesetWriteFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	svc := newService(t, &fakeApplier{}, StaticInventory{}, Config{BaseRulesetPath: filepath.Join(blocker, "tp-host.nft")})
	err := svc.Start(context.Background())
	var op *OpError
	require.True(t, errors.As(err, &op), "got %v", err)
	assert.Equal(t, "write-base", op.Op)
	assert.False(t, svc.Active())
}

func TestStaticInventory(t *testing.T) {
	inv := StaticInventory{{Protocol: ProtocolTCP, Port: 1}}
	assert.Len(t, inv.Listeners(), 1)
	assert.Empty(t, StaticInventory(nil).Listeners())
}
