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

package fhrp

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingActuator records what the group asked for.
type recordingActuator struct {
	adverts  []uint8
	claims   int
	releases int
	failAdv  error
	failClm  error
	failRel  error
}

func (a *recordingActuator) Advertise(_ *Group, priority uint8) error {
	a.adverts = append(a.adverts, priority)
	return a.failAdv
}
func (a *recordingActuator) Claim(*Group) error   { a.claims++; return a.failClm }
func (a *recordingActuator) Release(*Group) error { a.releases++; return a.failRel }

func boolp(b bool) *bool { return &b }

func backupConfig() GroupConfig {
	return GroupConfig{VRID: 20, Interface: "br-int", Priority: 100, AdvertIntervalCentiseconds: 100,
		Addresses: []string{"10.4.200.1/24"}, Source: "10.4.200.2"}
}

func newGroupT(t *testing.T, cfg GroupConfig) (*Group, *recordingActuator) {
	t.Helper()
	act := &recordingActuator{}
	g, err := NewGroup(cfg, act)
	require.NoError(t, err)
	return g, act
}

var t0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func TestNewGroup_Rejects(t *testing.T) {
	_, err := NewGroup(GroupConfig{}, &recordingActuator{})
	var invalid *ErrInvalidGroupConfig
	require.True(t, errors.As(err, &invalid))
	_, err = NewGroup(backupConfig(), nil)
	var req *ErrTransportRequired
	require.True(t, errors.As(err, &req))
}

func TestGroup_Timers(t *testing.T) {
	g, _ := newGroupT(t, backupConfig())
	// Skew_Time = ((256 − 100) × 100 cs) / 256 = 60 cs; Master_Down = 300 + 60 cs.
	assert.Equal(t, 600*time.Millisecond, g.SkewTime())
	assert.Equal(t, 3600*time.Millisecond, g.MasterDownInterval())
	assert.Equal(t, time.Second, g.AdvertInterval())
	assert.True(t, g.NextDeadline().IsZero(), "no timer in Initialize")

	owner := backupConfig()
	owner.Priority = PriorityOwner
	og, _ := newGroupT(t, owner)
	assert.Equal(t, time.Duration(0), og.SkewTime(), "the owner has no skew")
}

func TestGroup_StartupBackupThenMasterDown(t *testing.T) {
	g, act := newGroupT(t, backupConfig())
	require.NoError(t, g.Startup(t0))
	assert.Equal(t, StateBackup, g.State())
	assert.Equal(t, t0.Add(g.MasterDownInterval()), g.NextDeadline())
	assert.Empty(t, act.adverts)

	// Early tick: nothing.
	require.NoError(t, g.Tick(t0.Add(time.Second)))
	assert.Equal(t, StateBackup, g.State())

	// Master_Down_Timer fires: advertise, claim, become master.
	fire := g.NextDeadline()
	require.NoError(t, g.Tick(fire))
	assert.Equal(t, StateMaster, g.State())
	assert.Equal(t, []uint8{100}, act.adverts)
	assert.Equal(t, 1, act.claims)
	assert.Equal(t, fire.Add(time.Second), g.NextDeadline(), "Adver_Timer set")
	assert.Equal(t, uint64(2), g.Transitions())

	// Adver_Timer fires: advertise again.
	require.NoError(t, g.Tick(g.NextDeadline()))
	assert.Equal(t, []uint8{100, 100}, act.adverts)
}

func TestGroup_OwnerStartsAsMaster(t *testing.T) {
	cfg := backupConfig()
	cfg.Priority = PriorityOwner
	g, act := newGroupT(t, cfg)
	require.NoError(t, g.Startup(t0))
	assert.Equal(t, StateMaster, g.State())
	assert.Equal(t, []uint8{255}, act.adverts)
	assert.Equal(t, 1, act.claims)
	require.NoError(t, g.Startup(t0), "startup twice is a no-op")
	assert.Equal(t, 1, act.claims)
}

func TestGroup_BackupHearsMaster(t *testing.T) {
	g, act := newGroupT(t, backupConfig())
	require.NoError(t, g.Startup(t0))
	master := netip.MustParseAddr("10.4.200.10")

	t.Run("higher priority resets the timer with the master's interval", func(t *testing.T) {
		adv := &Advertisement{VRID: 20, Priority: 200, MaxAdvertInterval: 50, Addresses: g.Addresses()}
		now := t0.Add(2 * time.Second)
		require.NoError(t, g.HandleAdvertisement(adv, master, now))
		assert.Equal(t, StateBackup, g.State())
		// 3 × 50 cs + ((256−100)×50)/256 = 150 + 30 cs.
		assert.Equal(t, now.Add(1800*time.Millisecond), g.NextDeadline())
	})
	t.Run("lower priority while preempting is discarded", func(t *testing.T) {
		before := g.NextDeadline()
		adv := &Advertisement{VRID: 20, Priority: 50, MaxAdvertInterval: 100, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, master, t0.Add(3*time.Second)))
		assert.Equal(t, before, g.NextDeadline(), "timer untouched, the backup will preempt when it fires")
	})
	t.Run("release advertisement shortens the wait to skew time", func(t *testing.T) {
		now := t0.Add(4 * time.Second)
		adv := &Advertisement{VRID: 20, Priority: PriorityRelease, MaxAdvertInterval: 50, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, master, now))
		assert.Equal(t, now.Add(g.SkewTime()), g.NextDeadline())
		require.NoError(t, g.Tick(g.NextDeadline()))
		assert.Equal(t, StateMaster, g.State())
		assert.Equal(t, 1, act.claims)
	})
}

func TestGroup_BackupWithoutPreemptAcceptsLowerMaster(t *testing.T) {
	cfg := backupConfig()
	cfg.Preempt = boolp(false)
	g, _ := newGroupT(t, cfg)
	require.NoError(t, g.Startup(t0))
	now := t0.Add(time.Second)
	adv := &Advertisement{VRID: 20, Priority: 10, MaxAdvertInterval: 100, Addresses: g.Addresses()}
	require.NoError(t, g.HandleAdvertisement(adv, netip.MustParseAddr("10.4.200.10"), now))
	assert.Equal(t, now.Add(g.MasterDownInterval()), g.NextDeadline(), "a non-preempting backup defers to any master")
}

func TestGroup_MasterYieldsAndReleases(t *testing.T) {
	cfg := backupConfig()
	cfg.Priority = 150
	g, act := newGroupT(t, cfg)
	require.NoError(t, g.Startup(t0))
	require.NoError(t, g.Tick(g.NextDeadline()))
	require.Equal(t, StateMaster, g.State())
	peer := netip.MustParseAddr("10.4.200.10")

	t.Run("lower priority is ignored", func(t *testing.T) {
		adv := &Advertisement{VRID: 20, Priority: 100, MaxAdvertInterval: 100, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, peer, t0.Add(10*time.Second)))
		assert.Equal(t, StateMaster, g.State())
	})
	t.Run("equal priority from a lower source is ignored", func(t *testing.T) {
		adv := &Advertisement{VRID: 20, Priority: 150, MaxAdvertInterval: 100, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, netip.MustParseAddr("10.4.200.1"), t0.Add(10*time.Second)))
		assert.Equal(t, StateMaster, g.State())
	})
	t.Run("release from another master triggers an immediate advertisement", func(t *testing.T) {
		n := len(act.adverts)
		adv := &Advertisement{VRID: 20, Priority: PriorityRelease, MaxAdvertInterval: 100, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, peer, t0.Add(10*time.Second)))
		assert.Len(t, act.adverts, n+1)
		assert.Equal(t, StateMaster, g.State())
	})
	t.Run("equal priority from a higher source yields", func(t *testing.T) {
		now := t0.Add(11 * time.Second)
		adv := &Advertisement{VRID: 20, Priority: 150, MaxAdvertInterval: 100, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, peer, now))
		assert.Equal(t, StateBackup, g.State())
		assert.Equal(t, 1, act.releases)
		assert.Equal(t, now.Add(g.MasterDownInterval()), g.NextDeadline())
	})
	t.Run("higher priority yields", func(t *testing.T) {
		require.NoError(t, g.Tick(g.NextDeadline()))
		require.Equal(t, StateMaster, g.State())
		adv := &Advertisement{VRID: 20, Priority: 200, MaxAdvertInterval: 100, Addresses: g.Addresses()}
		require.NoError(t, g.HandleAdvertisement(adv, netip.MustParseAddr("10.4.200.3"), t0.Add(20*time.Second)))
		assert.Equal(t, StateBackup, g.State())
		assert.Equal(t, 2, act.releases)
	})
}

func TestGroup_Shutdown(t *testing.T) {
	g, act := newGroupT(t, backupConfig())
	require.NoError(t, g.Shutdown(t0), "shutdown in Initialize is a no-op")
	require.NoError(t, g.Startup(t0))
	require.NoError(t, g.Shutdown(t0))
	assert.Equal(t, StateInitialize, g.State())
	assert.Empty(t, act.adverts, "a backup leaves silently")

	require.NoError(t, g.Startup(t0))
	require.NoError(t, g.Tick(g.NextDeadline()))
	require.Equal(t, StateMaster, g.State())
	require.NoError(t, g.Shutdown(t0.Add(time.Minute)))
	assert.Equal(t, StateInitialize, g.State())
	assert.Equal(t, uint8(PriorityRelease), act.adverts[len(act.adverts)-1], "a master announces its release")
	assert.Equal(t, 1, act.releases)
	assert.True(t, g.NextDeadline().IsZero())
}

func TestGroup_ActuatorFailuresAreReported(t *testing.T) {
	g, act := newGroupT(t, backupConfig())
	act.failClm = errors.New("netlink EPERM")
	require.NoError(t, g.Startup(t0))
	err := g.Tick(g.NextDeadline())
	require.Error(t, err)
	assert.Equal(t, StateMaster, g.State(), "the state advances so the peer does not also claim")
	assert.ErrorIs(t, g.LastError(), act.failClm)

	act.failClm = nil
	act.failAdv = errors.New("ENETDOWN")
	err = g.Tick(g.NextDeadline())
	var tf *ErrTransportFailed
	require.True(t, errors.As(err, &tf), "got %v", err)

	act.failAdv = nil
	act.failRel = errors.New("EBUSY")
	err = g.Shutdown(t0.Add(time.Hour))
	assert.ErrorIs(t, err, act.failRel)
	assert.Equal(t, StateInitialize, g.State())
}

// A claim that fails at takeover stays reported, and is retried, until a
// claim succeeds: a later successful advertisement must not hide it.
func TestGroup_ClaimFailureSurvivesAdvertisement(t *testing.T) {
	g, act := newGroupT(t, backupConfig())
	act.failClm = errors.New("netlink EPERM")
	require.NoError(t, g.Startup(t0))
	require.Error(t, g.Tick(g.NextDeadline()))
	require.Equal(t, StateMaster, g.State())
	assert.ErrorIs(t, g.ClaimError(), act.failClm)

	// The claim still fails: the next advertisement retries it and reports it.
	require.Error(t, g.Tick(g.NextDeadline()))
	assert.Equal(t, 2, act.claims)
	assert.ErrorIs(t, g.ClaimError(), act.failClm)
	assert.ErrorIs(t, g.LastError(), act.failClm)

	// The claim is repaired: both errors clear.
	act.failClm = nil
	require.NoError(t, g.Tick(g.NextDeadline()))
	assert.Equal(t, 3, act.claims)
	assert.NoError(t, g.ClaimError())
	assert.NoError(t, g.LastError())

	// Leaving Master drops an unrepaired claim failure.
	g2, act2 := newGroupT(t, backupConfig())
	act2.failClm = errors.New("netlink EPERM")
	require.NoError(t, g2.Startup(t0))
	require.Error(t, g2.Tick(g2.NextDeadline()))
	require.Error(t, g2.ClaimError())
	_ = g2.Shutdown(t0.Add(time.Hour))
	assert.NoError(t, g2.ClaimError())
}

func TestGroup_Accessors(t *testing.T) {
	g, _ := newGroupT(t, backupConfig())
	assert.Equal(t, FamilyIPv4, g.Family())
	assert.Equal(t, uint8(20), g.Config().VRID)
	assert.Equal(t, netip.MustParseAddr("10.4.200.2"), g.Source())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.4.200.1/24")}, g.Prefixes())
	assert.Equal(t, "initialize", StateInitialize.String())
	assert.Equal(t, "backup", StateBackup.String())
	assert.Equal(t, "master", StateMaster.String())
	assert.Equal(t, "unknown", State(7).String())
	assert.Equal(t, &ErrInvalidPacket{Reason: "nil advertisement"}, g.HandleAdvertisement(nil, g.Source(), t0))
	require.NoError(t, g.HandleAdvertisement(&Advertisement{}, g.Source(), t0), "ignored in Initialize")
}
