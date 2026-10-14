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

package gateway

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// fakeLeaseControl is a control plane holding one desired configuration and
// recording the lease writes it receives.
type fakeLeaseControl struct {
	desired   *gwstate.DesiredConfig
	fetchErr  error
	putErr    error
	deleteErr error
	// lostAnswer is returned by a PUT the control plane has committed: the
	// answer timed out after the write landed.
	lostAnswer error
	puts       []gwstate.DesiredVPNLease
	deletes    []string
}

func (c *fakeLeaseControl) FetchDesiredConfig(context.Context) (*gwstate.DesiredConfig, error) {
	return c.desired, c.fetchErr
}

func (c *fakeLeaseControl) PutVPNLease(_ context.Context, lease *gwstate.DesiredVPNLease) error {
	if c.putErr != nil {
		return c.putErr
	}
	c.puts = append(c.puts, *lease)
	return c.lostAnswer
}

func (c *fakeLeaseControl) DeleteVPNLease(_ context.Context, tenantID, leaseID string) error {
	if c.deleteErr != nil {
		return c.deleteErr
	}
	c.deletes = append(c.deletes, tenantID+"/"+leaseID)
	return nil
}

// recordedLease is lease-1 for tenant-a/laptop-1 as the control plane
// records it.
func recordedLease() gwstate.DesiredVPNLease {
	now := time.Now()
	return gwstate.DesiredVPNLease{
		ID:                      "lease-1",
		TenantID:                "tenant-a",
		DeviceID:                "laptop-1",
		Address:                 "100.64.0.2/32",
		Zones:                   []string{"management"},
		DataPlane:               string(vpn.DataPlaneMASQUE),
		ClientCertificateSHA256: make([]byte, 32),
		IssuedAt:                now.Add(-time.Minute),
		ExpiresAt:               now.Add(time.Hour),
		Renewals:                2,
		Verdict:                 gwstate.DesiredVPNVerdict{Passed: true, Cryptographic: true, ProfileID: 7},
	}
}

// newProjectedRig is the vpn rig with a control plane that recorded lease-1
// and enrols its device, over an IPAM holding the service's pool.
func newProjectedRig(t *testing.T) (*vpnRig, *fakeLeaseControl) {
	t.Helper()
	control := recordingControl()
	return projectedRigOver(t, control, tempRevocationJournal(t)), control
}

// recordingControl is a control plane that recorded lease-1 and enrols its
// device.
func recordingControl() *fakeLeaseControl {
	section := laptopSection()
	section.Leases = []gwstate.DesiredVPNLease{recordedLease()}
	return &fakeLeaseControl{desired: &gwstate.DesiredConfig{GatewayID: "vpn-gw", VPN: section}}
}

// projectedRigOver is the vpn rig over control and journal, as a gatewayd
// process starting against that control plane and data directory would be.
func projectedRigOver(t *testing.T, control VPNLeaseControl, journal *RevocationJournal) *vpnRig {
	t.Helper()
	r := newVPNRig(t)
	pool := r.gw.config.Runtime.VPN.IPAM.(*backends.MemoryBackend)
	require.NoError(t, pool.CreatePool(context.Background(), &ipam.Pool{
		ID: "vpn-pool", Name: "remote-access", CIDR: netip.MustParsePrefix("100.64.0.0/24"),
	}))
	r.gw.SetVPNLeaseControl(control, journal)
	return r
}

// tempRevocationJournal is a journal in a fresh directory, not yet written.
func tempRevocationJournal(t *testing.T) *RevocationJournal {
	t.Helper()
	return NewRevocationJournal(filepath.Join(t.TempDir(), "vpn", "pending-revocations.json"))
}

// unwritableJournal is a journal whose every write fails: its parent is a
// file.
func unwritableJournal(t *testing.T) *RevocationJournal {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	return NewRevocationJournal(filepath.Join(blocker, "pending-revocations.json"))
}

// failingPutStore is a projection that refuses every Put.
type failingPutStore struct {
	vpn.LeaseStore
	err error
}

func (s *failingPutStore) Put(context.Context, *vpn.Lease) error { return s.err }

// newProjectedStore is a projection over local and control with a fresh
// journal.
func newProjectedStore(t *testing.T, local vpn.LeaseStore, control VPNLeaseControl) *projectedLeaseStore {
	t.Helper()
	return &projectedLeaseStore{local: local, control: control, journal: tempRevocationJournal(t)}
}

// journaled is what store's journal holds on disk.
func journaled(t *testing.T, store *projectedLeaseStore) map[vpn.LeaseID]string {
	t.Helper()
	pending, err := store.journal.load()
	require.NoError(t, err)
	return pending
}

func TestVPNService_StartRebuildsTheLeasesTheControlPlaneRecorded(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)

	require.NoError(t, r.handler().Start(ctx))
	t.Cleanup(func() { require.NoError(t, r.handler().Stop(ctx)) })

	stored, err := r.leases.Get(ctx, "lease-1")
	require.NoError(t, err, "the recorded lease is back in the projection")
	assert.Equal(t, 2, stored.Renewals)
	assert.Equal(t, uint64(7), stored.Verdict.ProfileID)
	held, err := r.gw.config.Runtime.VPN.IPAM.GetAllocation(ctx, stored.Address.Addr())
	require.NoError(t, err)
	assert.Equal(t, "laptop-1", held.DeviceID, "the restored lease holds its address again")
	assert.Len(t, r.gw.vpn.svc.Enrolments(), 1, "the section of the same pull is applied")
	assert.Empty(t, control.puts, "rebuilding writes nothing back")
	assert.Empty(t, control.deletes)
}

func TestVPNService_StartRevokesARecordedLeaseWhosePeerWasWithdrawn(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)
	control.desired.VPN.Peers = nil

	require.NoError(t, r.handler().Start(ctx))
	t.Cleanup(func() { require.NoError(t, r.handler().Stop(ctx)) })

	assert.Equal(t, []string{"tenant-a/lease-1"}, control.deletes, "the revocation reaches the control plane")
	_, err := r.leases.Get(ctx, "lease-1")
	var nf *vpn.ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "got %v", err)
}

func TestVPNService_StartRefusesWhenTheControlPlaneIsUnreachable(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)
	control.fetchErr = errors.New("dial tcp: connection refused")

	err := r.handler().Start(ctx)

	var unavailable *vpn.ErrLeaseStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.ErrorIs(t, err, control.fetchErr)
	assert.Empty(t, r.events, "no plane starts on an empty projection")
	assert.Nil(t, r.gw.collectVPN(ctx), "the service is not running")
}

func TestVPNService_StartRefusesARecordThatDoesNotProject(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)
	control.desired.VPN.Leases[0].Address = "not-an-address"

	err := r.handler().Start(ctx)

	var invalid *gwstate.ErrDesiredConfigInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, "vpn.leases[0].address", invalid.Field)
}

func TestVPNService_WritesRevocationsThroughToTheControlPlane(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)
	require.NoError(t, r.handler().Start(ctx))
	t.Cleanup(func() { require.NoError(t, r.handler().Stop(ctx)) })

	require.NoError(t, r.gw.vpn.svc.Revoke(ctx, "lease-1", vpn.RevokeOperator))

	assert.Equal(t, []string{"tenant-a/lease-1"}, control.deletes)
}

func TestVPNService_ARetriedRevocationLeavesAReassignedAddressAlone(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)
	require.NoError(t, r.handler().Start(ctx))
	t.Cleanup(func() { require.NoError(t, r.handler().Stop(ctx)) })
	pool := r.gw.config.Runtime.VPN.IPAM
	addr := netip.MustParseAddr("100.64.0.9")
	_, err := pool.AllocateSpecific(ctx, &ipam.AllocationRequest{PoolID: "vpn-pool", DeviceID: "laptop-2", RequestedIP: addr})
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, r.leases.Put(ctx, &vpn.Lease{
		ID: "lease-2", TenantID: "tenant-a", DeviceID: "laptop-2",
		Address: netip.PrefixFrom(addr, addr.BitLen()), Zones: []string{"management"},
		DataPlane: vpn.DataPlaneMASQUE, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}))

	// The sweep tears the expired lease down; the control plane refuses
	// its DELETE.
	control.deleteErr = errors.New("control plane returned 503")
	r.gw.vpn.svc.Sweep(ctx)
	assert.Equal(t, []vpn.LeaseID{"lease-2"}, r.plane.removed)
	_, err = r.gw.vpn.svc.Lease(ctx, "lease-2")
	var nf *vpn.ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "a torn-down lease is no longer served: %v", err)

	// Its address goes to another device, then the control plane recovers.
	_, err = pool.AllocateSpecific(ctx, &ipam.AllocationRequest{PoolID: "vpn-pool", DeviceID: "laptop-3", RequestedIP: addr})
	require.NoError(t, err)
	control.deleteErr = nil
	r.gw.vpn.svc.Sweep(ctx)

	held, err := pool.GetAllocation(ctx, addr)
	require.NoError(t, err, "the retry leaves the reassigned address allocated")
	assert.Equal(t, "laptop-3", held.DeviceID)
	assert.Equal(t, ipam.AllocationStatusActive, held.Status, "the retry releases no address")
	assert.Equal(t, []vpn.LeaseID{"lease-2"}, r.plane.removed, "the retry removes no peer")
	assert.Equal(t, []string{"tenant-a/lease-2"}, control.deletes, "the retry is the control-plane DELETE alone")
}

func TestVPNService_StopKeepsTheRecordedLeases(t *testing.T) {
	ctx := context.Background()
	r, control := newProjectedRig(t)
	require.NoError(t, r.handler().Start(ctx))

	require.NoError(t, r.handler().Stop(ctx))

	assert.Empty(t, control.deletes, "stopping is not revoking")
	_, err := r.leases.Get(ctx, "lease-1")
	assert.NoError(t, err, "the next start reinstates the lease")
}

// TestVPNService_ARefusedRevocationOutlivesARestart revokes a lease while the
// control plane refuses the DELETE, then starts a new gateway process over
// the same data directory while the control plane still records the lease.
// The revoked device must not come back without a fresh admission.
func TestVPNService_ARefusedRevocationOutlivesARestart(t *testing.T) {
	ctx := context.Background()
	control := recordingControl()
	journal := tempRevocationJournal(t)
	first := projectedRigOver(t, control, journal)
	require.NoError(t, first.handler().Start(ctx))
	control.deleteErr = errors.New("control plane returned 503")
	err := first.gw.vpn.svc.Revoke(ctx, "lease-1", vpn.RevokeOperator)
	var unavailable *vpn.ErrLeaseStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	require.NoError(t, first.handler().Stop(ctx))

	restarted := projectedRigOver(t, control, journal)
	require.NoError(t, restarted.handler().Start(ctx))
	t.Cleanup(func() { require.NoError(t, restarted.handler().Stop(ctx)) })

	_, err = restarted.leases.Get(ctx, "lease-1")
	var nf *vpn.ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "the revoked lease is not reinstated: %v", err)
	_, err = restarted.gw.config.Runtime.VPN.IPAM.GetAllocation(ctx, netip.MustParseAddr("100.64.0.2"))
	assert.Error(t, err, "the revoked lease holds no address")

	// The control plane recovers: the next sweep completes the revocation.
	control.deleteErr = nil
	restarted.gw.vpn.svc.Sweep(ctx)
	assert.Equal(t, []string{"tenant-a/lease-1"}, control.deletes)
	pending, err := journal.load()
	require.NoError(t, err)
	assert.Empty(t, pending, "a landed DELETE leaves the journal")
}

func TestVPNService_ARevocationRecordedNowhereIsRefusedWhole(t *testing.T) {
	ctx := context.Background()
	control := recordingControl()
	journal := tempRevocationJournal(t)
	first := projectedRigOver(t, control, journal)
	require.NoError(t, first.handler().Start(ctx))

	// Disk and control plane both fail: the journal's path is a directory
	// the rename cannot replace, and the DELETE is refused.
	require.NoError(t, os.RemoveAll(journal.path))
	require.NoError(t, os.MkdirAll(filepath.Join(journal.path, "occupied"), 0o700))
	control.deleteErr = errors.New("control plane returned 503")
	err := first.gw.vpn.svc.Revoke(ctx, "lease-1", vpn.RevokeOperator)
	var unrecorded *vpn.ErrRevocationNotRecorded
	require.True(t, errors.As(err, &unrecorded), "got %v", err)

	_, err = first.leases.Get(ctx, "lease-1")
	assert.NoError(t, err, "the lease is still served")
	alloc, err := first.gw.config.Runtime.VPN.IPAM.GetAllocation(ctx, netip.MustParseAddr("100.64.0.2"))
	require.NoError(t, err)
	assert.Equal(t, "laptop-1", alloc.DeviceID, "the lease keeps its address")
	assert.Empty(t, first.plane.removed, "the peer stays")
	require.NoError(t, first.handler().Stop(ctx))

	// The disk is repaired and the gateway restarts: it restores the lease
	// the first process still served, so the two never disagreed.
	require.NoError(t, os.RemoveAll(journal.path))
	restarted := projectedRigOver(t, control, journal)
	require.NoError(t, restarted.handler().Start(ctx))
	t.Cleanup(func() { require.NoError(t, restarted.handler().Stop(ctx)) })
	_, err = restarted.leases.Get(ctx, "lease-1")
	require.NoError(t, err)

	// The retried revocation is recorded and tears the lease down.
	control.deleteErr = nil
	require.NoError(t, restarted.gw.vpn.svc.Revoke(ctx, "lease-1", vpn.RevokeOperator))
	assert.Equal(t, []string{"tenant-a/lease-1"}, control.deletes)
	alloc, err = restarted.gw.config.Runtime.VPN.IPAM.GetAllocation(ctx, netip.MustParseAddr("100.64.0.2"))
	if err == nil {
		assert.NotEqual(t, ipam.AllocationStatusActive, alloc.Status, "the revoked lease holds no address")
	}
}

func TestVPNService_ALeaseControlPlaneNeedsARevocationJournal(t *testing.T) {
	r := newVPNRig(t)
	r.gw.SetVPNLeaseControl(recordingControl(), nil)

	err := r.handler().Start(context.Background())

	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, ServiceManagementVPN, unavailable.Service)
	assert.Empty(t, r.events, "no plane starts")
}

func TestVPNService_StartRefusesAnUnreadableRevocationJournal(t *testing.T) {
	ctx := context.Background()
	control := recordingControl()
	journal := tempRevocationJournal(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(journal.path), 0o700))
	require.NoError(t, os.WriteFile(journal.path, []byte("{not json"), 0o600))
	r := projectedRigOver(t, control, journal)

	err := r.handler().Start(ctx)

	var unavailable *vpn.ErrLeaseStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	var broken *ErrRevocationJournal
	require.True(t, errors.As(err, &broken), "got %v", err)
	assert.Equal(t, "parse", broken.Op)
	assert.Empty(t, r.events, "no plane starts when a revoked lease cannot be told apart")
}

func TestProjectedLeaseStore_PutWritesThroughFirst(t *testing.T) {
	ctx := context.Background()
	control := &fakeLeaseControl{}
	store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), control)
	want := recordedLease()
	lease, err := projectedLease(0, &want)
	require.NoError(t, err)

	require.NoError(t, store.Put(ctx, lease))

	require.Len(t, control.puts, 1)
	assert.Equal(t, want, control.puts[0], "the record round-trips through the lease")
	got, err := store.Get(ctx, lease.ID)
	require.NoError(t, err)
	assert.Equal(t, lease, got)
}

func TestProjectedLeaseStore_ARefusedWriteLeavesTheProjectionAlone(t *testing.T) {
	ctx := context.Background()
	refused := errors.New("control plane returned 503")
	record := recordedLease()
	lease, err := projectedLease(0, &record)
	require.NoError(t, err)

	t.Run("put", func(t *testing.T) {
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{putErr: refused})
		err := store.Put(ctx, lease)
		var unavailable *vpn.ErrLeaseStoreUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.ErrorIs(t, err, refused)
		leases, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, leases, "an admission the control plane refused is not projected")
	})
	t.Run("delete", func(t *testing.T) {
		local := vpn.NewMemoryLeaseStore()
		require.NoError(t, local.Put(ctx, lease))
		store := newProjectedStore(t, local, &fakeLeaseControl{deleteErr: refused})
		err := store.Delete(ctx, lease.ID)
		var unavailable *vpn.ErrLeaseStoreUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		_, found, err := store.FindByDevice(ctx, lease.TenantID, lease.DeviceID)
		require.NoError(t, err)
		assert.False(t, found, "a torn-down lease leaves the projection even when its DELETE is refused")
		assert.Equal(t, map[vpn.LeaseID]string{lease.ID: lease.TenantID}, store.pending)
		assert.Equal(t, store.pending, journaled(t, store), "the refused revocation is journaled")
	})
	t.Run("delete that lands", func(t *testing.T) {
		local := vpn.NewMemoryLeaseStore()
		require.NoError(t, local.Put(ctx, lease))
		control := &fakeLeaseControl{}
		store := newProjectedStore(t, local, control)
		require.NoError(t, store.Delete(ctx, lease.ID))
		assert.Equal(t, []string{lease.TenantID + "/" + string(lease.ID)}, control.deletes)
		assert.Empty(t, store.pending)
		assert.Empty(t, journaled(t, store), "a landed DELETE leaves nothing journaled")
	})
	t.Run("delete with a journal that cannot be written", func(t *testing.T) {
		local := vpn.NewMemoryLeaseStore()
		require.NoError(t, local.Put(ctx, lease))
		control := &fakeLeaseControl{}
		store := newProjectedStore(t, local, control)
		store.journal = unwritableJournal(t)

		require.NoError(t, store.Delete(ctx, lease.ID), "a DELETE that lands makes the revocation durable")

		assert.Equal(t, []string{lease.TenantID + "/" + string(lease.ID)}, control.deletes)
		_, found, err := store.FindByDevice(ctx, lease.TenantID, lease.DeviceID)
		require.NoError(t, err)
		assert.False(t, found)
		assert.Empty(t, store.pending)
	})
	t.Run("delete refused by both the journal and the control plane", func(t *testing.T) {
		local := vpn.NewMemoryLeaseStore()
		require.NoError(t, local.Put(ctx, lease))
		store := newProjectedStore(t, local, &fakeLeaseControl{deleteErr: refused})
		store.journal = unwritableJournal(t)

		err := store.Delete(ctx, lease.ID)

		var unrecorded *vpn.ErrRevocationNotRecorded
		require.True(t, errors.As(err, &unrecorded), "got %v", err)
		var broken *ErrRevocationJournal
		assert.True(t, errors.As(err, &broken), "got %v", err)
		assert.ErrorIs(t, err, refused)
		_, found, err := store.FindByDevice(ctx, lease.TenantID, lease.DeviceID)
		require.NoError(t, err)
		assert.True(t, found, "a revocation recorded nowhere keeps the lease a restart would rebuild")
		assert.Empty(t, store.pending, "memory claims no revocation the journal lacks")
	})
	t.Run("delete of an unknown lease", func(t *testing.T) {
		control := &fakeLeaseControl{}
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), control)
		var nf *vpn.ErrLeaseNotFound
		assert.True(t, errors.As(store.Delete(ctx, "lease-9"), &nf))
		assert.Empty(t, control.deletes)
	})
}

func TestProjectedLeaseStore_AFailedAdmissionIsWithdrawn(t *testing.T) {
	ctx := context.Background()
	lost := errors.New("control plane answer timed out")
	record := recordedLease()
	lease, err := projectedLease(0, &record)
	require.NoError(t, err)

	t.Run("a PUT that commits but reports an error", func(t *testing.T) {
		control := &fakeLeaseControl{lostAnswer: lost}
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), control)

		err := store.Put(ctx, lease)

		var unavailable *vpn.ErrLeaseStoreUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.ErrorIs(t, err, lost)
		require.Len(t, control.puts, 1, "the control plane committed the PUT")
		assert.Equal(t, []string{lease.TenantID + "/" + string(lease.ID)}, control.deletes,
			"the committed record is deleted again")
		assert.Empty(t, store.pending)
		assert.Empty(t, journaled(t, store))
	})
	t.Run("a committed PUT whose withdrawal is refused does not outlive a restart", func(t *testing.T) {
		control := &fakeLeaseControl{lostAnswer: lost, deleteErr: errors.New("control plane returned 503")}
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), control)
		require.Error(t, store.Put(ctx, lease))
		assert.Equal(t, map[vpn.LeaseID]string{lease.ID: lease.TenantID}, store.pending,
			"the withdrawal stays pending for the sweep")

		restarted := &projectedLeaseStore{local: vpn.NewMemoryLeaseStore(), control: control, journal: store.journal}
		section := laptopSection()
		section.Leases = control.puts
		require.NoError(t, restarted.rebuild(ctx, section))

		leases, err := restarted.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, leases, "a failed admission the control plane recorded is not restored")
		assert.Equal(t, map[vpn.LeaseID]string{lease.ID: lease.TenantID}, restarted.pending,
			"the restarted gateway retries the withdrawal")
	})
	t.Run("a projection that refuses the lease after the control plane took it", func(t *testing.T) {
		refused := errors.New("projection refused the lease")
		control := &fakeLeaseControl{}
		store := newProjectedStore(t, &failingPutStore{LeaseStore: vpn.NewMemoryLeaseStore(), err: refused}, control)

		err := store.Put(ctx, lease)

		var unavailable *vpn.ErrLeaseStoreUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.ErrorIs(t, err, refused)
		require.Len(t, control.puts, 1)
		assert.Equal(t, []string{lease.TenantID + "/" + string(lease.ID)}, control.deletes,
			"the record the control plane took is deleted again")
		assert.Empty(t, journaled(t, store))
	})
	t.Run("an admission the journal refuses is never sent", func(t *testing.T) {
		control := &fakeLeaseControl{}
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), control)
		store.journal = unwritableJournal(t)

		err := store.Put(ctx, lease)

		var broken *ErrRevocationJournal
		require.True(t, errors.As(err, &broken), "got %v", err)
		assert.Empty(t, control.puts)
		assert.Empty(t, store.admitting)
	})
	t.Run("an admission that lands leaves nothing journaled", func(t *testing.T) {
		control := &fakeLeaseControl{}
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), control)

		require.NoError(t, store.Put(ctx, lease))

		require.Len(t, control.puts, 1)
		assert.Empty(t, control.deletes)
		assert.Empty(t, store.admitting)
		assert.Empty(t, journaled(t, store))
		_, err := store.Get(ctx, lease.ID)
		assert.NoError(t, err)
	})
}

func TestProjectedLeaseStore_RetryPendingDeletes(t *testing.T) {
	ctx := context.Background()
	record := recordedLease()
	lease, err := projectedLease(0, &record)
	require.NoError(t, err)
	refusedRevocation := func(t *testing.T) (*projectedLeaseStore, *fakeLeaseControl) {
		t.Helper()
		local := vpn.NewMemoryLeaseStore()
		require.NoError(t, local.Put(ctx, lease))
		control := &fakeLeaseControl{deleteErr: errors.New("control plane returned 503")}
		store := newProjectedStore(t, local, control)
		require.Error(t, store.Delete(ctx, lease.ID))
		return store, control
	}

	t.Run("a recovered control plane completes the revocation", func(t *testing.T) {
		store, control := refusedRevocation(t)
		control.deleteErr = nil
		require.NoError(t, store.RetryPendingDeletes(ctx))
		assert.Equal(t, []string{lease.TenantID + "/" + string(lease.ID)}, control.deletes)
		assert.Empty(t, store.pending)
		assert.Empty(t, journaled(t, store), "the completed revocation leaves the journal")

		require.NoError(t, store.RetryPendingDeletes(ctx))
		assert.Len(t, control.deletes, 1, "a completed DELETE is not sent again")
	})
	t.Run("a DELETE refused again stays pending", func(t *testing.T) {
		store, control := refusedRevocation(t)
		err := store.RetryPendingDeletes(ctx)
		var unavailable *vpn.ErrLeaseStoreUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.Equal(t, map[vpn.LeaseID]string{lease.ID: lease.TenantID}, store.pending)
		assert.Equal(t, store.pending, journaled(t, store))
		assert.Empty(t, control.deletes)
	})
	t.Run("a landed DELETE the journal cannot drop is reported", func(t *testing.T) {
		store, control := refusedRevocation(t)
		control.deleteErr = nil
		require.NoError(t, os.Remove(store.journal.path))
		require.NoError(t, os.Mkdir(store.journal.path, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(store.journal.path, "entry"), nil, 0o600))

		err := store.RetryPendingDeletes(ctx)

		var broken *ErrRevocationJournal
		require.True(t, errors.As(err, &broken), "got %v", err)
		assert.Len(t, control.deletes, 1, "the DELETE landed")
		assert.Empty(t, store.pending, "a landed DELETE is not sent again")
	})
}

func TestProjectedLeaseStore_Rebuild(t *testing.T) {
	ctx := context.Background()
	t.Run("no section", func(t *testing.T) {
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{})
		require.NoError(t, store.rebuild(ctx, nil))
	})
	t.Run("a lease awaiting its DELETE stays out", func(t *testing.T) {
		record := recordedLease()
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{})
		store.pending = map[vpn.LeaseID]string{vpn.LeaseID(record.ID): record.TenantID}
		require.NoError(t, store.rebuild(ctx, &gwstate.DesiredVPN{Leases: []gwstate.DesiredVPNLease{record}}))
		leases, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, leases, "a revoked lease the control plane still records is not reinstated")
	})
	t.Run("a lease a previous process journaled stays out and stays pending", func(t *testing.T) {
		record := recordedLease()
		previous := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{})
		require.NoError(t, previous.journal.save(map[vpn.LeaseID]string{vpn.LeaseID(record.ID): record.TenantID}))
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{})
		store.journal = previous.journal

		require.NoError(t, store.rebuild(ctx, &gwstate.DesiredVPN{Leases: []gwstate.DesiredVPNLease{record}}))

		leases, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, leases, "the journaled revocation is not reinstated")
		assert.Equal(t, map[vpn.LeaseID]string{vpn.LeaseID(record.ID): record.TenantID}, store.pending,
			"the next sweep retries its DELETE")
	})
	t.Run("an unreadable journal fails the rebuild", func(t *testing.T) {
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{})
		require.NoError(t, os.MkdirAll(store.journal.path, 0o700))

		err := store.rebuild(ctx, nil)

		var broken *ErrRevocationJournal
		require.True(t, errors.As(err, &broken), "got %v", err)
		assert.Equal(t, "read", broken.Op)
	})
	t.Run("bad address", func(t *testing.T) {
		store := newProjectedStore(t, vpn.NewMemoryLeaseStore(), &fakeLeaseControl{})
		bad := recordedLease()
		bad.Address = "100.64.0.300/32"
		err := store.rebuild(ctx, &gwstate.DesiredVPN{Leases: []gwstate.DesiredVPNLease{recordedLease(), bad}})
		var invalid *gwstate.ErrDesiredConfigInvalid
		require.True(t, errors.As(err, &invalid), "got %v", err)
		assert.Equal(t, "vpn.leases[1].address", invalid.Field)
	})
}

func TestGateway_SetVPNLeaseControl(t *testing.T) {
	r := newVPNRig(t)
	control, journal := r.gw.vpnLeaseControlSet()
	assert.Nil(t, control, "leases live in memory until a control plane is set")
	assert.Nil(t, journal)
	want := &fakeLeaseControl{}
	wantJournal := tempRevocationJournal(t)
	r.gw.SetVPNLeaseControl(want, wantJournal)
	control, journal = r.gw.vpnLeaseControlSet()
	assert.Same(t, want, control)
	assert.Same(t, wantJournal, journal)
}
