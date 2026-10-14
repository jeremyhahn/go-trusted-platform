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

package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	vpncore "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

const testPolicy = `package vpn.posture

import rego.v1

default allow := false

allow if input.posture.agent_version == "9.9.9"
`

var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func newTestService(t testing.TB) (*Service, *quicbaas.MockStorage) {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	svc, err := NewService(storage, logging.DefaultLogger())
	require.NoError(t, err)
	svc.now = func() time.Time { return testNow }
	return svc, storage
}

// fakeSnapshots is a gateway telemetry store with injectable failures.
type fakeSnapshots struct {
	snaps map[string]*gwstate.Snapshot
	err   error
}

func (f *fakeSnapshots) Put(snap *gwstate.Snapshot) error {
	f.snaps[snap.GatewayID] = snap
	return nil
}

func (f *fakeSnapshots) Get(id string) (*gwstate.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	snap, ok := f.snaps[id]
	if !ok {
		return nil, gwstate.ErrSnapshotNotFound{GatewayID: id}
	}
	return snap, nil
}

func (f *fakeSnapshots) List() ([]*gwstate.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*gwstate.Snapshot, 0, len(f.snaps))
	for _, s := range f.snaps {
		out = append(out, s)
	}
	return out, nil
}

func (f *fakeSnapshots) Delete(id string) error {
	delete(f.snaps, id)
	return nil
}

func TestNewService_RequiresAStore(t *testing.T) {
	_, err := NewService(nil, nil)
	var missing *ErrMissingDependency
	require.True(t, errors.As(err, &missing), "got %v", err)
}

func TestNewService_DefaultsTheLogger(t *testing.T) {
	svc, err := NewService(quicbaas.NewMockStorage(), nil)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestEnrolPeer_StoresAndUpdatesZonesKeepingTheEnrolmentTime(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	first, err := svc.EnrolPeer(ctx, Peer{TenantID: "acme", DeviceID: "laptop-1", Zones: []string{"management"}})
	require.NoError(t, err)
	assert.Equal(t, testNow, first.EnrolledAt)

	svc.now = func() time.Time { return testNow.Add(time.Hour) }
	second, err := svc.EnrolPeer(ctx, Peer{TenantID: "acme", DeviceID: "laptop-1", Zones: []string{"management", "ops"}})
	require.NoError(t, err)
	assert.Equal(t, first.ID, second.ID, "re-enrolment replaces the record")
	assert.Equal(t, testNow, second.EnrolledAt, "re-enrolment keeps the first enrolment time")

	peers, err := svc.ListPeers(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, peers, 1)
	assert.Equal(t, []string{"management", "ops"}, peers[0].Zones)
}

func TestEnrolPeer_RefusesMalformedRequests(t *testing.T) {
	svc, _ := newTestService(t)
	cases := map[string]Peer{
		"no tenant":       {DeviceID: "d"},
		"no device":       {TenantID: "t"},
		"control char":    {TenantID: "t\x00", DeviceID: "d"},
		"long device":     {TenantID: "t", DeviceID: strings.Repeat("d", maxIDLength+1)},
		"empty zone":      {TenantID: "t", DeviceID: "d", Zones: []string{""}},
		"duplicate zones": {TenantID: "t", DeviceID: "d", Zones: []string{"a", "a"}},
	}
	for name, peer := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.EnrolPeer(context.Background(), peer)
			var invalid *ErrInvalidArgument
			require.True(t, errors.As(err, &invalid), "got %v", err)
		})
	}
}

func TestEnrolPeer_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	storage.PutError = errors.New("raft unavailable")
	_, err := svc.EnrolPeer(context.Background(), Peer{TenantID: "t", DeviceID: "d"})
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)

	storage.PutError = nil
	storage.GetError = errors.New("raft unavailable")
	_, err = svc.EnrolPeer(context.Background(), Peer{TenantID: "t", DeviceID: "d"})
	require.True(t, errors.As(err, &unavailable), "a failed read refuses the write, got %v", err)
}

// TestEnrolPeer_RefusesAKeyCollision: a record under the derived ID that
// belongs to another key is never overwritten.
func TestEnrolPeer_RefusesAKeyCollision(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	squatter := &Peer{ID: recordID(entityTypePeer, "t", "d"), TenantID: "other", DeviceID: "device"}
	require.NoError(t, svc.peers.Save(ctx, squatter))

	_, err := svc.EnrolPeer(ctx, Peer{TenantID: "t", DeviceID: "d"})
	var collision *ErrKeyCollision
	require.True(t, errors.As(err, &collision), "got %v", err)
	err = svc.RevokePeer(ctx, "t", "d")
	require.True(t, errors.As(err, &collision), "got %v", err)
}

func TestListPeers_FiltersByTenantAndSorts(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	for _, p := range []Peer{{TenantID: "b", DeviceID: "2"}, {TenantID: "a", DeviceID: "9"}, {TenantID: "b", DeviceID: "1"}} {
		_, err := svc.EnrolPeer(ctx, p)
		require.NoError(t, err)
	}

	all, err := svc.ListPeers(ctx, "")
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.Equal(t, []string{"a/9", "b/1", "b/2"}, []string{all[0].key(), all[1].key(), all[2].key()})

	tenantB, err := svc.ListPeers(ctx, "b")
	require.NoError(t, err)
	assert.Len(t, tenantB, 2)
}

func TestListPeers_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	storage.ListError = errors.New("raft unavailable")
	_, err := svc.ListPeers(context.Background(), "")
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
}

func TestRevokePeer_RemovesTheEnrolment(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, err := svc.EnrolPeer(ctx, Peer{TenantID: "t", DeviceID: "d"})
	require.NoError(t, err)

	require.NoError(t, svc.RevokePeer(ctx, "t", "d"))
	peers, err := svc.ListPeers(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, peers)
}

func TestRevokePeer_RefusesUnknownAndMalformed(t *testing.T) {
	svc, storage := newTestService(t)
	ctx := context.Background()

	var notFound *ErrPeerNotFound
	require.True(t, errors.As(svc.RevokePeer(ctx, "t", "d"), &notFound))
	var invalid *ErrInvalidArgument
	require.True(t, errors.As(svc.RevokePeer(ctx, "", "d"), &invalid))
	require.True(t, errors.As(svc.RevokePeer(ctx, "t", ""), &invalid))

	_, err := svc.EnrolPeer(ctx, Peer{TenantID: "t", DeviceID: "d"})
	require.NoError(t, err)
	storage.DeleteError = errors.New("raft unavailable")
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(svc.RevokePeer(ctx, "t", "d"), &unavailable))
}

func TestSetPosturePolicy_CompilesBeforeStoring(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	stored, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "acme", Name: "vpn_posture", Module: testPolicy})
	require.NoError(t, err)
	assert.Equal(t, testNow, stored.UpdatedAt)

	got, err := svc.GetPosturePolicy(ctx, "acme", "vpn_posture")
	require.NoError(t, err)
	assert.Equal(t, testPolicy, got.Module)
}

func TestSetPosturePolicy_RefusesInvalidPolicies(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "acme", Name: "vpn_posture", Module: "package other\n\nimport rego.v1\n\ndefault allow := true\n"})
	var invalidPolicy *ErrInvalidPosturePolicy
	require.True(t, errors.As(err, &invalidPolicy), "got %v", err)
	assert.Equal(t, "acme", invalidPolicy.TenantID)

	cases := map[string]PosturePolicy{
		"no tenant":   {Name: "p", Module: testPolicy},
		"no name":     {TenantID: "t", Module: testPolicy},
		"name path":   {TenantID: "t", Name: "../p", Module: testPolicy},
		"long name":   {TenantID: "t", Name: strings.Repeat("p", maxPolicyNameLength+1), Module: testPolicy},
		"huge module": {TenantID: "t", Name: "p", Module: strings.Repeat("#", maxModuleBytes+1)},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.SetPosturePolicy(ctx, policy)
			var invalid *ErrInvalidArgument
			require.True(t, errors.As(err, &invalid), "got %v", err)
		})
	}

	policies, err := svc.ListPosturePolicies(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, policies, "a refused policy is never stored")
}

func TestSetPosturePolicy_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	storage.PutError = errors.New("raft unavailable")
	_, err := svc.SetPosturePolicy(context.Background(), PosturePolicy{TenantID: "t", Name: "p", Module: testPolicy})
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
}

func TestGetPosturePolicy_RefusesUnknownAndMalformed(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, err := svc.GetPosturePolicy(ctx, "t", "p")
	var notFound *ErrPosturePolicyNotFound
	require.True(t, errors.As(err, &notFound), "got %v", err)
	_, err = svc.GetPosturePolicy(ctx, "", "p")
	var invalid *ErrInvalidArgument
	require.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestDeletePosturePolicy_RemovesThePolicy(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "t", Name: "p", Module: testPolicy})
	require.NoError(t, err)

	require.NoError(t, svc.DeletePosturePolicy(ctx, "t", "p"))
	var notFound *ErrPosturePolicyNotFound
	require.True(t, errors.As(svc.DeletePosturePolicy(ctx, "t", "p"), &notFound))
}

func TestDeletePosturePolicy_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	ctx := context.Background()
	_, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "t", Name: "p", Module: testPolicy})
	require.NoError(t, err)
	storage.DeleteError = errors.New("raft unavailable")
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(svc.DeletePosturePolicy(ctx, "t", "p"), &unavailable))
}

func TestListPosturePolicies_FiltersByTenant(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	for _, p := range []PosturePolicy{{TenantID: "b", Name: "p"}, {TenantID: "a", Name: "p"}} {
		p.Module = testPolicy
		_, err := svc.SetPosturePolicy(ctx, p)
		require.NoError(t, err)
	}
	all, err := svc.ListPosturePolicies(ctx, "")
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, "a", all[0].TenantID)
	tenantB, err := svc.ListPosturePolicies(ctx, "b")
	require.NoError(t, err)
	assert.Len(t, tenantB, 1)
}

func TestListPosturePolicies_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	storage.ListError = errors.New("raft unavailable")
	_, err := svc.ListPosturePolicies(context.Background(), "")
	var unavailable *ErrStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
}

func TestStatus_ReadsTheReportedVPNSections(t *testing.T) {
	svc, _ := newTestService(t)
	store := &fakeSnapshots{snaps: map[string]*gwstate.Snapshot{
		"gw-02": {GatewayID: "gw-02"},
		"gw-01": {GatewayID: "gw-01", ReportedAt: testNow, VPN: &gwstate.VPNState{Running: true, Admissions: 3}},
	}}
	svc.SetGatewaySnapshotStore(store)

	all, err := svc.Status(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, "gw-01", all[0].GatewayID)
	assert.Equal(t, uint64(3), all[0].VPN.Admissions)
	assert.Nil(t, all[1].VPN, "a gateway without the VPN service reports no section")

	one, err := svc.Status(context.Background(), "gw-01")
	require.NoError(t, err)
	require.Len(t, one, 1)
	assert.True(t, one[0].VPN.Running)
}

func TestStatus_FailsClosed(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Status(ctx, "")
	var unavailable *ErrStatusUnavailable
	require.True(t, errors.As(err, &unavailable), "no store wired, got %v", err)

	store := &fakeSnapshots{snaps: map[string]*gwstate.Snapshot{}}
	svc.SetGatewaySnapshotStore(store)
	_, err = svc.Status(ctx, "gw-09")
	var notFound *ErrGatewayNotFound
	require.True(t, errors.As(err, &notFound), "got %v", err)

	store.err = errors.New("disk")
	var storeErr *ErrStoreUnavailable
	_, err = svc.Status(ctx, "gw-09")
	require.True(t, errors.As(err, &storeErr), "got %v", err)
	_, err = svc.Status(ctx, "")
	require.True(t, errors.As(err, &storeErr), "got %v", err)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = svc.Status(cancelled, "")
	require.ErrorIs(t, err, context.Canceled)

	svc.SetGatewaySnapshotStore(nil)
	_, err = svc.Status(ctx, "")
	require.True(t, errors.As(err, &unavailable), "unwiring the store fails closed, got %v", err)
}

func TestDesiredVPN_CarriesEveryPeerAndPolicy(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	empty, err := svc.DesiredVPN(ctx, "gw-1")
	require.NoError(t, err)
	require.NotNil(t, empty, "an empty set is still delivered, so the last revocation reaches the gateways")
	assert.Empty(t, empty.Peers)

	_, err = svc.EnrolPeer(ctx, Peer{TenantID: "t", DeviceID: "d", Zones: []string{"management"}})
	require.NoError(t, err)
	_, err = svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: "t", Name: "vpn_posture", Module: testPolicy})
	require.NoError(t, err)

	section, err := svc.DesiredVPN(ctx, "gw-1")
	require.NoError(t, err)
	assert.Equal(t, []gwstate.DesiredVPNPeer{{TenantID: "t", DeviceID: "d", Zones: []string{"management"}}}, section.Peers)
	assert.Equal(t, []gwstate.DesiredVPNPosturePolicy{{TenantID: "t", Name: "vpn_posture", Module: testPolicy}}, section.PosturePolicies)
	require.NoError(t, (&gwstate.DesiredConfig{VPN: section}).Validate(), "the section is a valid desired-config section")
}

func TestDesiredVPN_ReportsStoreFailures(t *testing.T) {
	svc, storage := newTestService(t)
	storage.ListError = errors.New("raft unavailable")
	_, err := svc.DesiredVPN(context.Background(), "gw-1")
	var unavailable *vpncore.ErrLeaseStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "the lease sweep fails first, got %v", err)
}

func TestDesiredVPN_CarriesTheGatewaysLiveLeases(t *testing.T) {
	svc, _ := newTestService(t)
	svc.leases.now = func() time.Time { return testNow }
	ctx := context.Background()
	own := testLease("t", "lease-1")
	other := testLease("t", "lease-2")
	other.GatewayID = "gw-2"
	expired := testLease("t", "lease-3")
	expired.ExpiresAt = testNow
	for _, l := range []Lease{own, other, expired} {
		_, err := svc.leases.Put(ctx, l)
		require.NoError(t, err)
	}

	section, err := svc.DesiredVPN(ctx, "gw-1")

	require.NoError(t, err)
	require.Len(t, section.Leases, 1, "only gw-1's live lease is served to gw-1")
	assert.Equal(t, desiredLease(&own), section.Leases[0])
	_, err = svc.leases.Get(ctx, "t", "lease-3")
	var nf *vpncore.ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "the expired lease is swept, got %v", err)
	require.NoError(t, (&gwstate.DesiredConfig{VPN: section}).Validate(), "the leases are a valid desired-config section")
}

func TestDesiredVPN_RefusesAnInvalidGatewayID(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.DesiredVPN(context.Background(), "")
	var invalid *ErrInvalidArgument
	require.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestRecordGatewayLease_RoundTripsThroughDesiredVPN(t *testing.T) {
	svc, _ := newTestService(t)
	svc.leases.now = func() time.Time { return testNow }
	ctx := context.Background()
	want := testLease("t", "lease-1")
	record := desiredLease(&want)

	require.NoError(t, svc.RecordGatewayLease(ctx, "gw-1", &record))

	section, err := svc.DesiredVPN(ctx, "gw-1")
	require.NoError(t, err)
	assert.Equal(t, []gwstate.DesiredVPNLease{record}, section.Leases)
}

func TestRecordGatewayLease_Refusals(t *testing.T) {
	ctx := context.Background()
	lease := testLease("t", "lease-1")
	t.Run("no lease", func(t *testing.T) {
		svc, _ := newTestService(t)
		var invalid *ErrInvalidArgument
		require.True(t, errors.As(svc.RecordGatewayLease(ctx, "gw-1", nil), &invalid))
		assert.Equal(t, "lease", invalid.Field)
	})
	t.Run("bad address", func(t *testing.T) {
		svc, _ := newTestService(t)
		record := desiredLease(&lease)
		record.Address = "not-an-address"
		var invalid *ErrInvalidArgument
		require.True(t, errors.As(svc.RecordGatewayLease(ctx, "gw-1", &record), &invalid))
		assert.Equal(t, "address", invalid.Field)
	})
	t.Run("another gateway's lease", func(t *testing.T) {
		svc, _ := newTestService(t)
		record := desiredLease(&lease)
		require.NoError(t, svc.RecordGatewayLease(ctx, "gw-1", &record))
		var owned *ErrLeaseOwnedByOtherGateway
		require.True(t, errors.As(svc.RecordGatewayLease(ctx, "gw-2", &record), &owned))
	})
}

func TestReleaseGatewayLease(t *testing.T) {
	ctx := context.Background()
	lease := testLease("t", "lease-1")
	record := desiredLease(&lease)
	t.Run("releases the lease and tolerates a retry", func(t *testing.T) {
		svc, _ := newTestService(t)
		require.NoError(t, svc.RecordGatewayLease(ctx, "gw-1", &record))
		require.NoError(t, svc.ReleaseGatewayLease(ctx, "gw-1", "t", "lease-1"))
		require.NoError(t, svc.ReleaseGatewayLease(ctx, "gw-1", "t", "lease-1"), "a retried release succeeds")
		_, err := svc.leases.Get(ctx, "t", "lease-1")
		var nf *vpncore.ErrLeaseNotFound
		assert.True(t, errors.As(err, &nf), "got %v", err)
	})
	t.Run("another gateway's lease", func(t *testing.T) {
		svc, _ := newTestService(t)
		require.NoError(t, svc.RecordGatewayLease(ctx, "gw-1", &record))
		var owned *ErrLeaseOwnedByOtherGateway
		require.True(t, errors.As(svc.ReleaseGatewayLease(ctx, "gw-2", "t", "lease-1"), &owned))
	})
}

func TestRecordID_SeparatesKeysAndIsNeverZero(t *testing.T) {
	assert.NotEqual(t, recordID(entityTypePeer, "ab", "c"), recordID(entityTypePeer, "a", "bc"))
	assert.NotEqual(t, recordID(entityTypePeer, "t", "d"), recordID(entityTypePosturePolicy, "t", "d"))
	assert.Equal(t, recordID(entityTypePeer, "t", "d"), recordID(entityTypePeer, "t", "d"))
	assert.NotZero(t, recordID(""))
}

func TestErrors_NameTheirSubject(t *testing.T) {
	cause := errors.New("cause")
	cases := map[string]error{
		"tenant-a":   &ErrPeerNotFound{TenantID: "tenant-a", DeviceID: "d"},
		"policy-p":   &ErrPosturePolicyNotFound{TenantID: "t", Name: "policy-p"},
		"bad rego":   &ErrInvalidPosturePolicy{TenantID: "t", Name: "p", Reason: "bad rego"},
		"gw-7":       &ErrGatewayNotFound{GatewayID: "gw-7"},
		"no store":   &ErrStatusUnavailable{Reason: "no store"},
		"a/b":        &ErrKeyCollision{Kind: "peer", Key: "a/b", Stored: "c/d"},
		"a store":    &ErrMissingDependency{Name: "a store"},
		"zones[0]":   &ErrInvalidArgument{Field: "zones[0]", Reason: "required"},
		"save peer":  &ErrStoreUnavailable{Op: "save peer", Cause: cause},
		"the policy": &ErrPolicyEngineUnavailable{Cause: errors.New("the policy engine failed")},
	}
	for want, err := range cases {
		assert.Contains(t, err.Error(), want)
	}
	assert.ErrorIs(t, &ErrStoreUnavailable{Op: "x", Cause: cause}, cause)
	assert.ErrorIs(t, &ErrPolicyEngineUnavailable{Cause: cause}, cause)
}
