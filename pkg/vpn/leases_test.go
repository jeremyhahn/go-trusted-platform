package vpn

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	vpncore "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

func newTestLeaseStore(t testing.TB) (*LeaseStore, *quicbaas.MockStorage) {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	store, err := NewLeaseStore(storage, logging.DefaultLogger())
	require.NoError(t, err)
	store.now = func() time.Time { return testNow }
	return store, storage
}

// testLease is a complete lease gw-1 issued to device d of tenant, alive at
// testNow.
func testLease(tenant, id string) Lease {
	return Lease{
		LeaseID:                 id,
		GatewayID:               "gw-1",
		TenantID:                tenant,
		DeviceID:                "d-" + id,
		Address:                 netip.MustParsePrefix("100.64.0.7/32"),
		Zones:                   []string{"mgmt"},
		DataPlane:               vpncore.DataPlaneMASQUE,
		WireGuardPublicKey:      bytes.Repeat([]byte{1}, 32),
		ClientCertificateSHA256: bytes.Repeat([]byte{2}, 32),
		IssuedAt:                testNow.Add(-time.Hour),
		ExpiresAt:               testNow.Add(time.Hour),
		Verdict:                 vpncore.VerdictSummary{Passed: true, Cryptographic: true, ProfileID: 9},
	}
}

func TestNewLeaseStore_RequiresAStore(t *testing.T) {
	_, err := NewLeaseStore(nil, nil)
	var missing *ErrMissingDependency
	require.True(t, errors.As(err, &missing), "got %v", err)

	store, err := NewLeaseStore(quicbaas.NewMockStorage(), nil)
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestLeaseStore_RoundTripsPerTenant(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	in := testLease("t", "a1")

	put, err := store.Put(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, "tenant/t/vpn/lease/a1", put.key())

	got, err := store.Get(ctx, "t", "a1")
	require.NoError(t, err)
	in.ID = put.ID
	assert.Equal(t, in.Address, got.Address)
	assert.Equal(t, in.WireGuardPublicKey, got.WireGuardPublicKey)
	assert.Equal(t, in.ClientCertificateSHA256, got.ClientCertificateSHA256)
	assert.Equal(t, in.Verdict, got.Verdict)
	assert.True(t, in.ExpiresAt.Equal(got.ExpiresAt))

	listed, err := store.List(ctx, "t")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "a1", listed[0].LeaseID)

	require.NoError(t, store.Delete(ctx, "gw-1", "t", "a1"))
	_, err = store.Get(ctx, "t", "a1")
	var notFound *vpncore.ErrLeaseNotFound
	require.True(t, errors.As(err, &notFound), "got %v", err)
	err = store.Delete(ctx, "gw-1", "t", "a1")
	require.True(t, errors.As(err, &notFound), "a second delete is not found, got %v", err)
}

func TestLeaseStore_PutKeepsACopy(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	in := testLease("t", "a1")
	_, err := store.Put(ctx, in)
	require.NoError(t, err)
	in.Zones[0] = "changed"
	in.WireGuardPublicKey[0] = 9

	got, err := store.Get(ctx, "t", "a1")
	require.NoError(t, err)
	assert.Equal(t, []string{"mgmt"}, got.Zones)
	assert.Equal(t, byte(1), got.WireGuardPublicKey[0])
}

func TestLeaseStore_IsolatesTenants(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	for _, l := range []Lease{testLease("a", "x"), testLease("b", "x"), testLease("b", "y")} {
		_, err := store.Put(ctx, l)
		require.NoError(t, err)
	}

	tenantA, err := store.List(ctx, "a")
	require.NoError(t, err)
	require.Len(t, tenantA, 1)
	assert.Equal(t, "a", tenantA[0].TenantID)
	tenantB, err := store.List(ctx, "b")
	require.NoError(t, err)
	assert.Len(t, tenantB, 2)
	all, err := store.List(ctx, "")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	require.NoError(t, store.Delete(ctx, "gw-1", "a", "x"))
	_, err = store.Get(ctx, "b", "x")
	require.NoError(t, err, "deleting tenant a's lease leaves tenant b's lease of the same id")
}

func TestLeaseStore_ListOrdersByIssueTime(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	late, early, tie := testLease("t", "late"), testLease("t", "early"), testLease("t", "a-tie")
	early.IssuedAt = late.IssuedAt.Add(-time.Minute)
	tie.IssuedAt = late.IssuedAt
	for _, l := range []Lease{late, early, tie} {
		_, err := store.Put(ctx, l)
		require.NoError(t, err)
	}

	listed, err := store.List(ctx, "t")
	require.NoError(t, err)
	ids := make([]string, 0, len(listed))
	for _, l := range listed {
		ids = append(ids, l.LeaseID)
	}
	assert.Equal(t, []string{"early", "a-tie", "late"}, ids)
}

func TestLeaseStore_ListByGatewayReturnsOnlyThatGateway(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	other := testLease("t", "o1")
	other.GatewayID = "gw-2"
	for _, l := range []Lease{testLease("t", "m1"), testLease("u", "m2"), other} {
		_, err := store.Put(ctx, l)
		require.NoError(t, err)
	}

	mine, err := store.ListByGateway(ctx, "gw-1")
	require.NoError(t, err)
	assert.Len(t, mine, 2)
	theirs, err := store.ListByGateway(ctx, "gw-2")
	require.NoError(t, err)
	require.Len(t, theirs, 1)
	assert.Equal(t, "o1", theirs[0].LeaseID)

	_, err = store.ListByGateway(ctx, "")
	var invalid *ErrInvalidArgument
	require.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestLeaseStore_RefusesAnotherGatewaysLease(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	_, err := store.Put(ctx, testLease("t", "a1"))
	require.NoError(t, err)

	hijack := testLease("t", "a1")
	hijack.GatewayID = "gw-2"
	_, err = store.Put(ctx, hijack)
	var owned *ErrLeaseOwnedByOtherGateway
	require.True(t, errors.As(err, &owned), "got %v", err)
	require.True(t, errors.As(store.Delete(ctx, "gw-2", "t", "a1"), &owned))

	got, err := store.Get(ctx, "t", "a1")
	require.NoError(t, err)
	assert.Equal(t, "gw-1", got.GatewayID, "the issuing gateway still owns the lease")
}

func TestLeaseStore_RefusesAKeyCollision(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	squatter := &Lease{ID: recordID(entityTypeLease, "t", "a1"), TenantID: "other", LeaseID: "lease"}
	require.NoError(t, store.leases.Save(ctx, squatter))

	var collision *ErrKeyCollision
	_, err := store.Put(ctx, testLease("t", "a1"))
	require.True(t, errors.As(err, &collision), "got %v", err)
	_, err = store.Get(ctx, "t", "a1")
	require.True(t, errors.As(err, &collision), "got %v", err)
	require.True(t, errors.As(store.Delete(ctx, "gw-1", "t", "a1"), &collision))
}

func TestLeaseStore_RefusesAnIncompleteLease(t *testing.T) {
	cases := map[string]func(*Lease){
		"gateway_id":                func(l *Lease) { l.GatewayID = "" },
		"tenant_id":                 func(l *Lease) { l.TenantID = "" },
		"device_id":                 func(l *Lease) { l.DeviceID = "" },
		"lease_id":                  func(l *Lease) { l.LeaseID = "bad\n" },
		"address":                   func(l *Lease) { l.Address = netip.Prefix{} },
		"data_plane":                func(l *Lease) { l.DataPlane = "ipsec" },
		"expires_at":                func(l *Lease) { l.ExpiresAt = l.IssuedAt },
		"wireguard_public_key":      func(l *Lease) { l.WireGuardPublicKey = []byte{1} },
		"client_certificate_sha256": func(l *Lease) { l.ClientCertificateSHA256 = []byte{2} },
		"zones[1]":                  func(l *Lease) { l.Zones = []string{"mgmt", "mgmt"} },
	}
	store, _ := newTestLeaseStore(t)
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			l := testLease("t", "a1")
			mutate(&l)
			_, err := store.Put(context.Background(), l)
			var invalid *ErrInvalidArgument
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, field, invalid.Field)
		})
	}
	all, err := store.List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, all, "a refused lease is never stored")

	_, err = store.Get(context.Background(), "", "a1")
	var invalid *ErrInvalidArgument
	require.True(t, errors.As(err, &invalid), "got %v", err)
	require.True(t, errors.As(store.Delete(context.Background(), "", "t", "a1"), &invalid))
}

func TestLeaseStore_AcceptsALeaseWithoutClientKeys(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	l := testLease("t", "a1")
	l.WireGuardPublicKey, l.ClientCertificateSHA256, l.Zones = nil, nil, nil
	_, err := store.Put(context.Background(), l)
	require.NoError(t, err)
}

func TestLeaseStore_ReportsAnUnavailableStore(t *testing.T) {
	cause := errors.New("raft unavailable")
	cases := map[string]struct {
		inject func(*quicbaas.MockStorage)
		call   func(*LeaseStore) error
	}{
		"put": {
			inject: func(m *quicbaas.MockStorage) { m.PutError = cause },
			call: func(s *LeaseStore) error {
				_, err := s.Put(context.Background(), testLease("t", "new"))
				return err
			},
		},
		"get": {
			inject: func(m *quicbaas.MockStorage) { m.GetError = cause },
			call: func(s *LeaseStore) error {
				_, err := s.Get(context.Background(), "t", "a1")
				return err
			},
		},
		"delete": {
			inject: func(m *quicbaas.MockStorage) { m.DeleteError = cause },
			call:   func(s *LeaseStore) error { return s.Delete(context.Background(), "gw-1", "t", "a1") },
		},
		"list": {
			inject: func(m *quicbaas.MockStorage) { m.ListError = cause },
			call: func(s *LeaseStore) error {
				_, err := s.List(context.Background(), "t")
				return err
			},
		},
		"list by gateway": {
			inject: func(m *quicbaas.MockStorage) { m.ListError = cause },
			call: func(s *LeaseStore) error {
				_, err := s.ListByGateway(context.Background(), "gw-1")
				return err
			},
		},
		"sweep list": {
			inject: func(m *quicbaas.MockStorage) { m.ListError = cause },
			call: func(s *LeaseStore) error {
				_, err := s.Sweep(context.Background())
				return err
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store, storage := newTestLeaseStore(t)
			_, err := store.Put(context.Background(), testLease("t", "a1"))
			require.NoError(t, err)
			tc.inject(storage)

			err = tc.call(store)
			var unavailable *vpncore.ErrLeaseStoreUnavailable
			require.True(t, errors.As(err, &unavailable), "got %v", err)
			assert.ErrorIs(t, err, cause)
		})
	}
}

func TestLeaseStore_SweepRemovesOnlyExpiredLeases(t *testing.T) {
	store, _ := newTestLeaseStore(t)
	ctx := context.Background()
	live, atExpiry, past := testLease("t", "live"), testLease("t", "at-expiry"), testLease("u", "past")
	atExpiry.ExpiresAt = testNow
	past.ExpiresAt = testNow.Add(-time.Minute)
	for _, l := range []Lease{live, atExpiry, past} {
		_, err := store.Put(ctx, l)
		require.NoError(t, err)
	}

	removed, err := store.Sweep(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, removed, "a lease is expired at its ExpiresAt, as the gateway sweep holds")
	left, err := store.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, left, 1)
	assert.Equal(t, "live", left[0].LeaseID)

	removed, err = store.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed)
}

func TestLeaseStore_SweepReportsAFailedDelete(t *testing.T) {
	store, storage := newTestLeaseStore(t)
	ctx := context.Background()
	expired := testLease("t", "gone")
	expired.ExpiresAt = testNow
	_, err := store.Put(ctx, expired)
	require.NoError(t, err)
	storage.DeleteError = errors.New("raft unavailable")

	removed, err := store.Sweep(ctx)
	var unavailable *vpncore.ErrLeaseStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Zero(t, removed)
}

// listHookStorage runs afterList once, when the first listing has returned:
// whatever it writes lands between Sweep's list and its delete.
type listHookStorage struct {
	*quicbaas.MockStorage
	afterList func()
}

func (s *listHookStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	entities, next, err := s.MockStorage.List(ctx, entityType, pageSize, pageToken, shardID)
	if hook := s.afterList; hook != nil {
		s.afterList = nil
		hook()
	}
	return entities, next, err
}

func TestLeaseStore_SweepKeepsARenewalSavedAfterItsList(t *testing.T) {
	storage := &listHookStorage{MockStorage: quicbaas.NewMockStorage()}
	require.NoError(t, storage.Start(context.Background()))
	store, err := NewLeaseStore(storage, logging.DefaultLogger())
	require.NoError(t, err)
	store.now = func() time.Time { return testNow }
	ctx := context.Background()
	lease := testLease("t", "renewed")
	lease.ExpiresAt = testNow
	_, err = store.Put(ctx, lease)
	require.NoError(t, err)

	renewal := lease
	renewal.ExpiresAt = testNow.Add(time.Hour)
	renewal.Renewals = 1
	storage.afterList = func() {
		_, err := store.Put(ctx, renewal)
		require.NoError(t, err)
	}

	removed, err := store.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed, "the renewal saved after the list is no longer expired")
	got, err := store.Get(ctx, "t", "renewed")
	require.NoError(t, err, "the renewed record survives the sweep")
	assert.Equal(t, 1, got.Renewals)
	assert.True(t, got.ExpiresAt.Equal(renewal.ExpiresAt))
}

func TestLeaseStore_SweepReportsAFailedReRead(t *testing.T) {
	store, storage := newTestLeaseStore(t)
	ctx := context.Background()
	expired := testLease("t", "gone")
	expired.ExpiresAt = testNow
	_, err := store.Put(ctx, expired)
	require.NoError(t, err)
	storage.GetError = errors.New("raft unavailable")

	removed, err := store.Sweep(ctx)
	var unavailable *vpncore.ErrLeaseStoreUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Zero(t, removed)
	storage.GetError = nil
	_, err = store.Get(ctx, "t", "gone")
	require.NoError(t, err, "a lease the sweep could not re-read is left for the next sweep")
}

func TestErrLeaseOwnedByOtherGateway_NamesTheLease(t *testing.T) {
	err := &ErrLeaseOwnedByOtherGateway{TenantID: "t", LeaseID: "a1", GatewayID: "gw-2"}
	assert.Equal(t, "vpn: lease a1 of tenant t was not issued by gateway gw-2", err.Error())
}
