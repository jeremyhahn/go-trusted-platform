// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package tenant

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// fakeQRDBTenants is a QRDB tenant client that implements only the four
// per-tenant barrier verbs the manager uses. Every other method of the
// embedded interface panics (nil embedded value), so a call the adapter
// should not make fails the test loudly. It also answers GetTenant with each
// tenant's isolation type (barrier unless set otherwise).
type fakeQRDBTenants struct {
	quicbaassdk.QRDBTenantClient

	mu          sync.Mutex
	inits       []*quicbaassdk.QRDBTenantBarrierInitRequest
	unseals     []*quicbaassdk.QRDBTenantBarrierUnsealRequest
	seals       []string
	statuses    []string
	sealed      map[string]bool
	initialized map[string]bool
	passphrase  map[string][]byte
	initErr     error

	// prefix tenants answer "prefix" from GetTenant; untyped tenants answer
	// an empty isolation type; every other tenant answers "barrier".
	prefix  map[string]bool
	untyped map[string]bool
	getErr  error
	gets    []string
}

func newFakeQRDBTenants() *fakeQRDBTenants {
	return &fakeQRDBTenants{
		sealed:      map[string]bool{},
		initialized: map[string]bool{},
		passphrase:  map[string][]byte{},
		prefix:      map[string]bool{},
		untyped:     map[string]bool{},
	}
}

func (f *fakeQRDBTenants) TenantBarrierInit(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) (*quicbaassdk.QRDBTenantBarrierInitResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inits = append(f.inits, req)
	// Mirrors go-qrdb v0.19.0-alpha: an init with no passphrase is refused
	// with ErrEmptyPassphrase.
	if len(req.Passphrase) == 0 {
		return nil, errors.New("qrdb: tenant barrier passphrase is empty")
	}
	if f.initErr != nil {
		return nil, f.initErr
	}
	f.initialized[req.TenantID] = true
	f.sealed[req.TenantID] = true
	f.passphrase[req.TenantID] = append([]byte(nil), req.Passphrase...)
	return &quicbaassdk.QRDBTenantBarrierInitResponse{}, nil
}

func (f *fakeQRDBTenants) TenantBarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unseals = append(f.unseals, req)
	// Mirrors go-qrdb v0.19.0-alpha: an unseal of a tenant that was never
	// initialized, or with a key that is not the init passphrase, is refused
	// with a BarrierError (op unseal) and the tenant stays sealed.
	if !f.initialized[req.TenantID] || !bytes.Equal(req.Key, f.passphrase[req.TenantID]) {
		return errors.New("qrdb: tenant barrier unseal: key does not open the barrier")
	}
	f.sealed[req.TenantID] = false
	return nil
}

func (f *fakeQRDBTenants) TenantBarrierSeal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierSealRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seals = append(f.seals, req.TenantID)
	f.sealed[req.TenantID] = true
	return nil
}

func (f *fakeQRDBTenants) TenantBarrierStatus(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierStatusRequest) (*quicbaassdk.QRDBTenantBarrierStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, req.TenantID)
	return &quicbaassdk.QRDBTenantBarrierStatusResponse{
		TenantID:       req.TenantID,
		Sealed:         f.sealed[req.TenantID],
		Initialized:    f.initialized[req.TenantID],
		Strategy:       "software",
		HardwareBacked: true,
	}, nil
}

func (f *fakeQRDBTenants) GetTenant(ctx context.Context, tenantID string) (*quicbaassdk.QRDBGetTenantResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, tenantID)
	if f.getErr != nil {
		return nil, f.getErr
	}
	info := quicbaassdk.QRDBTenantInfo{ID: tenantID}
	switch {
	case f.untyped[tenantID]:
	case f.prefix[tenantID]:
		info.IsolationType = "prefix"
	default:
		info.IsolationType = "barrier"
	}
	return &quicbaassdk.QRDBGetTenantResponse{Tenant: info}, nil
}

func TestNewTenantBarrierClient_NilIsNil(t *testing.T) {
	bc := NewTenantBarrierClient(nil)
	if bc != nil {
		t.Fatalf("NewTenantBarrierClient(nil) = %#v, want a nil interface", bc)
	}

	m, err := NewManager(&ManagerConfig{
		IAMTenantClient:     newMockIAMClient(),
		IAMRoleClient:       newMockIAMClient(),
		TenantBarrierClient: bc,
		Config:              func() *Config { c := DefaultConfig(); c.EnableDEKIsolation = false; return c }(),
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.BarrierConfigured() {
		t.Fatal("BarrierConfigured() = true with a nil SDK client, want false")
	}
}

func TestSDKTenantBarrierClient_ForwardsEachVerb(t *testing.T) {
	fake := newFakeQRDBTenants()
	bc := NewTenantBarrierClient(fake)
	if bc == nil {
		t.Fatal("NewTenantBarrierClient(fake) = nil")
	}
	ctx := context.Background()
	const id = "tenant-a"

	if err := bc.TenantBarrierInit(ctx, &quicbaassdk.QRDBTenantBarrierInitRequest{TenantID: id, Passphrase: []byte("operator-pass")}); err != nil {
		t.Fatalf("TenantBarrierInit: %v", err)
	}
	if err := bc.TenantBarrierUnseal(ctx, &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: id, Key: []byte("operator-pass")}); err != nil {
		t.Fatalf("TenantBarrierUnseal: %v", err)
	}
	st, err := bc.TenantBarrierStatus(ctx, &quicbaassdk.QRDBTenantBarrierStatusRequest{TenantID: id})
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if st.Sealed || !st.Initialized || st.Strategy != "software" || !st.HardwareBacked {
		t.Fatalf("status after unseal = %+v, want unsealed, initialized, software, hardware-backed", st)
	}
	if err := bc.TenantBarrierSeal(ctx, &quicbaassdk.QRDBTenantBarrierSealRequest{TenantID: id}); err != nil {
		t.Fatalf("TenantBarrierSeal: %v", err)
	}

	if len(fake.inits) != 1 || fake.inits[0].TenantID != id || string(fake.inits[0].Passphrase) != "operator-pass" {
		t.Fatalf("inits = %+v, want one for %q with the operator passphrase", fake.inits, id)
	}
	if len(fake.unseals) != 1 || fake.unseals[0].TenantID != id || string(fake.unseals[0].Key) != "operator-pass" {
		t.Fatalf("unseals = %+v, want one for %q with the operator passphrase key", fake.unseals, id)
	}
	if len(fake.seals) != 1 || fake.seals[0] != id {
		t.Fatalf("seals = %v, want [%s]", fake.seals, id)
	}
	if len(fake.statuses) != 1 || fake.statuses[0] != id {
		t.Fatalf("statuses = %v, want [%s]", fake.statuses, id)
	}
}

func TestSDKTenantBarrierClient_InitErrorPropagates(t *testing.T) {
	fake := newFakeQRDBTenants()
	fake.initErr = errors.New("barrier backend down")
	bc := NewTenantBarrierClient(fake)

	err := bc.TenantBarrierInit(context.Background(), &quicbaassdk.QRDBTenantBarrierInitRequest{TenantID: "t", Passphrase: []byte("operator-pass")})
	if !errors.Is(err, fake.initErr) {
		t.Fatalf("TenantBarrierInit error = %v, want %v", err, fake.initErr)
	}
}

func TestManager_BarrierLifecycleThroughSDKAdapter(t *testing.T) {
	fake := newFakeQRDBTenants()
	iamClient := newMockIAMClient()
	cfg := &ManagerConfig{
		IAMTenantClient:     iamClient,
		IAMRoleClient:       iamClient,
		TenantBarrierClient: NewTenantBarrierClient(fake),
		Config:              DefaultConfig(),
		Logger:              newTestLogger(),
	}
	cfg.Config.EnableDEKIsolation = false
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !m.BarrierConfigured() {
		t.Fatal("BarrierConfigured() = false with the SDK adapter wired")
	}

	ctx := context.Background()
	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{Name: "sdk-adapter-tenant"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	id := entity.ID

	if err := m.InitTenantBarrier(ctx, id, []byte("operator-pass")); err != nil {
		t.Fatalf("InitTenantBarrier: %v", err)
	}
	st, err := m.TenantBarrierStatus(ctx, id)
	if err != nil {
		t.Fatalf("TenantBarrierStatus after init: %v", err)
	}
	if !st.Initialized || !st.Sealed {
		t.Fatalf("status after init = %+v, want initialized and sealed", st)
	}

	if err := m.UnsealTenantBarrier(ctx, id, []byte("operator-pass")); err != nil {
		t.Fatalf("UnsealTenantBarrier: %v", err)
	}
	if n := len(fake.unseals); n != 1 || string(fake.unseals[0].Key) != "operator-pass" || fake.unseals[0].TenantID != id {
		t.Fatalf("unseals = %+v, want one for %q with the operator passphrase key", fake.unseals, id)
	}
	st, err = m.TenantBarrierStatus(ctx, id)
	if err != nil {
		t.Fatalf("TenantBarrierStatus after unseal: %v", err)
	}
	if st.Sealed {
		t.Fatalf("status after unseal = %+v, want unsealed", st)
	}

	if err := m.SealTenantBarrier(ctx, id); err != nil {
		t.Fatalf("SealTenantBarrier: %v", err)
	}
	st, err = m.TenantBarrierStatus(ctx, id)
	if err != nil {
		t.Fatalf("TenantBarrierStatus after seal: %v", err)
	}
	if !st.Sealed {
		t.Fatalf("status after seal = %+v, want sealed", st)
	}
	if len(fake.seals) != 1 || fake.seals[0] != id {
		t.Fatalf("seals = %v, want [%s]", fake.seals, id)
	}
}

// TestSDKTenantBarrierClient_UnsealRefusesWrongKey: like go-qrdb's
// TenantBarrierUnseal, an unseal whose key is not the init passphrase is
// refused and the tenant stays sealed; the init passphrase opens it.
func TestSDKTenantBarrierClient_UnsealRefusesWrongKey(t *testing.T) {
	fake := newFakeQRDBTenants()
	bc := NewTenantBarrierClient(fake)
	ctx := context.Background()
	const id = "t"

	if err := bc.TenantBarrierInit(ctx, &quicbaassdk.QRDBTenantBarrierInitRequest{TenantID: id, Passphrase: []byte("operator-pass")}); err != nil {
		t.Fatalf("TenantBarrierInit: %v", err)
	}
	if err := bc.TenantBarrierUnseal(ctx, &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: id, Key: []byte("wrong-pass")}); err == nil {
		t.Fatal("TenantBarrierUnseal with a wrong key = nil, want a refusal")
	}
	st, err := bc.TenantBarrierStatus(ctx, &quicbaassdk.QRDBTenantBarrierStatusRequest{TenantID: id})
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if !st.Sealed || !st.Initialized {
		t.Fatalf("status after a wrong-key unseal = %+v, want sealed and initialized", st)
	}
	if err := bc.TenantBarrierUnseal(ctx, &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: id, Key: []byte("operator-pass")}); err != nil {
		t.Fatalf("TenantBarrierUnseal with the init passphrase: %v", err)
	}
	st, err = bc.TenantBarrierStatus(ctx, &quicbaassdk.QRDBTenantBarrierStatusRequest{TenantID: id})
	if err != nil {
		t.Fatalf("TenantBarrierStatus: %v", err)
	}
	if st.Sealed {
		t.Fatalf("status after unseal with the init passphrase = %+v, want unsealed", st)
	}
}

// TestSDKTenantBarrierClient_UnsealUninitializedRefused: a tenant whose
// barrier was never initialized cannot be unsealed.
func TestSDKTenantBarrierClient_UnsealUninitializedRefused(t *testing.T) {
	fake := newFakeQRDBTenants()
	bc := NewTenantBarrierClient(fake)
	if err := bc.TenantBarrierUnseal(context.Background(), &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: "never-init", Key: []byte("operator-pass")}); err == nil {
		t.Fatal("TenantBarrierUnseal of a never-initialized tenant = nil, want a refusal")
	}
}

// TestManager_UnsealRefusesKeyOtherThanInitPassphrase: through the manager a
// wrong unseal key is an ErrBarrierOperationFailed for "unseal", the barrier
// stays sealed, and the init passphrase unseals it.
func TestManager_UnsealRefusesKeyOtherThanInitPassphrase(t *testing.T) {
	fake := newFakeQRDBTenants()
	m := newSDKAdapterManager(t, fake)
	ctx := context.Background()
	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{Name: "wrong-key-tenant"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	id := entity.ID
	if err := m.InitTenantBarrier(ctx, id, []byte("operator-pass")); err != nil {
		t.Fatalf("InitTenantBarrier: %v", err)
	}

	err = m.UnsealTenantBarrier(ctx, id, []byte("wrong-pass"))
	var failed ErrBarrierOperationFailed
	if !errors.As(err, &failed) || failed.Operation != "unseal" {
		t.Fatalf("UnsealTenantBarrier with a wrong key: err = %v, want ErrBarrierOperationFailed for unseal", err)
	}
	st, err := m.TenantBarrierStatus(ctx, id)
	if err != nil {
		t.Fatalf("TenantBarrierStatus after a wrong-key unseal: %v", err)
	}
	if !st.Sealed {
		t.Fatalf("status after a wrong-key unseal = %+v, want sealed", st)
	}

	if err := m.UnsealTenantBarrier(ctx, id, []byte("operator-pass")); err != nil {
		t.Fatalf("UnsealTenantBarrier with the init passphrase: %v", err)
	}
	st, err = m.TenantBarrierStatus(ctx, id)
	if err != nil {
		t.Fatalf("TenantBarrierStatus after unseal: %v", err)
	}
	if st.Sealed {
		t.Fatalf("status after unseal with the init passphrase = %+v, want unsealed", st)
	}

	if err := m.SealTenantBarrier(ctx, id); err != nil {
		t.Fatalf("SealTenantBarrier: %v", err)
	}
	st, err = m.TenantBarrierStatus(ctx, id)
	if err != nil {
		t.Fatalf("TenantBarrierStatus after seal: %v", err)
	}
	if !st.Sealed {
		t.Fatalf("status after seal = %+v, want sealed", st)
	}
}

// newSDKAdapterManager builds a Manager whose barrier client is the SDK
// adapter over fake.
func newSDKAdapterManager(t *testing.T, fake *fakeQRDBTenants) *Manager {
	t.Helper()
	iamClient := newMockIAMClient()
	cfg := &ManagerConfig{
		IAMTenantClient:     iamClient,
		IAMRoleClient:       iamClient,
		TenantBarrierClient: NewTenantBarrierClient(fake),
		Config:              DefaultConfig(),
		Logger:              newTestLogger(),
	}
	cfg.Config.EnableDEKIsolation = false
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// TestManager_BarrierOpsRefusedForNonBarrierIsolation: a tenant whose data
// routes through the shared store (prefix, or no type, which the engine reads
// as prefix) refuses Initialize, Unseal and Seal, so the card can never show
// Sealed over readable data; nothing reaches the barrier backend.
func TestManager_BarrierOpsRefusedForNonBarrierIsolation(t *testing.T) {
	cases := []struct {
		name string
		set  func(f *fakeQRDBTenants, id string)
	}{
		{"prefix", func(f *fakeQRDBTenants, id string) { f.prefix[id] = true }},
		{"untyped", func(f *fakeQRDBTenants, id string) { f.untyped[id] = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeQRDBTenants()
			m := newSDKAdapterManager(t, fake)
			ctx := context.Background()
			entity, err := m.CreateTenant(ctx, &CreateTenantRequest{Name: "iso-" + tc.name})
			if err != nil {
				t.Fatalf("CreateTenant: %v", err)
			}
			id := entity.ID
			fake.mu.Lock()
			tc.set(fake, id)
			inits, unseals, seals := len(fake.inits), len(fake.unseals), len(fake.seals)
			fake.mu.Unlock()

			ops := []struct {
				op string
				fn func() error
			}{
				{"init", func() error { return m.InitTenantBarrier(ctx, id, []byte("operator-pass")) }},
				{"unseal", func() error { return m.UnsealTenantBarrier(ctx, id, []byte("k")) }},
				{"seal", func() error { return m.SealTenantBarrier(ctx, id) }},
			}
			for _, o := range ops {
				err := o.fn()
				var bad ErrInvalidRequest
				if !errors.As(err, &bad) || !strings.Contains(bad.Reason, "prefix isolation") {
					t.Fatalf("%s on a %s tenant: err = %v, want ErrInvalidRequest naming prefix isolation", o.op, tc.name, err)
				}
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.inits) != inits || len(fake.unseals) != unseals || len(fake.seals) != seals {
				t.Fatalf("a refused barrier operation reached the backend")
			}
		})
	}
}

// TestManager_BarrierOpsFailClosedOnIsolationLookupError: when the tenant's
// isolation type cannot be read, the barrier operation is refused with the
// lookup error and nothing reaches the barrier backend.
func TestManager_BarrierOpsFailClosedOnIsolationLookupError(t *testing.T) {
	fake := newFakeQRDBTenants()
	m := newSDKAdapterManager(t, fake)
	ctx := context.Background()
	entity, err := m.CreateTenant(ctx, &CreateTenantRequest{Name: "iso-lookup-down"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	id := entity.ID
	fake.mu.Lock()
	fake.getErr = errors.New("qrdb tenant lookup down")
	inits, seals := len(fake.inits), len(fake.seals)
	fake.mu.Unlock()

	if err := m.InitTenantBarrier(ctx, id, []byte("operator-pass")); !errors.Is(err, fake.getErr) {
		t.Fatalf("InitTenantBarrier err = %v, want the lookup error", err)
	}
	if len(fake.inits) != inits {
		t.Fatalf("init reached the backend after a failed isolation lookup")
	}
	if err := m.SealTenantBarrier(ctx, id); !errors.Is(err, fake.getErr) {
		t.Fatalf("SealTenantBarrier err = %v, want the lookup error", err)
	}
	if len(fake.seals) != seals {
		t.Fatalf("seal reached the backend after a failed isolation lookup")
	}
}
