// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package tenant

import (
	"context"
	"errors"
	"sync"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// fakeQRDBTenants is a QRDB tenant client that implements only the four
// per-tenant barrier verbs the manager uses. Every other method of the
// embedded interface panics (nil embedded value), so a call the adapter
// should not make fails the test loudly.
type fakeQRDBTenants struct {
	quicbaassdk.QRDBTenantClient

	mu          sync.Mutex
	inits       []*quicbaassdk.QRDBTenantBarrierInitRequest
	unseals     []*quicbaassdk.QRDBTenantBarrierUnsealRequest
	seals       []string
	statuses    []string
	sealed      map[string]bool
	initialized map[string]bool
	initErr     error
}

func newFakeQRDBTenants() *fakeQRDBTenants {
	return &fakeQRDBTenants{
		sealed:      map[string]bool{},
		initialized: map[string]bool{},
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
	return &quicbaassdk.QRDBTenantBarrierInitResponse{}, nil
}

func (f *fakeQRDBTenants) TenantBarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unseals = append(f.unseals, req)
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
	if err := bc.TenantBarrierUnseal(ctx, &quicbaassdk.QRDBTenantBarrierUnsealRequest{TenantID: id, Key: []byte("k")}); err != nil {
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
	if len(fake.unseals) != 1 || fake.unseals[0].TenantID != id || string(fake.unseals[0].Key) != "k" {
		t.Fatalf("unseals = %+v, want one for %q with key k", fake.unseals, id)
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

	if err := m.UnsealTenantBarrier(ctx, id, []byte("k")); err != nil {
		t.Fatalf("UnsealTenantBarrier: %v", err)
	}
	if n := len(fake.unseals); n != 1 || string(fake.unseals[0].Key) != "k" || fake.unseals[0].TenantID != id {
		t.Fatalf("unseals = %+v, want one for %q with key k", fake.unseals, id)
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
