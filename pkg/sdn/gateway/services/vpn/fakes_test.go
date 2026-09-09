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
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// fakeClock is a manual clock: Now advances only when the test says so, and
// Tick delivers only when the test fires it.
type fakeClock struct {
	mu   sync.Mutex
	now  time.Time
	tick chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC), tick: make(chan time.Time, 1)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) Tick(time.Duration) (<-chan time.Time, func()) { return c.tick, func() {} }

type fakeIdentity struct {
	decision calleradmission.Decision
}

func (f *fakeIdentity) Evaluate(context.Context, *calleradmission.Peer) calleradmission.Decision {
	return f.decision
}

type fakeVerifier struct {
	mu      sync.Mutex
	verdict *verdict.DeviceVerdict
	err     error
	calls   int
}

func (f *fakeVerifier) Verify(_ context.Context, deviceID string, _ []byte, _ *manifest.HostAttestation) (*verdict.DeviceVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.verdict == nil {
		return nil, nil
	}
	v := *f.verdict
	return &v, nil
}

func (f *fakeVerifier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakePosture struct {
	mu     sync.Mutex
	result *opa.EvaluationResult
	err    error
	inputs []map[string]interface{}
}

func (f *fakePosture) Evaluate(_ context.Context, _ string, input map[string]interface{}) (*opa.EvaluationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, input)
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func (f *fakePosture) inputCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inputs)
}

type fakeFactors struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (f *fakeFactors) Verify(context.Context, string, string, []byte, *PersonFactor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeFactors) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakePlane struct {
	kind       DataPlaneKind
	installErr error
	removeErr  error
	mu         sync.Mutex
	installed  map[LeaseID]*Lease
	removed    []LeaseID
}

func newFakePlane(kind DataPlaneKind) *fakePlane {
	return &fakePlane{kind: kind, installed: map[LeaseID]*Lease{}}
}

func (p *fakePlane) Kind() DataPlaneKind { return p.kind }

func (p *fakePlane) InstallPeer(_ context.Context, lease *Lease) error {
	if p.installErr != nil {
		return p.installErr
	}
	p.mu.Lock()
	cp := *lease
	p.installed[lease.ID] = &cp
	p.mu.Unlock()
	return nil
}

func (p *fakePlane) RemovePeer(_ context.Context, id LeaseID) error {
	p.mu.Lock()
	delete(p.installed, id)
	p.removed = append(p.removed, id)
	p.mu.Unlock()
	return p.removeErr
}

func (p *fakePlane) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.installed)
}

// fakeIPAM is a minimal Allocator: a named pool with a fixed number of
// addresses, released back on Release.
type fakeIPAM struct {
	ipam.Allocator
	mu        sync.Mutex
	pool      *ipam.Pool
	poolErr   error
	next      netip.Addr
	free      []netip.Addr
	allocated map[netip.Addr]string
	capacity  int
	renewErr  error
	releases  int
}

func newFakeIPAM(capacity int) *fakeIPAM {
	return &fakeIPAM{
		pool:      &ipam.Pool{ID: "pool-1", Name: "vpn-clients", CIDR: netip.MustParsePrefix("10.200.0.0/24")},
		next:      netip.MustParseAddr("10.200.0.10"),
		allocated: map[netip.Addr]string{},
		capacity:  capacity,
	}
}

func (f *fakeIPAM) GetPoolByName(_ context.Context, name string) (*ipam.Pool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.poolErr != nil {
		return nil, f.poolErr
	}
	if name != f.pool.Name {
		return nil, errors.New("no such pool")
	}
	return f.pool, nil
}

func (f *fakeIPAM) Allocate(_ context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.allocated) >= f.capacity {
		return nil, errors.New("pool exhausted")
	}
	var addr netip.Addr
	if len(f.free) > 0 {
		addr = f.free[0]
		f.free = f.free[1:]
	} else {
		addr = f.next
		f.next = f.next.Next()
	}
	f.allocated[addr] = req.DeviceID
	return &ipam.Allocation{ID: addr.String(), PoolID: req.PoolID, IP: addr, DeviceID: req.DeviceID}, nil
}

func (f *fakeIPAM) Release(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.allocated[ip]; !ok {
		return errors.New("not allocated")
	}
	delete(f.allocated, ip)
	f.free = append(f.free, ip)
	f.releases++
	return nil
}

func (f *fakeIPAM) Renew(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renewErr != nil {
		return f.renewErr
	}
	if _, ok := f.allocated[ip]; !ok {
		return errors.New("not allocated")
	}
	return nil
}

type fakeAudit struct {
	mu        sync.Mutex
	decisions []calleradmission.Decision
	err       error
}

func (a *fakeAudit) RecordAdmission(_ context.Context, d calleradmission.Decision) error {
	a.mu.Lock()
	a.decisions = append(a.decisions, d)
	a.mu.Unlock()
	return a.err
}

// harness wires a service with admitting fakes; tests flip one fake at a
// time to exercise each refusal.
type harness struct {
	svc      *Service
	clock    *fakeClock
	identity *fakeIdentity
	verifier *fakeVerifier
	posture  *fakePosture
	factors  *fakeFactors
	ipam     *fakeIPAM
	plane    *fakePlane
	store    *MemoryLeaseStore
	audit    *fakeAudit
}

func testConfig() Config {
	return Config{
		Pool:       "vpn-clients",
		DataPlanes: []DataPlaneKind{DataPlaneMASQUE},
		AllowTo:    []string{"management"},
	}
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{
		clock:    newFakeClock(),
		identity: &fakeIdentity{decision: calleradmission.Decision{Admitted: true, Identity: "mini-99", Reason: calleradmission.ReasonAdmitted}},
		verifier: &fakeVerifier{verdict: &verdict.DeviceVerdict{DeviceID: 99, Passed: true, Cryptographic: true, ProfileID: 7}},
		posture:  &fakePosture{result: &opa.EvaluationResult{Allowed: true}},
		factors:  &fakeFactors{},
		ipam:     newFakeIPAM(2),
		plane:    newFakePlane(DataPlaneMASQUE),
		store:    NewMemoryLeaseStore(),
		audit:    &fakeAudit{},
	}
	deps := Deps{
		Identity:   h.identity,
		Verifier:   h.verifier,
		Posture:    h.posture,
		Factors:    h.factors,
		IPAM:       h.ipam,
		DataPlanes: map[DataPlaneKind]DataPlane{DataPlaneMASQUE: h.plane},
		Leases:     h.store,
		Audit:      h.audit,
		Clock:      h.clock,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	svc, err := New(deps, cfg)
	require.NoError(t, err)
	h.svc = svc
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	return h
}

func (h *harness) request(t *testing.T) *AdmissionRequest {
	t.Helper()
	nonce, err := h.svc.Challenge()
	require.NoError(t, err)
	return &AdmissionRequest{
		Peer:           &calleradmission.Peer{Leaf: &x509.Certificate{}, RemoteAddr: "203.0.113.9:4433"},
		DeviceID:       "mini-99",
		TenantID:       "tenant-a",
		Nonce:          nonce,
		Attestation:    &manifest.HostAttestation{QuoteData: []byte("quote"), Nonce: nonce},
		Posture:        &PostureReport{SecureBoot: SecureBootPosture{Enabled: true, Available: true}, IMA: IMAPosture{Enabled: true, PolicyLoaded: true}, FDE: FDEPosture{RootEncrypted: true}, AgentVersion: "0.1.0", CollectedAt: h.clock.Now()},
		PersonFactor:   &PersonFactor{Kind: PersonFactorFIDO2, CredentialID: "cred-1", Assertion: []byte("sig")},
		DataPlane:      DataPlaneMASQUE,
		RequestedZones: []string{"management"},
	}
}

func (h *harness) evidence(t *testing.T) *Evidence {
	t.Helper()
	nonce, err := h.svc.Challenge()
	require.NoError(t, err)
	return &Evidence{
		Nonce:        nonce,
		Attestation:  &manifest.HostAttestation{QuoteData: []byte("quote"), Nonce: nonce},
		Posture:      &PostureReport{SecureBoot: SecureBootPosture{Enabled: true}, IMA: IMAPosture{Enabled: true, PolicyLoaded: true}, FDE: FDEPosture{RootEncrypted: true}, AgentVersion: "0.1.0"},
		PersonFactor: &PersonFactor{Kind: PersonFactorFIDO2, CredentialID: "cred-1", Assertion: []byte("sig")},
	}
}

func (f *fakeIPAM) allocatedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.allocated)
}

func (f *fakeIPAM) releaseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.releases
}
