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
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// validVPNServiceConfig is the smallest enabled management VPN the core
// accepts: a pool to lease from and a zone to reach.
func validVPNServiceConfig() *ManagementVPNServiceConfig {
	return &ManagementVPNServiceConfig{
		Enabled: true,
		Config: vpn.Config{
			Pool:    "remote-access",
			AllowTo: []string{"management"},
			MASQUE: vpn.MASQUESettings{
				Template: "https://gw.example:4433/.well-known/masque/ip/",
				Routes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
		},
	}
}

// errVPNStub is returned by the admission collaborators these tests never
// drive: admission itself is the VPN core's own suite.
type errVPNStub struct{ op string }

func (e *errVPNStub) Error() string {
	return "vpn stub: " + e.op + " is not driven by the gateway tests"
}

type stubVPNIdentity struct{}

func (stubVPNIdentity) Evaluate(context.Context, *calleradmission.Peer) calleradmission.Decision {
	return calleradmission.Decision{}
}

func (stubVPNIdentity) RecordAdmission(context.Context, calleradmission.Decision) error { return nil }

type stubVPNVerifier struct{}

func (stubVPNVerifier) Verify(context.Context, string, []byte, *manifest.HostAttestation) (*verdict.DeviceVerdict, error) {
	return nil, &errVPNStub{op: "attestation"}
}

type stubVPNPosture struct{}

func (stubVPNPosture) Evaluate(context.Context, string, map[string]interface{}) (*opa.EvaluationResult, error) {
	return nil, &errVPNStub{op: "posture"}
}

type stubVPNFactors struct{}

func (stubVPNFactors) Verify(context.Context, string, string, []byte, *vpn.PersonFactor) error {
	return &errVPNStub{op: "person factor"}
}

// errFakePlane is a fake data plane's injected failure.
type errFakePlane struct{ name string }

func (e *errFakePlane) Error() string { return "fake plane " + e.name + " failed" }

// fakeVPNPlane records its lifecycle into a log shared with its siblings,
// so the tests can assert the order planes start and stop in.
type fakeVPNPlane struct {
	name     string
	events   *[]string
	startErr error
	stopErr  error
	removed  []vpn.LeaseID
}

func (p *fakeVPNPlane) Kind() vpn.DataPlaneKind                       { return vpn.DataPlaneMASQUE }
func (p *fakeVPNPlane) InstallPeer(context.Context, *vpn.Lease) error { return nil }

func (p *fakeVPNPlane) RemovePeer(_ context.Context, id vpn.LeaseID) error {
	p.removed = append(p.removed, id)
	return nil
}

func (p *fakeVPNPlane) Start(context.Context) error {
	*p.events = append(*p.events, "start "+p.name)
	return p.startErr
}

func (p *fakeVPNPlane) Stop(context.Context) error {
	*p.events = append(*p.events, "stop "+p.name)
	return p.stopErr
}

// listFailingLeaseStore is a memory store whose List can be made to fail.
type listFailingLeaseStore struct {
	*vpn.MemoryLeaseStore
	fail bool
}

func (s *listFailingLeaseStore) List(ctx context.Context) ([]*vpn.Lease, error) {
	if s.fail {
		return nil, &errVPNStub{op: "lease list"}
	}
	return s.MemoryLeaseStore.List(ctx)
}

// vpnRig is a gateway hosting only the management VPN, over fakes.
type vpnRig struct {
	gw     *Gateway
	plane  *fakeVPNPlane
	builds int
	events []string
	leases *listFailingLeaseStore
	pki    *testutil.TestTLSBundle
}

func newVPNRuntime(r *vpnRig) *VPNRuntime {
	r.plane = &fakeVPNPlane{name: "masque", events: &r.events}
	r.leases = &listFailingLeaseStore{MemoryLeaseStore: vpn.NewMemoryLeaseStore()}
	return &VPNRuntime{
		Identity: stubVPNIdentity{},
		Verifier: stubVPNVerifier{},
		Posture:  stubVPNPosture{},
		Factors:  stubVPNFactors{},
		IPAM:     backends.NewMemoryBackend(),
		DataPlanes: map[vpn.DataPlaneKind]VPNDataPlaneFactory{
			vpn.DataPlaneMASQUE: func(*slog.Logger) (vpn.ManagedDataPlane, error) {
				r.builds++
				return r.plane, nil
			},
		},
		Leases:   r.leases,
		Audit:    stubVPNIdentity{},
		Listener: vpn.ListenerDeps{Certificate: r.pki.ServerCert, ClientCAs: staticVPNAnchor{pool: r.pki.CAPool}},
	}
}

// staticVPNAnchor is the device-identity anchor the rig's listener trusts.
type staticVPNAnchor struct{ pool *x509.CertPool }

func (a staticVPNAnchor) CAPool(context.Context) (*x509.CertPool, error) { return a.pool, nil }

// freeLoopbackPort returns a loopback port nothing listens on; the listener
// config refuses port 0, so the rig cannot let the kernel pick at bind.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func newVPNRig(t *testing.T) *vpnRig {
	t.Helper()
	r := &vpnRig{pki: testutil.GenerateTestTLSBundle(t)}
	cfg := baseGatewayConfig("vpn-gw")
	cfg.ManagementVPN = validVPNServiceConfig()
	cfg.ManagementVPN.Listener = vpn.ListenerConfig{BindHost: "127.0.0.1", Port: freeLoopbackPort(t)}
	cfg.HostedServices = []string{ServiceManagementVPN}
	cfg.Runtime = &GatewayRuntime{VPN: newVPNRuntime(r)}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	r.gw = gw
	return r
}

func (r *vpnRig) handler() ServiceHandler { return r.gw.serviceHandlers[ServiceManagementVPN] }

// putLease stores a live lease for tenant-a/laptop-1 as an earlier admission
// would have.
func (r *vpnRig) putLease(t *testing.T) *vpn.Lease {
	t.Helper()
	now := time.Now()
	lease := &vpn.Lease{
		ID:        "lease-1",
		TenantID:  "tenant-a",
		DeviceID:  "laptop-1",
		Address:   netip.MustParsePrefix("100.64.0.2/32"),
		Zones:     []string{"management"},
		DataPlane: vpn.DataPlaneMASQUE,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, r.leases.Put(context.Background(), lease))
	return lease
}

func laptopSection() *gwstate.DesiredVPN {
	return &gwstate.DesiredVPN{
		Peers: []gwstate.DesiredVPNPeer{{TenantID: "tenant-a", DeviceID: "laptop-1", Zones: []string{"management"}}},
	}
}

func TestBuildManagementVPN_RefusesWithoutAVPNRuntime(t *testing.T) {
	r := newVPNRig(t)
	r.gw.config.Runtime = &GatewayRuntime{}

	_, err := buildManagementVPN(r.gw)
	var missing *ErrRuntimeMissing
	require.True(t, errors.As(err, &missing), "got %v", err)
	assert.Equal(t, ServiceManagementVPN, missing.Service)
}

func TestBuildManagementVPN_RefusesWithoutASection(t *testing.T) {
	r := newVPNRig(t)
	r.gw.config.ManagementVPN = nil

	_, err := buildManagementVPN(r.gw)
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, ServiceManagementVPN, unavailable.Service)
}

// TestBuildManagementVPN_AConfiguredPlaneTheHostLacksRefuses: the service
// never starts without a plane it is configured to offer.
func TestBuildManagementVPN_AConfiguredPlaneTheHostLacksRefuses(t *testing.T) {
	r := newVPNRig(t)
	r.gw.config.Runtime.VPN.DataPlanes = nil

	_, err := buildManagementVPN(r.gw)
	var failed *ErrServiceStartFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	var deps *vpn.ErrDepsMissing
	assert.True(t, errors.As(err, &deps), "the core's refusal is the cause, got %v", err)
}

func TestBuildManagementVPN_APlaneThatWillNotBuildRefuses(t *testing.T) {
	r := newVPNRig(t)
	r.gw.config.Runtime.VPN.DataPlanes[vpn.DataPlaneMASQUE] = func(*slog.Logger) (vpn.ManagedDataPlane, error) {
		return nil, &errFakePlane{name: "masque"}
	}

	_, err := buildManagementVPN(r.gw)
	var failed *ErrServiceStartFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	var planeErr *errFakePlane
	assert.True(t, errors.As(err, &planeErr), "got %v", err)
}

// TestBuildManagementVPN_ARefusedServiceStopsThePlanesItBuilt: a plane holds
// its host device from construction, so a refusal must release it.
func TestBuildManagementVPN_ARefusedServiceStopsThePlanesItBuilt(t *testing.T) {
	r := newVPNRig(t)
	r.gw.config.Runtime.VPN.Identity = nil

	_, err := buildManagementVPN(r.gw)
	var deps *vpn.ErrDepsMissing
	require.True(t, errors.As(err, &deps), "got %v", err)
	assert.Equal(t, []string{"stop masque"}, r.events)
}

func TestBuildManagementVPN_RefusesWithoutListenerTLS(t *testing.T) {
	r := newVPNRig(t)
	r.gw.config.Runtime.VPN.Listener = vpn.ListenerDeps{}

	_, err := buildManagementVPN(r.gw)
	var failed *ErrServiceStartFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	var deps *vpn.ErrDepsMissing
	require.True(t, errors.As(err, &deps), "got %v", err)
	assert.Equal(t, "listener certificate", deps.Dep)
	assert.Equal(t, []string{"stop masque"}, r.events)
}

func TestVPNBackend_ServesTheAdmissionListenerUntilStop(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))
	addr := r.gw.vpn.listener.Addr()
	require.NotNil(t, addr)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: r.pki.ClientTLSConfig()}}
	defer client.CloseIdleConnections()
	resp, err := client.Post("https://"+addr.String()+vpn.PathChallenges, "application/json", nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, r.handler().Stop(ctx))
	ln, err := net.Listen("tcp", addr.String())
	require.NoError(t, err, "stop releases the listener's port")
	require.NoError(t, ln.Close())
}

func TestVPNBackend_ATakenListenerPortRollsBack(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	listen := r.gw.config.ManagementVPN.Listener
	taken, err := net.Listen("tcp", net.JoinHostPort(listen.BindHost, strconv.Itoa(listen.Port)))
	require.NoError(t, err)
	defer func() { require.NoError(t, taken.Close()) }()

	err = r.handler().Start(ctx)
	var bind *vpn.ErrListenerBind
	require.True(t, errors.As(err, &bind), "got %v", err)
	assert.Equal(t, []string{"start masque", "stop masque"}, r.events)
	assert.Nil(t, r.gw.vpn)
}

// TestVPNService_ARestartBuildsFreshPlanes: a stopped MASQUE plane cannot be
// started again, so every start builds its planes anew.
func TestVPNService_ARestartBuildsFreshPlanes(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	for range 2 {
		require.NoError(t, r.handler().Start(ctx))
		require.NoError(t, r.handler().Stop(ctx))
	}
	assert.Equal(t, 2, r.builds)
}

// TestVPNService_StartAppliesTheRecordedSectionAndStopRevokes: a section
// delivered before the service starts is applied as it starts, and stopping
// the service hands every address back.
func TestVPNService_StartAppliesTheRecordedSectionAndStopRevokes(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	lease := r.putLease(t)
	require.NoError(t, r.gw.applyVPN(ctx, laptopSection()), "a section before start is recorded")
	assert.Nil(t, r.gw.collectVPN(ctx), "no vpn section while the service is not running")

	require.NoError(t, r.handler().Start(ctx))
	assert.Equal(t, []string{"start masque"}, r.events)
	assert.Equal(t, []vpn.Enrolment{{TenantID: "tenant-a", DeviceID: "laptop-1", Zones: []string{"management"}}},
		r.gw.vpn.svc.Enrolments())

	snap := r.gw.collectVPN(ctx)
	require.NotNil(t, snap)
	assert.True(t, snap.Running)
	assert.Equal(t, 1, snap.EnrolledPeers)
	require.Len(t, snap.Leases, 1, "the enrolled peer's lease survives the section")
	assert.Equal(t, "100.64.0.2/32", snap.Leases[0].Address)
	assert.Equal(t, map[string]int{"masque": 1}, snap.LeasesByDataPlane)

	require.NoError(t, r.handler().Stop(ctx))
	assert.Equal(t, []string{"start masque", "stop masque"}, r.events)
	assert.Equal(t, []vpn.LeaseID{lease.ID}, r.plane.removed)
	_, err := r.leases.Get(ctx, lease.ID)
	var nf *vpn.ErrLeaseNotFound
	assert.True(t, errors.As(err, &nf), "stop revokes the lease, got %v", err)
	assert.Nil(t, r.gw.collectVPN(ctx))
}

func TestVPNService_StartWithoutASectionEnrolsNobody(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	r.putLease(t)

	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()
	assert.Empty(t, r.gw.vpn.svc.Enrolments())
	assert.Len(t, r.gw.collectVPN(ctx).Leases, 1, "no section, no sweep: nothing was delivered to act on")
}

// TestCollectVPN_CarriesTheServiceCounters: the section carries what the
// gatewayd_vpn_* metrics export, from the same health snapshot.
func TestCollectVPN_CarriesTheServiceCounters(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	lease := r.putLease(t)
	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()

	snap := r.gw.collectVPN(ctx)
	assert.Nil(t, snap.Revocations, "nothing revoked yet")
	assert.Nil(t, snap.PostureViolations)
	require.NotNil(t, snap.Reattest, "the histogram is always reported")
	assert.Equal(t, uint64(0), snap.Reattest.Count)
	assert.NotEmpty(t, snap.Reattest.Buckets)

	require.NoError(t, r.gw.vpn.svc.Revoke(ctx, lease.ID, vpn.RevokeOperator))
	assert.Equal(t, map[string]uint64{"operator": 1}, r.gw.collectVPN(ctx).Revocations)
}

func TestReattestState_ConvertsTheHistogram(t *testing.T) {
	got := reattestState(vpn.DurationHistogram{
		Count:   3,
		Sum:     1500 * time.Millisecond,
		Buckets: []vpn.HistogramBucket{{UpperBoundSeconds: 0.5, Count: 1}, {UpperBoundSeconds: 1, Count: 2}},
	})
	assert.Equal(t, &gwstate.DurationHistogram{
		Count:      3,
		SumSeconds: 1.5,
		Buckets:    []gwstate.HistogramBucket{{UpperBoundSeconds: 0.5, Count: 1}, {UpperBoundSeconds: 1, Count: 2}},
	}, got)
	assert.Empty(t, reattestState(vpn.DurationHistogram{}).Buckets, "no buckets converts to none")
}

func TestVPNBackend_StartRollsBackThePlanesAlreadyStarted(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	svc, err := buildManagementVPN(r.gw)
	require.NoError(t, err)
	backend := svc.(*vpnBackend)
	second := &fakeVPNPlane{name: "second", events: &r.events, startErr: &errFakePlane{name: "second"}}
	backend.planes = []vpn.ManagedDataPlane{r.plane, second}

	err = backend.Start(ctx)
	var planeErr *errFakePlane
	require.True(t, errors.As(err, &planeErr), "got %v", err)
	assert.Equal(t, []string{"start masque", "start second", "stop masque"}, r.events)
	assert.False(t, backend.Active())
	assert.Nil(t, r.gw.vpn)
}

func TestVPNBackend_AServiceThatWillNotStartStopsThePlanes(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	svc, err := buildManagementVPN(r.gw)
	require.NoError(t, err)
	backend := svc.(*vpnBackend)
	require.NoError(t, backend.svc.Start(ctx))
	defer func() { require.NoError(t, backend.svc.Stop(ctx)) }()

	err = backend.Start(ctx)
	var already *vpn.ErrAlreadyStarted
	require.True(t, errors.As(err, &already), "got %v", err)
	assert.Equal(t, []string{"start masque", "stop masque"}, r.events)
	assert.Nil(t, r.gw.vpn)
}

func TestStopPlanes_StopsInReverseAndJoinsFailures(t *testing.T) {
	var events []string
	first := &fakeVPNPlane{name: "first", events: &events, stopErr: &errFakePlane{name: "first"}}
	second := &fakeVPNPlane{name: "second", events: &events}

	err := stopPlanes(context.Background(), []vpn.ManagedDataPlane{first, second})
	var planeErr *errFakePlane
	require.True(t, errors.As(err, &planeErr), "got %v", err)
	assert.Equal(t, []string{"stop second", "stop first"}, events, "a failed stop does not stop the others stopping")
	assert.NoError(t, stopPlanes(context.Background(), nil))
}

func TestApplyVPN_ReachesTheRunningService(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()

	require.NoError(t, r.gw.applyVPN(ctx, laptopSection()))
	assert.Len(t, r.gw.vpn.svc.Enrolments(), 1)

	broken := laptopSection()
	broken.PosturePolicies = []gwstate.DesiredVPNPosturePolicy{
		{TenantID: "tenant-a", Name: vpn.DefaultPosturePolicy, Module: "package vpn.posture\nallow if {"},
	}
	err := r.gw.applyVPN(ctx, broken)
	var invalid *vpn.ErrPosturePolicyInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
	snap := r.gw.collectVPN(ctx)
	require.Len(t, snap.PosturePolicyErrors, 1, "the refused tenant is visible in telemetry")
	assert.Contains(t, snap.PosturePolicyErrors[0], "tenant-a")
}

func TestApplyVPN_AGatewayWithoutTheVPNIgnoresTheSection(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)

	r.gw.config.ManagementVPN = &ManagementVPNServiceConfig{Enabled: false}
	require.NoError(t, r.gw.applyVPN(ctx, laptopSection()))
	r.gw.config.ManagementVPN = nil
	require.NoError(t, r.gw.applyVPN(ctx, laptopSection()))
	assert.Nil(t, r.gw.desiredVPN, "a gateway that does not run the VPN keeps no enrolment set")
}

func TestCollectVPN_ReportsTheServiceWhenItsLeasesAreUnreadable(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))

	r.leases.fail = true
	snap := r.gw.collectVPN(ctx)
	require.NotNil(t, snap)
	assert.True(t, snap.Running)
	assert.Empty(t, snap.Leases)

	err := r.handler().Stop(ctx)
	var stub *errVPNStub
	assert.True(t, errors.As(err, &stub), "stop reports the leases it could not revoke, got %v", err)
}

func TestGatewayApply_AppliesTheVPNSectionInProcess(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()

	require.NoError(t, r.gw.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "vpn-gw", Version: "v1", VPN: laptopSection()}))
	assert.Len(t, r.gw.vpn.svc.Enrolments(), 1)
	assert.Equal(t, "v1", r.gw.DesiredConfigState().Version)
}

// A peer asking for a zone the gateway does not serve does not block the
// others: the version applies, the valid peer is enrolled, and telemetry
// names the refused peer and its reason.
func TestGatewayApply_ARefusedPeerDoesNotBlockTheRest(t *testing.T) {
	ctx := context.Background()
	r := newVPNRig(t)
	require.NoError(t, r.handler().Start(ctx))
	defer func() { require.NoError(t, r.handler().Stop(ctx)) }()

	section := laptopSection()
	section.Peers = append(section.Peers, gwstate.DesiredVPNPeer{TenantID: "tenant-a", DeviceID: "laptop-2", Zones: []string{"no-such-zone"}})
	require.NoError(t, r.gw.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "vpn-gw", Version: "v1", VPN: section}))

	assert.Equal(t, "v1", r.gw.DesiredConfigState().Version)
	assert.Equal(t, []vpn.Enrolment{{TenantID: "tenant-a", DeviceID: "laptop-1", Zones: []string{"management"}}}, r.gw.vpn.svc.Enrolments())
	snap := r.gw.collectVPN(ctx)
	require.Len(t, snap.RejectedPeers, 1)
	assert.Equal(t, "laptop-2", snap.RejectedPeers[0].DeviceID)
	assert.Contains(t, snap.RejectedPeers[0].Reason, "no-such-zone")
}

// TestGatewayApply_TheVPNSectionStaysInProcessBesideASupervisedDatapath:
// the datapath child gets the document; the VPN section is applied here.
func TestGatewayApply_TheVPNSectionStaysInProcessBesideASupervisedDatapath(t *testing.T) {
	ctx := context.Background()
	sup := newFakeSupervisor()
	sup.unsupervised[ServiceManagementVPN] = true
	sup.applyState = gwstate.DesiredConfigState{Version: "v1"}
	gw := newSupervisedGateway(t, sup)

	desired := &gwstate.DesiredConfig{GatewayID: "supervised-gw", Version: "v1", VPN: laptopSection()}
	require.NoError(t, gw.Apply(ctx, desired))
	assert.Same(t, desired, sup.applied)
	assert.Same(t, desired.VPN, gw.desiredVPN)
	assert.Equal(t, "v1", gw.DesiredConfigState().Version)
}

// TestGatewayApply_ASupervisedVPNSectionGoesToTheSupervisor: the supervisor
// sends the document to the vpn child (#557), so the parent applies nothing
// of the section itself and reports the document applied.
func TestGatewayApply_ASupervisedVPNSectionGoesToTheSupervisor(t *testing.T) {
	ctx := context.Background()
	sup := newFakeSupervisor()
	sup.applyState = gwstate.DesiredConfigState{Version: "v1"}
	gw := newSupervisedGateway(t, sup)

	desired := &gwstate.DesiredConfig{GatewayID: "supervised-gw", Version: "v1", VPN: laptopSection()}
	require.NoError(t, gw.Apply(ctx, desired))
	assert.Same(t, desired, sup.applied, "the supervisor receives the whole document")
	assert.Nil(t, gw.desiredVPN, "the parent does not hold the supervised section")
	assert.Equal(t, "v1", gw.DesiredConfigState().Version)
	assert.Empty(t, gw.DesiredConfigState().LastError)
}
