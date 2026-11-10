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

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// errFake is the failure every fake returns when told to fail.
type errFake struct{ what string }

func (e *errFake) Error() string { return e.what + " failed" }

type fakeDevice struct {
	id       string
	cert     tls.Certificate
	certErr  error
	quoteErr error
}

func (d *fakeDevice) ID() string { return d.id }

func (d *fakeDevice) Certificate() (tls.Certificate, error) { return d.cert, d.certErr }

func (d *fakeDevice) Quote(_ context.Context, nonce []byte) (*manifest.HostAttestation, error) {
	if d.quoteErr != nil {
		return nil, d.quoteErr
	}
	return &manifest.HostAttestation{
		QuoteData: append([]byte("quote:"), nonce...),
		Signature: []byte("sig"),
		Nonce:     nonce,
		PCRs:      []manifest.PCRValue{{Index: 7, Value: []byte{0x07}, Algorithm: "sha256"}},
	}, nil
}

type fakePosture struct{ err error }

func (p *fakePosture) Collect(context.Context) (*gwvpn.PostureReport, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &gwvpn.PostureReport{FDE: gwvpn.FDEPosture{RootEncrypted: true}, AgentVersion: "test"}, nil
}

type fakeFactors struct {
	err   error
	nonce []byte
}

func (f *fakeFactors) Sign(_ context.Context, kind gwvpn.PersonFactorKind, nonce []byte) (*gwvpn.PersonFactor, error) {
	f.nonce = nonce
	if f.err != nil {
		return nil, f.err
	}
	return &gwvpn.PersonFactor{Kind: kind, CredentialID: "cred-1", Assertion: []byte("assertion")}, nil
}

type fakePlane struct {
	kind       gwvpn.DataPlaneKind
	prepareErr error
	upErr      error
	downErr    error
	up         []gwvpn.LeaseID
	down       []Session
	// onUp runs as Up starts, before Up fails or succeeds.
	onUp func()
}

func (p *fakePlane) Kind() gwvpn.DataPlaneKind { return p.kind }

func (p *fakePlane) Prepare(context.Context) (gwvpn.PeerWire, error) {
	if p.prepareErr != nil {
		return gwvpn.PeerWire{}, p.prepareErr
	}
	if p.kind == gwvpn.DataPlaneMASQUE {
		return gwvpn.PeerWire{}, nil
	}
	return gwvpn.PeerWire{WireGuardPublicKey: []byte("wg-public")}, nil
}

func (p *fakePlane) Up(_ context.Context, lease *gwvpn.LeaseWire) (Session, error) {
	if p.onUp != nil {
		p.onUp()
	}
	if p.upErr != nil {
		return Session{}, p.upErr
	}
	p.up = append(p.up, lease.ID)
	return Session{Interface: string(p.kind) + "0"}, nil
}

func (p *fakePlane) Down(ctx context.Context, s Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.downErr != nil {
		return p.downErr
	}
	p.down = append(p.down, s)
	return nil
}

type fakeGateway struct {
	offered      []gwvpn.DataPlaneKind
	challengeErr error
	admitErr     error
	lease        *gwvpn.LeaseWire
	revokeErr    error
	admitted     *gwvpn.AdmissionRequestWire
	revoked      []gwvpn.LeaseID
	// revokeDeadline records the last revoke's context deadline; zero when it
	// had none.
	revokeDeadline time.Time
	// renewQueue answers renewals in order; once empty a renewal fails
	// without a refusal, as an unreachable gateway does.
	renewQueue []renewal
	renewedIDs []gwvpn.LeaseID
	renewReqs  []*gwvpn.RenewalRequestWire
}

type renewal struct {
	lease *gwvpn.LeaseWire
	err   error
}

// renewedLease is testState's lease after n renewals, an hour apart.
func renewedLease(n int64) *gwvpn.LeaseWire {
	lease := testState().Lease
	lease.RenewAtUnix += n * 3600
	lease.ExpiresAtUnix += n * 3600
	lease.Renewals = int(n)
	return &lease
}

func (g *fakeGateway) Challenge(context.Context) (*gwvpn.ChallengeWire, error) {
	if g.challengeErr != nil {
		return nil, g.challengeErr
	}
	return &gwvpn.ChallengeWire{Nonce: []byte("nonce-1"), DataPlanes: g.offered}, nil
}

func (g *fakeGateway) Admit(_ context.Context, req *gwvpn.AdmissionRequestWire) (*gwvpn.LeaseWire, error) {
	g.admitted = req
	if g.admitErr != nil {
		return nil, g.admitErr
	}
	if g.lease != nil {
		return g.lease, nil
	}
	return &gwvpn.LeaseWire{ID: "l-1", DeviceID: req.DeviceID, Address: "10.8.0.2/32", DataPlane: req.DataPlane}, nil
}

func (g *fakeGateway) Renew(_ context.Context, id gwvpn.LeaseID, req *gwvpn.RenewalRequestWire) (*gwvpn.LeaseWire, error) {
	g.renewedIDs = append(g.renewedIDs, id)
	g.renewReqs = append(g.renewReqs, req)
	if len(g.renewQueue) == 0 {
		return nil, &ErrGatewayUnreachable{Gateway: "gw.example:4433", Cause: &errFake{"dial"}}
	}
	next := g.renewQueue[0]
	g.renewQueue = g.renewQueue[1:]
	return next.lease, next.err
}

func (g *fakeGateway) Revoke(ctx context.Context, id gwvpn.LeaseID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.revokeDeadline, _ = ctx.Deadline()
	g.revoked = append(g.revoked, id)
	return g.revokeErr
}

type memState struct {
	st        *State
	saveErr   error
	removeErr error
}

func (m *memState) Load() (*State, error) {
	if m.st == nil {
		return nil, &ErrNotConnected{}
	}
	return m.st, nil
}

func (m *memState) Save(st *State) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.st = st
	return nil
}

func (m *memState) Remove() error {
	if m.removeErr != nil {
		return m.removeErr
	}
	m.st = nil
	return nil
}

type fixture struct {
	device  *fakeDevice
	posture *fakePosture
	factors *fakeFactors
	masque  *fakePlane
	wg      *fakePlane
	gateway *fakeGateway
	state   *memState
	dialErr error
	dialed  []string
	now     time.Time
	waits   []time.Duration
	// onWait runs at each wait KeepAlive starts, numbered from 1; when it
	// returns false the wait never fires.
	onWait func(n int) bool
}

func newFixture(t *testing.T) *fixture {
	return &fixture{
		now:     time.Unix(1760300000, 0),
		device:  &fakeDevice{id: "laptop-1", cert: deviceCertificate(t, "laptop-1")},
		posture: &fakePosture{},
		factors: &fakeFactors{},
		masque:  &fakePlane{kind: gwvpn.DataPlaneMASQUE},
		wg:      &fakePlane{kind: "wireguard"},
		gateway: &fakeGateway{offered: []gwvpn.DataPlaneKind{gwvpn.DataPlaneMASQUE}},
		state:   &memState{},
	}
}

func (f *fixture) agent(t *testing.T) *Agent {
	t.Helper()
	a, err := New(Deps{
		Device:     f.device,
		Posture:    f.posture,
		Factors:    f.factors,
		DataPlanes: []DataPlane{f.masque, f.wg},
		State:      f.state,
		Dial: func(addr string, cert tls.Certificate) (Gateway, error) {
			f.dialed = append(f.dialed, addr+" as "+cert.Leaf.Subject.CommonName)
			return f.gateway, f.dialErr
		},
		Now:   func() time.Time { return f.now },
		After: f.after,
	})
	require.NoError(t, err)
	return a
}

// after moves the fixture's clock on by d and fires at once, so KeepAlive
// runs its whole schedule without waiting.
func (f *fixture) after(d time.Duration) <-chan time.Time {
	f.waits = append(f.waits, d)
	if f.onWait != nil && !f.onWait(len(f.waits)) {
		return nil
	}
	f.now = f.now.Add(d)
	fired := make(chan time.Time, 1)
	fired <- f.now
	return fired
}

var connectOpts = ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme", Factor: gwvpn.PersonFactorFIDO2, Zones: []string{"management"}}

func TestConnect_AdmitsWithEvidenceBoundToTheNonceAndBringsThePlaneUp(t *testing.T) {
	f := newFixture(t)

	st, err := f.agent(t).Connect(context.Background(), connectOpts)

	require.NoError(t, err)
	req := f.gateway.admitted
	assert.Equal(t, "acme", req.TenantID)
	assert.Equal(t, "laptop-1", req.DeviceID)
	assert.Equal(t, []byte("nonce-1"), req.Nonce)
	assert.Equal(t, []byte("quote:nonce-1"), req.Attestation.Quote, "the quote's qualifying data is the gateway's nonce")
	assert.Equal(t, "07", req.Attestation.PCRs[0].Value)
	assert.True(t, req.Posture.FDE.RootEncrypted)
	assert.Equal(t, []byte("nonce-1"), f.factors.nonce, "the factor signs the same nonce")
	assert.Equal(t, &gwvpn.PersonFactorWire{Kind: gwvpn.PersonFactorFIDO2, CredentialID: "cred-1", Assertion: []byte("assertion")}, req.PersonFactor)
	assert.Equal(t, gwvpn.DataPlaneMASQUE, req.DataPlane)
	assert.Equal(t, []string{"management"}, req.Zones)
	assert.Equal(t, []string{"gw.example:4433 as laptop-1"}, f.dialed, "mTLS with the device certificate")

	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.masque.up)
	assert.Equal(t, "gw.example:4433", st.Gateway)
	assert.Equal(t, gwvpn.LeaseID("l-1"), st.Lease.ID)
	assert.Equal(t, Session{Interface: "masque0"}, st.Session)
	assert.Equal(t, time.Unix(1760300000, 0).UTC(), st.ConnectedAt)
	assert.Equal(t, st, f.state.st, "the lease is recorded")
}

func TestConnect_WithoutAFactorPresentsNone(t *testing.T) {
	f := newFixture(t)

	_, err := f.agent(t).Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme"})

	require.NoError(t, err)
	assert.Nil(t, f.gateway.admitted.PersonFactor)
	assert.Nil(t, f.factors.nonce)
}

func TestConnect_PicksTheGatewaysFirstPlaneThisBuildHas(t *testing.T) {
	f := newFixture(t)
	f.gateway.offered = []gwvpn.DataPlaneKind{"quic-datagram", "wireguard", gwvpn.DataPlaneMASQUE}

	_, err := f.agent(t).Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme"})

	require.NoError(t, err)
	assert.Equal(t, gwvpn.DataPlaneKind("wireguard"), f.gateway.admitted.DataPlane)
	assert.Equal(t, []byte("wg-public"), f.gateway.admitted.Peer.WireGuardPublicKey)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.wg.up)
}

func TestConnect_ARequestedPlaneOverridesTheGatewaysPreference(t *testing.T) {
	f := newFixture(t)
	f.gateway.offered = []gwvpn.DataPlaneKind{"wireguard", gwvpn.DataPlaneMASQUE}

	_, err := f.agent(t).Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme", DataPlane: gwvpn.DataPlaneMASQUE})

	require.NoError(t, err)
	assert.Equal(t, gwvpn.DataPlaneMASQUE, f.gateway.admitted.DataPlane)
}

func TestConnect_RefusesAPlaneThisBuildDoesNotHave(t *testing.T) {
	f := newFixture(t)
	f.gateway.offered = []gwvpn.DataPlaneKind{"quic-datagram"}
	a := f.agent(t)

	_, err := a.Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme", DataPlane: "ipsec"})
	var unsupported *ErrDataPlaneUnsupported
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, gwvpn.DataPlaneKind("ipsec"), unsupported.Kind)

	_, err = a.Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme"})
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, "data plane quic-datagram not available", err.Error())

	f.gateway.offered = nil
	_, err = a.Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme"})
	var invalid *ErrInvalidResponse
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, f.gateway.admitted, "nothing is presented without a plane")
}

func TestConnect_RefusesBadOptionsBeforeContactingTheGateway(t *testing.T) {
	tests := []struct {
		name  string
		opts  ConnectOptions
		field string
	}{
		{"no gateway", ConnectOptions{}, "gateway"},
		{"no tenant", ConnectOptions{Gateway: "gw:1"}, "tenant"},
		{"unknown factor", ConnectOptions{Gateway: "gw:1", TenantID: "acme", Factor: "totp"}, "factor"},
		{"no device id", ConnectOptions{Gateway: "gw:1", TenantID: "acme"}, "device id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.field == "device id" {
				f.device.id = ""
			}
			_, err := f.agent(t).Connect(context.Background(), tt.opts)
			var invalid *ErrInvalidOptions
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tt.field, invalid.Field)
			assert.Empty(t, f.dialed)
		})
	}
}

func TestConnect_RefusesAFactorThisHostCannotSign(t *testing.T) {
	f := newFixture(t)
	a, err := New(Deps{Device: f.device, Posture: f.posture, DataPlanes: []DataPlane{f.masque}, State: f.state,
		Dial: func(string, tls.Certificate) (Gateway, error) { return f.gateway, nil }})
	require.NoError(t, err)

	_, err = a.Connect(context.Background(), connectOpts)
	var invalid *ErrInvalidOptions
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "factor", invalid.Field)
}

func TestConnect_RefusesWhileALeaseIsHeld(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()

	_, err := f.agent(t).Connect(context.Background(), connectOpts)

	var already *ErrAlreadyConnected
	require.ErrorAs(t, err, &already)
	assert.Equal(t, gwvpn.LeaseID("l-1"), already.LeaseID)
	assert.Empty(t, f.dialed)
}

func TestConnect_EachEvidenceStepFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		sabotage func(f *fixture)
		step     string
	}{
		{"device certificate", func(f *fixture) { f.device.certErr = &errFake{"cert"} }, "device certificate"},
		{"quote", func(f *fixture) { f.device.quoteErr = &errFake{"quote"} }, "quote"},
		{"posture", func(f *fixture) { f.posture.err = &errFake{"posture"} }, "posture"},
		{"factor", func(f *fixture) { f.factors.err = &errFake{"touch"} }, "person factor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.sabotage(f)

			_, err := f.agent(t).Connect(context.Background(), connectOpts)

			var evidence *ErrEvidence
			require.ErrorAs(t, err, &evidence)
			assert.Equal(t, tt.step, evidence.Step)
			assert.Nil(t, f.gateway.admitted, "no admission without every piece of evidence")
			assert.Equal(t, ExitFailure, ExitCode(err))
		})
	}
}

func TestConnect_PrepareFailureIsADataPlaneError(t *testing.T) {
	f := newFixture(t)
	f.masque.prepareErr = &errFake{"keygen"}

	_, err := f.agent(t).Connect(context.Background(), connectOpts)

	var plane *ErrDataPlane
	require.ErrorAs(t, err, &plane)
	assert.Equal(t, "prepare", plane.Op)
	assert.Nil(t, f.gateway.admitted)
}

func TestConnect_GatewayFailuresReachTheCaller(t *testing.T) {
	f := newFixture(t)
	f.dialErr = &ErrInvalidOptions{Field: "gateway", Reason: "bad"}
	_, err := f.agent(t).Connect(context.Background(), connectOpts)
	assert.ErrorIs(t, err, f.dialErr)

	f = newFixture(t)
	f.gateway.challengeErr = &ErrGatewayUnreachable{Gateway: "gw", Cause: &errFake{"dial"}}
	_, err = f.agent(t).Connect(context.Background(), connectOpts)
	assert.ErrorIs(t, err, f.gateway.challengeErr)
}

func TestConnect_ARefusalIsReturnedWithItsExitCode(t *testing.T) {
	tests := []struct {
		name    string
		refusal *RefusedError
		exit    int
	}{
		{"identity", &RefusedError{Status: http.StatusUnauthorized, Class: "untrusted-issuer"}, ExitRefused},
		{"attestation", &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalAttestationFailed}, ExitRefused},
		{"posture", &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation, Rules: []string{"fde"}}, ExitPostureViolation},
		{"factor", &RefusedError{Status: http.StatusUnauthorized, Class: gwvpn.RefusalPersonFactorInvalid}, ExitRefused},
		{"lease", &RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalPoolExhausted}, ExitRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.gateway.admitErr = tt.refusal

			_, err := f.agent(t).Connect(context.Background(), connectOpts)

			assert.ErrorIs(t, err, tt.refusal)
			assert.Equal(t, tt.exit, ExitCode(err))
			assert.Empty(t, f.masque.up)
			assert.Nil(t, f.state.st)
		})
	}
}

func TestConnect_RevokesALeaseItCannotUse(t *testing.T) {
	f := newFixture(t)
	f.gateway.lease = &gwvpn.LeaseWire{ID: "l-9", DataPlane: "wireguard"}

	_, err := f.agent(t).Connect(context.Background(), connectOpts)

	var invalid *ErrInvalidResponse
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, []gwvpn.LeaseID{"l-9"}, f.gateway.revoked)
	assert.Empty(t, f.masque.up)
}

func TestConnect_RevokesTheLeaseWhenThePlaneFailsToComeUp(t *testing.T) {
	f := newFixture(t)
	f.masque.upErr = &errFake{"tun"}

	_, err := f.agent(t).Connect(context.Background(), connectOpts)

	var plane *ErrDataPlane
	require.ErrorAs(t, err, &plane)
	assert.Equal(t, "up", plane.Op)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked)
	assert.Nil(t, f.state.st)
}

func TestConnect_AFailedRollbackIsReportedButNotDecisive(t *testing.T) {
	f := newFixture(t)
	f.masque.upErr = &errFake{"tun"}
	f.gateway.revokeErr = &RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalLeaseStoreUnavailable}

	_, err := f.agent(t).Connect(context.Background(), connectOpts)

	var rollback *ErrRollback
	require.ErrorAs(t, err, &rollback)
	assert.Equal(t, ExitFailure, ExitCode(err), "the data plane failed; the revoke's refusal is detail")
}

func TestConnect_TearsDownAndRevokesWhenTheStateCannotBeSaved(t *testing.T) {
	f := newFixture(t)
	f.state.saveErr = &ErrStateStore{Op: "write", Cause: &errFake{"disk"}}

	_, err := f.agent(t).Connect(context.Background(), connectOpts)

	assert.ErrorIs(t, err, f.state.saveErr)
	assert.Equal(t, []Session{{Interface: "masque0"}}, f.masque.down)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked)

	f.masque.downErr = &errFake{"ip link del"}
	_, err = f.agent(t).Connect(context.Background(), connectOpts)
	var rollback *ErrRollback
	require.ErrorAs(t, err, &rollback)
	var plane *ErrDataPlane
	assert.ErrorAs(t, rollback.Rollback, &plane)
	assert.Len(t, f.gateway.revoked, 2, "the lease is revoked even when the tunnel would not go down")
}

// A connect cancelled while the plane comes up still undoes its admission:
// the revoke and the teardown run on their own bounded context, so the
// gateway does not keep the peer and its address until the lease expires.
func TestConnect_RollsBackOnItsOwnContextWhenTheConnectIsCancelled(t *testing.T) {
	tests := []struct {
		name     string
		sabotage func(f *fixture)
		down     []Session
	}{
		{"the plane does not come up", func(f *fixture) { f.masque.upErr = context.Canceled }, nil},
		{"the state cannot be saved", func(f *fixture) {
			f.state.saveErr = &ErrStateStore{Op: "write", Cause: &errFake{"disk"}}
		}, []Session{{Interface: "masque0"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.sabotage(f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.masque.onUp = cancel

			_, err := f.agent(t).Connect(ctx, connectOpts)

			require.Error(t, err)
			var rollback *ErrRollback
			assert.False(t, errors.As(err, &rollback), "the rollback succeeded: %v", err)
			assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked)
			assert.False(t, f.gateway.revokeDeadline.IsZero(), "the rollback has its own deadline")
			assert.Equal(t, tt.down, f.masque.down)
			assert.Nil(t, f.state.st)
		})
	}
}

// The rollback's bound starts when the cleanup begins, not before setup: a
// plane that takes longer than the bound to come up, or a slow state save,
// must not leave the revoke and the teardown an expired context.
func TestConnect_RollbackDeadlineStartsWhenTheCleanupBegins(t *testing.T) {
	tests := []struct {
		name     string
		sabotage func(f *fixture)
	}{
		{"the plane does not come up", func(f *fixture) { f.masque.upErr = &errFake{"up"} }},
		{"the state cannot be saved", func(f *fixture) {
			f.state.saveErr = &ErrStateStore{Op: "write", Cause: &errFake{"disk"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.sabotage(f)
			var setupAt time.Time
			f.masque.onUp = func() { setupAt = time.Now() }

			_, err := f.agent(t).Connect(context.Background(), connectOpts)

			require.Error(t, err)
			assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked)
			require.False(t, f.gateway.revokeDeadline.IsZero(), "the rollback has its own deadline")
			assert.False(t, f.gateway.revokeDeadline.Before(setupAt.Add(rollbackTimeout)),
				"the rollback deadline %v was set before setup ran at %v", f.gateway.revokeDeadline, setupAt)
		})
	}
}

func TestDisconnect_RevokesTearsDownAndForgets(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()

	st, err := f.agent(t).Disconnect(context.Background())

	require.NoError(t, err)
	assert.Equal(t, gwvpn.LeaseID("l-1"), st.Lease.ID)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked)
	assert.Equal(t, []string{"gw.example:4433 as laptop-1"}, f.dialed)
	assert.Equal(t, []Session{{Interface: "vpn0"}}, f.masque.down)
	assert.Nil(t, f.state.st)
}

func TestAgent_EveryLeaseOperationWithoutALeaseIsNotConnected(t *testing.T) {
	tests := []struct {
		name string
		call func(a *Agent) error
	}{
		{"disconnect", func(a *Agent) error { _, err := a.Disconnect(context.Background()); return err }},
		{"lease", func(a *Agent) error { _, err := a.Lease(); return err }},
		{"renew", func(a *Agent) error { _, err := a.Renew(context.Background()); return err }},
		{"keep alive", func(a *Agent) error { return a.KeepAlive(context.Background()) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(newFixture(t).agent(t))
			assert.Equal(t, ExitNotConnected, ExitCode(err))
		})
	}
}

func TestDisconnect_ALeaseTheGatewayNoLongerHoldsIsGone(t *testing.T) {
	for _, class := range []gwvpn.RefusalClass{gwvpn.RefusalLeaseNotFound, gwvpn.RefusalLeaseExpired} {
		t.Run(string(class), func(t *testing.T) {
			f := newFixture(t)
			f.state.st = testState()
			f.gateway.revokeErr = &RefusedError{Status: http.StatusNotFound, Class: class}

			_, err := f.agent(t).Disconnect(context.Background())

			require.NoError(t, err)
			assert.Nil(t, f.state.st)
		})
	}
}

func TestDisconnect_TearsDownEvenWhenTheRevokeFails(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.gateway.revokeErr = &ErrGatewayUnreachable{Gateway: "gw", Cause: &errFake{"dial"}}

	_, err := f.agent(t).Disconnect(context.Background())

	assert.ErrorIs(t, err, f.gateway.revokeErr)
	assert.Len(t, f.masque.down, 1, "the tunnel goes down; the lease expires on its own")
	assert.Nil(t, f.state.st)
}

func TestDisconnect_KeepsTheStateWhenTheTunnelWillNotGoDown(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.masque.downErr = &errFake{"ip link del"}

	_, err := f.agent(t).Disconnect(context.Background())

	var plane *ErrDataPlane
	require.ErrorAs(t, err, &plane)
	assert.NotNil(t, f.state.st, "disconnect can be run again")
}

func TestDisconnect_ReportsAStateThatCannotBeRemoved(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.state.removeErr = &ErrStateStore{Op: "remove", Cause: &errFake{"unlink"}}

	_, err := f.agent(t).Disconnect(context.Background())

	assert.ErrorIs(t, err, f.state.removeErr)
}

func TestDisconnect_ReportsAPlaneThisBuildDoesNotHave(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.state.st.Lease.DataPlane = "ipsec"

	_, err := f.agent(t).Disconnect(context.Background())

	var unsupported *ErrDataPlaneUnsupported
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked, "the lease is still revoked")
}

func TestDisconnect_StillTearsDownWithoutTheDeviceCertificate(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.device.certErr = &errFake{"tpm"}

	_, err := f.agent(t).Disconnect(context.Background())

	var evidence *ErrEvidence
	require.ErrorAs(t, err, &evidence)
	assert.Len(t, f.masque.down, 1)
}

func TestLease_ReturnsTheHeldLease(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()

	st, err := f.agent(t).Lease()

	require.NoError(t, err)
	assert.Equal(t, int64(1760325200), st.Lease.RenewAtUnix)
}

func TestPosture_ReturnsTheReportConnectSends(t *testing.T) {
	f := newFixture(t)

	report, err := f.agent(t).Posture(context.Background())

	require.NoError(t, err)
	assert.True(t, report.FDE.RootEncrypted)
	assert.Equal(t, "test", report.AgentVersion)
	assert.Empty(t, f.dialed)
}

func TestPosture_CollectionFailureIsEvidence(t *testing.T) {
	f := newFixture(t)
	f.posture.err = &errFake{"posture"}

	_, err := f.agent(t).Posture(context.Background())

	var evidence *ErrEvidence
	require.ErrorAs(t, err, &evidence)
	assert.Equal(t, "posture", evidence.Step)
	assert.Equal(t, ExitFailure, ExitCode(err))
}

func TestRenew_PresentsFreshEvidenceForTheHeldLease(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.state.st.Factor = gwvpn.PersonFactorFIDO2
	f.gateway.renewQueue = []renewal{{lease: renewedLease(1)}}

	st, err := f.agent(t).Renew(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.renewedIDs)
	req := f.gateway.renewReqs[0]
	assert.Equal(t, []byte("nonce-1"), req.Nonce)
	assert.Equal(t, []byte("quote:nonce-1"), req.Attestation.Quote, "a fresh quote over the renewal's nonce")
	assert.True(t, req.Posture.FDE.RootEncrypted)
	assert.Equal(t, gwvpn.PersonFactorFIDO2, req.PersonFactor.Kind, "the factor connect presented signs again")
	assert.Equal(t, 1, st.Lease.Renewals)
	assert.Equal(t, renewedLease(1).ExpiresAtUnix, f.state.st.Lease.ExpiresAtUnix, "the renewed lease is saved")
	assert.Empty(t, f.masque.down)
}

func TestRenew_ARefusalThatEndsTheLeaseTearsItDown(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.gateway.renewQueue = []renewal{{err: &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation, Rules: []string{"fde"}}}}

	_, err := f.agent(t).Renew(context.Background())

	assert.Equal(t, ExitPostureViolation, ExitCode(err))
	assert.Equal(t, []Session{{Interface: "vpn0"}}, f.masque.down)
	assert.Equal(t, []gwvpn.LeaseID{"l-1"}, f.gateway.revoked)
	assert.Nil(t, f.state.st)
}

func TestRenew_ARefusalThatKeepsTheLeaseLeavesItUp(t *testing.T) {
	for name, refusal := range map[string]*RefusedError{
		"renewal-not-open": {Status: http.StatusConflict, Class: gwvpn.RefusalRenewalNotOpen},
		"nonce-unknown":    {Status: http.StatusForbidden, Class: gwvpn.RefusalNonceUnknown},
		"unavailable":      {Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalLeaseStoreUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.state.st = testState()
			f.gateway.renewQueue = []renewal{{err: refusal}}

			_, err := f.agent(t).Renew(context.Background())

			assert.Equal(t, ExitRefused, ExitCode(err))
			assert.Empty(t, f.masque.down)
			assert.Empty(t, f.gateway.revoked)
			assert.Equal(t, testState(), f.state.st)
		})
	}
}

func TestRenew_ReportsAFailedTeardownWithTheRefusalsCode(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.masque.downErr = &errFake{"ip link del"}
	f.gateway.renewQueue = []renewal{{err: &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation}}}

	_, err := f.agent(t).Renew(context.Background())

	var rollback *ErrRollback
	require.ErrorAs(t, err, &rollback)
	assert.Equal(t, ExitPostureViolation, ExitCode(err))
}

func TestRenew_RejectsARenewalOfAnotherLease(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	other := renewedLease(1)
	other.ID = "l-2"
	f.gateway.renewQueue = []renewal{{lease: other}}

	_, err := f.agent(t).Renew(context.Background())

	var invalid *ErrInvalidResponse
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, testState(), f.state.st, "the held lease is kept")
}

func TestRenew_KeepsTheLeaseWhenTheEvidenceFails(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.device.quoteErr = &errFake{"tpm2_quote"}

	_, err := f.agent(t).Renew(context.Background())

	var evidence *ErrEvidence
	require.ErrorAs(t, err, &evidence)
	assert.Equal(t, "quote", evidence.Step)
	assert.Empty(t, f.gateway.renewedIDs)
	assert.NotNil(t, f.state.st)
}

func TestRenew_ReportsARenewalThatCannotBeSaved(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.state.saveErr = &ErrStateStore{Op: "save", Cause: &errFake{"write"}}
	f.gateway.renewQueue = []renewal{{lease: renewedLease(1)}}

	_, err := f.agent(t).Renew(context.Background())

	assert.ErrorIs(t, err, f.state.saveErr)
}

func TestEndsLease_OnlyARefusalThatCannotBeRetried(t *testing.T) {
	cases := map[string]struct {
		err  error
		ends bool
	}{
		"posture violation": {&RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation}, true},
		"lease expired":     {&RefusedError{Status: http.StatusGone, Class: gwvpn.RefusalLeaseExpired}, true},
		"renewal not open":  {&RefusedError{Status: http.StatusConflict, Class: gwvpn.RefusalRenewalNotOpen}, false},
		"unavailable":       {&RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalPostureUnavailable}, false},
		"unreachable":       {&ErrGatewayUnreachable{Gateway: "gw", Cause: &errFake{"dial"}}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.ends, endsLease(tc.err))
		})
	}
}

func TestKeepAlive_RenewsEachTimeTheWindowOpensUntilCancelled(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.gateway.renewQueue = []renewal{{lease: renewedLease(1)}, {lease: renewedLease(2)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onWait = func(n int) bool {
		if n == 3 {
			cancel()
			return false
		}
		return true
	}

	err := f.agent(t).KeepAlive(ctx)

	require.NoError(t, err)
	assert.Equal(t, []time.Duration{25200 * time.Second, time.Hour, time.Hour}, f.waits, "each wait ends when the lease's renewal opens")
	assert.Equal(t, []gwvpn.LeaseID{"l-1", "l-1"}, f.gateway.renewedIDs)
	assert.Equal(t, 2, f.state.st.Lease.Renewals)
	assert.Empty(t, f.masque.down)
}

func TestKeepAlive_ARefusalTearsDownAndReturnsItsCode(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.gateway.renewQueue = []renewal{{err: &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation, Rules: []string{"ima"}}}}

	err := f.agent(t).KeepAlive(context.Background())

	assert.Equal(t, ExitPostureViolation, ExitCode(err))
	assert.Len(t, f.masque.down, 1)
	assert.Nil(t, f.state.st)
}

func TestKeepAlive_RetriesAFailedRenewal(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.gateway.renewQueue = []renewal{
		{err: &RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalLeaseStoreUnavailable}},
		{lease: renewedLease(1)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onWait = func(n int) bool {
		if n == 3 {
			cancel()
			return false
		}
		return true
	}

	err := f.agent(t).KeepAlive(ctx)

	require.NoError(t, err)
	require.Len(t, f.waits, 3)
	assert.Equal(t, renewRetry, f.waits[1])
	assert.Equal(t, 1, f.state.st.Lease.Renewals)
}

func TestKeepAlive_ALeaseThatExpiresUnrenewedLapses(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.state.st.Lease.ExpiresAtUnix = f.state.st.Lease.RenewAtUnix + 45

	err := f.agent(t).KeepAlive(context.Background())

	var lapsed *ErrLeaseLapsed
	require.ErrorAs(t, err, &lapsed)
	assert.Equal(t, gwvpn.LeaseID("l-1"), lapsed.LeaseID)
	assert.Equal(t, ExitFailure, ExitCode(err))
	assert.Equal(t, []time.Duration{25200 * time.Second, renewRetry, 15 * time.Second}, f.waits, "the last retry waits only until expiry")
	assert.Len(t, f.masque.down, 1)
	assert.Nil(t, f.state.st)
}

func TestKeepAlive_StopsWhenTheLeaseIsForgotten(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	f.onWait = func(int) bool {
		f.state.st = nil
		return true
	}

	err := f.agent(t).KeepAlive(context.Background())

	assert.Equal(t, ExitNotConnected, ExitCode(err))
	assert.Empty(t, f.gateway.renewedIDs)
}

func TestErrLeaseLapsed_NamesTheLeaseAndUnwrapsToTheCause(t *testing.T) {
	cause := &errFake{"dial"}
	err := &ErrLeaseLapsed{LeaseID: "l-1", Cause: cause}

	assert.Equal(t, "lease l-1 expired before it could be renewed: dial failed", err.Error())
	assert.ErrorIs(t, err, cause)
}

func TestNew_RequiresEveryCollaborator(t *testing.T) {
	f := newFixture(t)
	full := Deps{Device: f.device, Posture: f.posture, DataPlanes: []DataPlane{f.masque}, State: f.state,
		Dial: func(string, tls.Certificate) (Gateway, error) { return f.gateway, nil }}
	tests := []struct {
		field string
		strip func(d *Deps)
	}{
		{"posture source", func(d *Deps) { d.Posture = nil }},
		{"state store", func(d *Deps) { d.State = nil }},
		{"gateway dialer", func(d *Deps) { d.Dial = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			deps := full
			tt.strip(&deps)
			_, err := New(deps)
			var invalid *ErrInvalidOptions
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tt.field, invalid.Field)
		})
	}
	_, err := New(full)
	assert.NoError(t, err, "Factors and Now are optional")
}

func TestNew_WithoutDeviceOrDataPlanesStillReadsTheLease(t *testing.T) {
	f := newFixture(t)
	f.state.st = testState()
	a, err := New(Deps{Posture: f.posture, State: f.state,
		Dial: func(string, tls.Certificate) (Gateway, error) { return f.gateway, nil }})
	require.NoError(t, err)

	st, err := a.Lease()
	require.NoError(t, err)
	assert.Equal(t, testState().Lease.ID, st.Lease.ID)
}

func TestConnect_WithoutDeviceRefusesBeforeContactingTheGateway(t *testing.T) {
	f := newFixture(t)
	dialed := false
	a, err := New(Deps{Posture: f.posture, State: f.state, DataPlanes: []DataPlane{f.masque},
		Dial: func(string, tls.Certificate) (Gateway, error) { dialed = true; return f.gateway, nil }})
	require.NoError(t, err)

	_, err = a.Connect(context.Background(), ConnectOptions{Gateway: "gw.example:4433", TenantID: "acme"})
	var noDevice *ErrNoDevice
	require.ErrorAs(t, err, &noDevice)
	assert.False(t, dialed, "no gateway is dialled without a device identity")
	assert.Nil(t, f.state.st, "nothing is saved")
	assert.Equal(t, ExitFailure, ExitCode(err))
}
