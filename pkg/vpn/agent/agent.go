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

// Package agent is the remote-access VPN client agent behind
// `platformctl vpn connect|disconnect|lease` (docs/vpn/cli.md): it runs the
// admission against a gateway's admission listener — mTLS with the IDevID,
// a quote over the gateway's nonce, the posture report, the person factor —
// and brings the leased data plane up. Everything that touches the TPM, the
// person's authenticator or the host network is behind an interface, so the
// orchestration is tested in memory.
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// Device is the enrolled machine: its IDevID and its TPM.
type Device interface {
	// ID is the device id the gateway's enrolment set names.
	ID() string
	// Certificate is the IDevID chain and its TPM-resident signer, presented
	// as the mTLS client certificate.
	Certificate() (tls.Certificate, error)
	// Quote is a TPM quote whose qualifying data is nonce, exactly.
	Quote(ctx context.Context, nonce []byte) (*manifest.HostAttestation, error)
}

// PostureSource collects the posture report the gateway's policy judges.
type PostureSource interface {
	Collect(ctx context.Context) (*gwvpn.PostureReport, error)
}

// FactorSigner obtains the person's presence proof over nonce.
type FactorSigner interface {
	Sign(ctx context.Context, kind gwvpn.PersonFactorKind, nonce []byte) (*gwvpn.PersonFactor, error)
}

// DataPlane is the client side of one data plane.
type DataPlane interface {
	Kind() gwvpn.DataPlaneKind
	// Prepare returns the client key the admission request carries.
	Prepare(ctx context.Context) (gwvpn.PeerWire, error)
	// Up brings the tunnel up for lease. A failed Up leaves nothing up.
	Up(ctx context.Context, lease *gwvpn.LeaseWire) (Session, error)
	// Down tears down what Up brought up.
	Down(ctx context.Context, session Session) error
}

// Gateway is a gateway's admission listener.
type Gateway interface {
	Challenge(ctx context.Context) (*gwvpn.ChallengeWire, error)
	Admit(ctx context.Context, req *gwvpn.AdmissionRequestWire) (*gwvpn.LeaseWire, error)
	Revoke(ctx context.Context, id gwvpn.LeaseID) error
}

// GatewayDialer returns the admission listener at addr, presenting cert.
type GatewayDialer func(addr string, cert tls.Certificate) (Gateway, error)

// StateStore records the lease the agent holds.
type StateStore interface {
	// Load returns ErrNotConnected when no lease is recorded.
	Load() (*State, error)
	Save(st *State) error
	Remove() error
}

// Deps are the agent's collaborators. Factors may be nil when this host has
// no person factor; a connect that asks for one is then refused locally.
type Deps struct {
	Device     Device
	Posture    PostureSource
	Factors    FactorSigner
	DataPlanes []DataPlane
	State      StateStore
	Dial       GatewayDialer
	Now        func() time.Time
}

// ConnectOptions are the connect verb's flags.
type ConnectOptions struct {
	// Gateway is the admission listener, host:port.
	Gateway string
	// DataPlane is the plane to request; empty takes the gateway's
	// preference among the planes this build has.
	DataPlane gwvpn.DataPlaneKind
	// Factor is the person factor to present; empty presents none.
	Factor gwvpn.PersonFactorKind
	// Zones narrows the zones the lease reaches; empty asks for every zone
	// the enrolment allows.
	Zones []string
}

// Agent runs the client verbs.
type Agent struct {
	deps   Deps
	planes map[gwvpn.DataPlaneKind]DataPlane
}

// rollbackTimeout bounds the revoke and teardown that undo an admission
// Connect could not complete.
const rollbackTimeout = 10 * time.Second

// knownFactors are the person factors the gateway verifies.
var knownFactors = map[gwvpn.PersonFactorKind]bool{
	gwvpn.PersonFactorFIDO2: true,
	gwvpn.PersonFactorPIV:   true,
}

// New returns an agent over deps.
func New(deps Deps) (*Agent, error) {
	required := []struct {
		name    string
		missing bool
	}{
		{"device", deps.Device == nil},
		{"posture source", deps.Posture == nil},
		{"state store", deps.State == nil},
		{"gateway dialer", deps.Dial == nil},
		{"data planes", len(deps.DataPlanes) == 0},
	}
	for _, r := range required {
		if r.missing {
			return nil, &ErrInvalidOptions{Field: r.name, Reason: "required"}
		}
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	planes := make(map[gwvpn.DataPlaneKind]DataPlane, len(deps.DataPlanes))
	for _, p := range deps.DataPlanes {
		planes[p.Kind()] = p
	}
	return &Agent{deps: deps, planes: planes}, nil
}

// Connect runs the admission against opts.Gateway and brings the leased data
// plane up. A failure after admission revokes the lease, so the gateway is
// never left holding a lease no tunnel uses; the revoke runs on its own
// bounded context, so a cancelled or expired ctx does not stop it.
func (a *Agent) Connect(ctx context.Context, opts ConnectOptions) (*State, error) {
	if opts.Gateway == "" {
		return nil, &ErrInvalidOptions{Field: "gateway", Reason: "required"}
	}
	if opts.Factor != "" && !knownFactors[opts.Factor] {
		return nil, &ErrInvalidOptions{Field: "factor", Reason: "want fido2 or piv, got " + string(opts.Factor)}
	}
	if opts.Factor != "" && a.deps.Factors == nil {
		return nil, &ErrInvalidOptions{Field: "factor", Reason: "this host has no person factor signer"}
	}
	if err := a.ensureDisconnected(); err != nil {
		return nil, err
	}
	gw, err := a.dial(opts.Gateway)
	if err != nil {
		return nil, err
	}
	challenge, err := gw.Challenge(ctx)
	if err != nil {
		return nil, err
	}
	plane, err := a.pickPlane(opts, challenge.DataPlanes)
	if err != nil {
		return nil, err
	}
	req, err := a.admissionRequest(ctx, opts, challenge.Nonce, plane)
	if err != nil {
		return nil, err
	}
	lease, err := gw.Admit(ctx, req)
	if err != nil {
		return nil, err
	}
	if lease.ID == "" || lease.DataPlane != plane.Kind() {
		cause := &ErrInvalidResponse{Gateway: opts.Gateway, Reason: "lease without an id or on another data plane"}
		return nil, a.revokeAfter(ctx, gw, lease.ID, cause, nil)
	}
	session, err := plane.Up(ctx, lease)
	if err != nil {
		return nil, a.revokeAfter(ctx, gw, lease.ID, &ErrDataPlane{Op: "up", Kind: plane.Kind(), Cause: err}, nil)
	}
	st := &State{Gateway: opts.Gateway, Lease: *lease, Session: session, ConnectedAt: a.deps.Now().UTC()}
	if err := a.deps.State.Save(st); err != nil {
		teardown := func(undoCtx context.Context) error { return down(undoCtx, plane, session) }
		return nil, a.revokeAfter(ctx, gw, lease.ID, err, teardown)
	}
	return st, nil
}

// Disconnect revokes the held lease and tears its data plane down. A lease
// the gateway no longer knows is already gone, so its refusal is not an
// error. The state is kept when the tunnel could not be torn down, so the
// verb can be run again.
func (a *Agent) Disconnect(ctx context.Context) (*State, error) {
	st, err := a.deps.State.Load()
	if err != nil {
		return nil, err
	}
	revokeErr := a.revoke(ctx, st)
	plane, ok := a.planes[st.Lease.DataPlane]
	if !ok {
		return nil, errors.Join(revokeErr, &ErrDataPlaneUnsupported{Kind: st.Lease.DataPlane})
	}
	if err := down(ctx, plane, st.Session); err != nil {
		return nil, errors.Join(revokeErr, err)
	}
	if err := a.deps.State.Remove(); err != nil {
		return nil, errors.Join(revokeErr, err)
	}
	if revokeErr != nil {
		return nil, revokeErr
	}
	return st, nil
}

// Lease returns the held lease, or ErrNotConnected.
func (a *Agent) Lease() (*State, error) {
	return a.deps.State.Load()
}

// ensureDisconnected refuses a second connect while a lease is recorded.
func (a *Agent) ensureDisconnected() error {
	st, err := a.deps.State.Load()
	var notConnected *ErrNotConnected
	switch {
	case errors.As(err, &notConnected):
		return nil
	case err != nil:
		return err
	default:
		return &ErrAlreadyConnected{Gateway: st.Gateway, LeaseID: st.Lease.ID}
	}
}

// dial opens the admission listener with the device's IDevID.
func (a *Agent) dial(addr string) (Gateway, error) {
	cert, err := a.deps.Device.Certificate()
	if err != nil {
		return nil, &ErrEvidence{Step: "device certificate", Cause: err}
	}
	return a.deps.Dial(addr, cert)
}

// pickPlane returns the requested plane, or the first plane the gateway
// offers that this build has a client for.
func (a *Agent) pickPlane(opts ConnectOptions, offered []gwvpn.DataPlaneKind) (DataPlane, error) {
	if opts.DataPlane != "" {
		plane, ok := a.planes[opts.DataPlane]
		if !ok {
			return nil, &ErrDataPlaneUnsupported{Kind: opts.DataPlane}
		}
		return plane, nil
	}
	if len(offered) == 0 {
		return nil, &ErrInvalidResponse{Gateway: opts.Gateway, Reason: "challenge offers no data plane"}
	}
	i := slices.IndexFunc(offered, func(k gwvpn.DataPlaneKind) bool { return a.planes[k] != nil })
	if i < 0 {
		return nil, &ErrDataPlaneUnsupported{Kind: offered[0]}
	}
	return a.planes[offered[i]], nil
}

// admissionRequest collects the evidence, each piece bound to nonce where the
// gateway verifies a binding.
func (a *Agent) admissionRequest(ctx context.Context, opts ConnectOptions, nonce []byte, plane DataPlane) (*gwvpn.AdmissionRequestWire, error) {
	att, err := a.deps.Device.Quote(ctx, nonce)
	if err != nil {
		return nil, &ErrEvidence{Step: "quote", Cause: err}
	}
	posture, err := a.deps.Posture.Collect(ctx)
	if err != nil {
		return nil, &ErrEvidence{Step: "posture", Cause: err}
	}
	var factor *gwvpn.PersonFactor
	if opts.Factor != "" {
		if factor, err = a.deps.Factors.Sign(ctx, opts.Factor, nonce); err != nil {
			return nil, &ErrEvidence{Step: "person factor", Cause: err}
		}
	}
	peer, err := plane.Prepare(ctx)
	if err != nil {
		return nil, &ErrDataPlane{Op: "prepare", Kind: plane.Kind(), Cause: err}
	}
	return &gwvpn.AdmissionRequestWire{
		DeviceID:     a.deps.Device.ID(),
		Nonce:        nonce,
		Attestation:  gwvpn.AttestationFromHost(att),
		Posture:      posture,
		PersonFactor: gwvpn.PersonFactorToWire(factor),
		DataPlane:    plane.Kind(),
		Peer:         peer,
		Zones:        opts.Zones,
	}, nil
}

// revokeAfter undoes an admission Connect could not complete: it runs
// teardown when there is one, revokes the lease, and returns cause with any
// undo failure attached. The undo runs on a rollbackContext made here, when
// the cleanup begins, so the time setup took does not count against its bound.
func (a *Agent) revokeAfter(ctx context.Context, gw Gateway, id gwvpn.LeaseID, cause error, teardown func(context.Context) error) error {
	ctx, cancel := rollbackContext(ctx)
	defer cancel()
	var failures []error
	if teardown != nil {
		if err := teardown(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if id != "" {
		if err := gw.Revoke(ctx, id); err != nil {
			failures = append(failures, err)
		}
	}
	if rollback := errors.Join(failures...); rollback != nil {
		return &ErrRollback{Cause: cause, Rollback: rollback}
	}
	return cause
}

// rollbackContext returns the context Connect's undo runs on. It keeps ctx's
// values but not its cancellation: a connect cancelled or timed out after
// admission must still revoke the lease and tear the tunnel down, or the
// gateway holds the peer and its address until the lease expires. The undo
// is bounded by rollbackTimeout instead.
func rollbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
}

// down tears the plane's session down, returning nil or an ErrDataPlane.
func down(ctx context.Context, plane DataPlane, session Session) error {
	if err := plane.Down(ctx, session); err != nil {
		return &ErrDataPlane{Op: "down", Kind: plane.Kind(), Cause: err}
	}
	return nil
}

// goneClasses are the refusals that mean the lease is already gone.
var goneClasses = map[gwvpn.RefusalClass]bool{
	gwvpn.RefusalLeaseNotFound: true,
	gwvpn.RefusalLeaseExpired:  true,
}

// revoke ends the held lease at its gateway, treating a lease the gateway no
// longer holds as revoked.
func (a *Agent) revoke(ctx context.Context, st *State) error {
	gw, err := a.dial(st.Gateway)
	if err != nil {
		return err
	}
	err = gw.Revoke(ctx, st.Lease.ID)
	var refused *RefusedError
	if errors.As(err, &refused) && goneClasses[refused.Class] {
		return nil
	}
	return err
}
