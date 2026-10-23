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
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// VPNLeaseControl is the control plane as the management VPN's leases see
// it: the desired-config pull the gateway rebuilds its leases from on start,
// and the write-through of every admission, renewal and revocation.
// controlplane.Reporter implements it.
type VPNLeaseControl interface {
	FetchDesiredConfig(ctx context.Context) (*gwstate.DesiredConfig, error)
	PutVPNLease(ctx context.Context, lease *gwstate.DesiredVPNLease) error
	// DeleteVPNLease succeeds for a lease the control plane no longer holds.
	DeleteVPNLease(ctx context.Context, tenantID, leaseID string) error
}

// SetVPNLeaseControl makes the control plane the record of the management
// VPN's leases: the service rebuilds them from it on start and writes every
// change through to it, so a restart does not forget the admitted clients.
// journal keeps the revocations the control plane has not yet taken, so a
// restart does not reinstate them either; without one the service refuses to
// build. Without a control plane the leases live in the gateway's memory
// only. Set it before Start; the service reads it when it is assembled.
func (g *Gateway) SetVPNLeaseControl(control VPNLeaseControl, journal *RevocationJournal) {
	g.vpnMu.Lock()
	defer g.vpnMu.Unlock()
	g.vpnLeaseControl = control
	g.vpnRevocations = journal
}

// vpnLeaseControlSet returns the control plane and the revocation journal
// set by SetVPNLeaseControl.
func (g *Gateway) vpnLeaseControlSet() (VPNLeaseControl, *RevocationJournal) {
	g.vpnMu.Lock()
	defer g.vpnMu.Unlock()
	return g.vpnLeaseControl, g.vpnRevocations
}

// projectedLeaseStore is the gateway's lease store when the control plane
// keeps the record: reads are served from the local projection, and every
// write lands in the control plane before the projection, so the projection
// never holds a lease the control plane does not. A write the control plane
// refuses is ErrLeaseStoreUnavailable.
//
// The journal is what a restart trusts over the control plane: a lease it
// names is revoked, and stays out of the rebuilt projection. An admission is
// journaled before its PUT is sent and cleared once both the control plane
// and the projection hold it, so a PUT that commits while its answer is lost,
// or a projection that refuses the lease after the control plane took it,
// leaves a record a restart revokes instead of restoring. The failed
// admission is withdrawn at once: its DELETE is sent, and stays pending when
// the control plane refuses it. A refused renewal leaves the projection
// unchanged.
//
// A revocation is journaled before the lease leaves the projection. If the
// DELETE is refused after that, the lease is gone from the projection and
// the DELETE stays pending until the expiry sweep retries it; retrying the
// DELETE alone means the lease is never torn down twice, so the retry cannot
// remove a peer or release an address that a later lease now holds. If the
// journal cannot be written, the revocation is durable only once the
// control plane takes the DELETE; when it refuses too, the lease is kept and
// the revocation is ErrRevocationNotRecorded, because dropping it would
// leave the revocation in this process's memory alone and a restart would
// reinstate it.
type projectedLeaseStore struct {
	local   vpn.LeaseStore
	control VPNLeaseControl
	journal *RevocationJournal

	// mu guards pending, which maps each lease awaiting its control-plane
	// DELETE to the tenant that holds the lease; admitting, which maps each
	// admission whose PUT may be in flight the same way; and the journal
	// writes that mirror both.
	mu        sync.Mutex
	pending   map[vpn.LeaseID]string
	admitting map[vpn.LeaseID]string
}

// Put writes an admission or a renewal through to the control plane. A lease
// the projection does not hold yet is an admission.
func (p *projectedLeaseStore) Put(ctx context.Context, lease *vpn.Lease) error {
	_, err := p.local.Get(ctx, lease.ID)
	var nf *vpn.ErrLeaseNotFound
	if errors.As(err, &nf) {
		return p.admit(ctx, lease)
	}
	if err != nil {
		return err
	}
	if err := p.control.PutVPNLease(ctx, desiredLease(lease)); err != nil {
		return &vpn.ErrLeaseStoreUnavailable{Cause: err}
	}
	return p.local.Put(ctx, lease)
}

// admit records a new lease. Nothing is sent before the admission is
// journaled; once it is, any failure withdraws the lease from the control
// plane.
func (p *projectedLeaseStore) admit(ctx context.Context, lease *vpn.Lease) error {
	if err := p.markAdmitting(lease.ID, lease.TenantID); err != nil {
		return &vpn.ErrLeaseStoreUnavailable{Cause: err}
	}
	if err := p.control.PutVPNLease(ctx, desiredLease(lease)); err != nil {
		return &vpn.ErrLeaseStoreUnavailable{Cause: errors.Join(err, p.withdraw(ctx, lease))}
	}
	if err := p.local.Put(ctx, lease); err != nil {
		return &vpn.ErrLeaseStoreUnavailable{Cause: errors.Join(err, p.withdraw(ctx, lease))}
	}
	if err := p.admitted(lease.ID); err != nil {
		// The journal still names the lease, so a restart would revoke it:
		// withdraw it now rather than serve a lease a restart disagrees with.
		return &vpn.ErrLeaseStoreUnavailable{Cause: errors.Join(err, p.local.Delete(ctx, lease.ID), p.withdraw(ctx, lease))}
	}
	return nil
}

// withdraw turns a failed admission into a pending revocation and sends its
// DELETE. The journal already names the lease, so the revocation is durable
// whether or not the DELETE lands.
func (p *projectedLeaseStore) withdraw(ctx context.Context, lease *vpn.Lease) error {
	p.mu.Lock()
	delete(p.admitting, lease.ID)
	if p.pending == nil {
		p.pending = make(map[vpn.LeaseID]string)
	}
	p.pending[lease.ID] = lease.TenantID
	p.mu.Unlock()
	if err := p.control.DeleteVPNLease(ctx, lease.TenantID, string(lease.ID)); err != nil {
		return err
	}
	return p.settle(lease.ID)
}

func (p *projectedLeaseStore) Delete(ctx context.Context, id vpn.LeaseID) error {
	lease, err := p.local.Get(ctx, id)
	if err != nil {
		return err
	}
	// Journaled before the projection lets the lease go: a restart before
	// the DELETE lands must not rebuild the lease the control plane still
	// records.
	if journalErr := p.markPending(id, lease.TenantID); journalErr != nil {
		if err := p.control.DeleteVPNLease(ctx, lease.TenantID, string(id)); err != nil {
			return &vpn.ErrLeaseStoreUnavailable{
				Cause: &vpn.ErrRevocationNotRecorded{LeaseID: id, Cause: errors.Join(err, journalErr)},
			}
		}
		return p.local.Delete(ctx, id)
	}
	if err := p.local.Delete(ctx, id); err != nil {
		return err
	}
	if err := p.control.DeleteVPNLease(ctx, lease.TenantID, string(id)); err != nil {
		return &vpn.ErrLeaseStoreUnavailable{Cause: err}
	}
	if err := p.settle(id); err != nil {
		return &vpn.ErrLeaseStoreUnavailable{Cause: err}
	}
	return nil
}

// RetryPendingDeletes sends the control-plane DELETE again for each
// revocation the control plane refused. It touches nothing else: those leases
// have no peer or address left to tear down. A DELETE that fails again stays
// pending for the next sweep.
func (p *projectedLeaseStore) RetryPendingDeletes(ctx context.Context) error {
	p.mu.Lock()
	pending := maps.Clone(p.pending)
	p.mu.Unlock()
	var errs []error
	for id, tenantID := range pending {
		if err := p.control.DeleteVPNLease(ctx, tenantID, string(id)); err != nil {
			errs = append(errs, &vpn.ErrLeaseStoreUnavailable{Cause: err})
			continue
		}
		if err := p.settle(id); err != nil {
			errs = append(errs, &vpn.ErrLeaseStoreUnavailable{Cause: err})
		}
	}
	return errors.Join(errs...)
}

// markPending records the revocation of id as pending, in memory and in the
// journal. A revocation the journal refuses is not kept in memory either, so
// memory never claims a durability the journal lacks.
func (p *projectedLeaseStore) markPending(id vpn.LeaseID, tenantID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = make(map[vpn.LeaseID]string)
	}
	_, already := p.pending[id]
	p.pending[id] = tenantID
	if err := p.saveLocked(); err != nil {
		if !already {
			delete(p.pending, id)
		}
		return err
	}
	return nil
}

// markAdmitting journals the admission of id before its PUT is sent. An
// admission the journal refuses is not attempted.
func (p *projectedLeaseStore) markAdmitting(id vpn.LeaseID, tenantID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.admitting == nil {
		p.admitting = make(map[vpn.LeaseID]string)
	}
	p.admitting[id] = tenantID
	if err := p.saveLocked(); err != nil {
		delete(p.admitting, id)
		return err
	}
	return nil
}

// admitted clears the admission of id, which the control plane and the
// projection both hold.
func (p *projectedLeaseStore) admitted(id vpn.LeaseID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	tenantID := p.admitting[id]
	delete(p.admitting, id)
	if err := p.saveLocked(); err != nil {
		p.admitting[id] = tenantID
		return err
	}
	return nil
}

// saveLocked writes every pending revocation and every admission in flight
// to the journal. The caller holds mu.
func (p *projectedLeaseStore) saveLocked() error {
	journaled := maps.Clone(p.pending)
	if journaled == nil {
		journaled = make(map[vpn.LeaseID]string, len(p.admitting))
	}
	maps.Copy(journaled, p.admitting)
	return p.journal.save(journaled)
}

// settle clears the revocation of id, whose DELETE has landed. A journal
// left holding it is harmless: the next start keeps a lease the control plane
// no longer records out, and its DELETE is sent again and succeeds.
func (p *projectedLeaseStore) settle(id vpn.LeaseID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, id)
	return p.saveLocked()
}

func (p *projectedLeaseStore) Get(ctx context.Context, id vpn.LeaseID) (*vpn.Lease, error) {
	return p.local.Get(ctx, id)
}

func (p *projectedLeaseStore) List(ctx context.Context) ([]*vpn.Lease, error) {
	return p.local.List(ctx)
}

func (p *projectedLeaseStore) FindByDevice(ctx context.Context, tenantID, deviceID string) (*vpn.Lease, bool, error) {
	return p.local.FindByDevice(ctx, tenantID, deviceID)
}

// rebuild loads the leases the control plane recorded for this gateway into
// the projection. They are already the record, so nothing is written back.
// A lease whose DELETE is pending, in memory or in the journal a previous
// process left, was revoked and stays out; so does an admission the previous
// process journaled and never cleared, whose DELETE becomes pending. A journal that cannot be read
// fails the rebuild: no recorded lease could be told apart from a revoked one.
func (p *projectedLeaseStore) rebuild(ctx context.Context, section *gwstate.DesiredVPN) error {
	journaled, err := p.journal.load()
	if err != nil {
		return err
	}
	p.mu.Lock()
	maps.Copy(journaled, p.pending)
	p.pending = journaled
	revoked := maps.Clone(p.pending)
	p.mu.Unlock()
	if section == nil {
		return nil
	}
	for i := range section.Leases {
		lease, err := projectedLease(i, &section.Leases[i])
		if err != nil {
			return err
		}
		if _, ok := revoked[lease.ID]; ok {
			continue
		}
		if err := p.local.Put(ctx, lease); err != nil {
			return err
		}
	}
	return nil
}

// desiredLease is lease as the control plane records it.
func desiredLease(lease *vpn.Lease) *gwstate.DesiredVPNLease {
	return &gwstate.DesiredVPNLease{
		ID:                      string(lease.ID),
		TenantID:                lease.TenantID,
		DeviceID:                lease.DeviceID,
		Address:                 lease.Address.String(),
		Zones:                   slices.Clone(lease.Zones),
		DataPlane:               string(lease.DataPlane),
		WireGuardPublicKey:      slices.Clone(lease.Keys.WireGuardPublicKey),
		ClientCertificateSHA256: slices.Clone(lease.Keys.ClientCertificateSHA256),
		IssuedAt:                lease.IssuedAt,
		ExpiresAt:               lease.ExpiresAt,
		Renewals:                lease.Renewals,
		Verdict: gwstate.DesiredVPNVerdict{
			Passed:        lease.Verdict.Passed,
			Cryptographic: lease.Verdict.Cryptographic,
			ProfileID:     lease.Verdict.ProfileID,
		},
	}
}

// projectedLease is the control plane's i-th recorded lease as the
// gateway's service holds it.
func projectedLease(i int, l *gwstate.DesiredVPNLease) (*vpn.Lease, error) {
	addr, err := netip.ParsePrefix(l.Address)
	if err != nil {
		return nil, &gwstate.ErrDesiredConfigInvalid{
			Field:  gwstate.SectionVPN + ".leases[" + strconv.Itoa(i) + "].address",
			Reason: err.Error(),
		}
	}
	return &vpn.Lease{
		ID:        vpn.LeaseID(l.ID),
		DeviceID:  l.DeviceID,
		TenantID:  l.TenantID,
		Address:   addr,
		Zones:     slices.Clone(l.Zones),
		DataPlane: vpn.DataPlaneKind(l.DataPlane),
		Keys: vpn.PeerKeys{
			WireGuardPublicKey:      slices.Clone(l.WireGuardPublicKey),
			ClientCertificateSHA256: slices.Clone(l.ClientCertificateSHA256),
		},
		IssuedAt:  l.IssuedAt,
		ExpiresAt: l.ExpiresAt,
		Renewals:  l.Renewals,
		Verdict: vpn.VerdictSummary{
			Passed:        l.Verdict.Passed,
			Cryptographic: l.Verdict.Cryptographic,
			ProfileID:     l.Verdict.ProfileID,
		},
	}, nil
}
