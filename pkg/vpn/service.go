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

// Package vpn is the control-plane side of the remote-access VPN (#584): the
// operator surface that enrols peers, holds the tenant posture policies,
// reports the session state the gateways send back, and composes the vpn
// section of every gateway's desired configuration. The admission pipeline
// itself runs on the gateway (pkg/sdn/gateway/services/vpn); this package
// decides who may be admitted and reads back what happened.
package vpn

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	vpncore "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	// maxIDLength bounds tenant, device and zone identifiers.
	maxIDLength = 256
	// maxPolicyNameLength bounds a posture policy name, which is a URL path
	// segment and a gateway configuration value.
	maxPolicyNameLength = 64
	// maxModuleBytes bounds a posture policy module.
	maxModuleBytes = 64 << 10
	// listPageSize is the page size the store is read with.
	listPageSize = 1000
)

// GatewayStatus is one gateway's last reported VPN session state.
type GatewayStatus struct {
	GatewayID  string
	ReportedAt time.Time
	// VPN is nil when the gateway does not run the VPN service.
	VPN *gwstate.VPNState
}

// snapshotSource holds the gateway telemetry store behind an atomic pointer.
type snapshotSource struct {
	store gwstate.Store
}

// Service is the VPN control-plane service. Peers and posture policies are
// tenant-scoped records in the platform store; session status is read from
// the gateway telemetry store.
type Service struct {
	peers     *quicbaas.GenericDAO[*Peer]
	policies  *quicbaas.GenericDAO[*PosturePolicy]
	leases    *LeaseStore
	snapshots atomic.Pointer[snapshotSource]
	now       func() time.Time
}

// NewService builds the service over the platform store. The gateway
// telemetry store is set separately: without one, Status is unavailable.
func NewService(storage quicbaas.Storage, logger *logging.Logger) (*Service, error) {
	if storage == nil {
		return nil, &ErrMissingDependency{Name: "a platform store"}
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	leases, err := NewLeaseStore(storage, logger)
	if err != nil {
		return nil, err
	}
	return &Service{
		peers: quicbaas.NewGenericDAO[*Peer](storage, entityTypePeer,
			func() *Peer { return &Peer{} }, logger),
		policies: quicbaas.NewGenericDAO[*PosturePolicy](storage, entityTypePosturePolicy,
			func() *PosturePolicy { return &PosturePolicy{} }, logger),
		leases: leases,
		now:    time.Now,
	}, nil
}

// SetGatewaySnapshotStore wires the store the gateways' telemetry reports
// land in; Status reads the vpn section of each snapshot from it.
func (s *Service) SetGatewaySnapshotStore(store gwstate.Store) {
	if store == nil {
		s.snapshots.Store(nil)
		return
	}
	s.snapshots.Store(&snapshotSource{store: store})
}

// EnrolPeer enrols a device as a VPN peer of its tenant, or replaces the
// zones of an existing enrolment. The gateways pick the change up on their
// next desired-config pull.
func (s *Service) EnrolPeer(ctx context.Context, peer Peer) (*Peer, error) {
	if err := validateID("tenant_id", peer.TenantID); err != nil {
		return nil, err
	}
	if err := validateID("device_id", peer.DeviceID); err != nil {
		return nil, err
	}
	if err := validateZones(peer.Zones); err != nil {
		return nil, err
	}
	record := &Peer{
		ID:         recordID(entityTypePeer, peer.TenantID, peer.DeviceID),
		TenantID:   peer.TenantID,
		DeviceID:   peer.DeviceID,
		Zones:      slices.Clone(peer.Zones),
		EnrolledAt: s.now().UTC(),
	}
	stored, err := s.peer(ctx, record)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		record.EnrolledAt = stored.EnrolledAt
	}
	if err := s.peers.Save(ctx, record); err != nil {
		return nil, &ErrStoreUnavailable{Op: "save peer", Cause: err}
	}
	return record, nil
}

// ListPeers returns the enrolled peers sorted by tenant and device; every
// tenant's when tenantID is empty.
func (s *Service) ListPeers(ctx context.Context, tenantID string) ([]*Peer, error) {
	peers, err := listAll(ctx, s.peers, func(p *Peer) bool {
		return tenantID == "" || p.TenantID == tenantID
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(peers, func(a, b *Peer) int { return strings.Compare(a.key(), b.key()) })
	return peers, nil
}

// RevokePeer removes a device's enrolment. On their next pull the gateways
// revoke the device's live leases and refuse its admissions.
func (s *Service) RevokePeer(ctx context.Context, tenantID, deviceID string) error {
	if err := validateID("tenant_id", tenantID); err != nil {
		return err
	}
	if err := validateID("device_id", deviceID); err != nil {
		return err
	}
	probe := &Peer{ID: recordID(entityTypePeer, tenantID, deviceID), TenantID: tenantID, DeviceID: deviceID}
	stored, err := s.peer(ctx, probe)
	if err != nil {
		return err
	}
	if stored == nil {
		return &ErrPeerNotFound{TenantID: tenantID, DeviceID: deviceID}
	}
	if err := s.peers.Delete(ctx, stored); err != nil {
		return &ErrStoreUnavailable{Op: "delete peer", Cause: err}
	}
	return nil
}

// GetPosturePolicy returns a tenant's posture policy.
func (s *Service) GetPosturePolicy(ctx context.Context, tenantID, name string) (*PosturePolicy, error) {
	if err := validateID("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if err := validatePolicyName(name); err != nil {
		return nil, err
	}
	probe := &PosturePolicy{ID: recordID(entityTypePosturePolicy, tenantID, name), TenantID: tenantID, Name: name}
	stored, err := s.policy(ctx, probe)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, &ErrPosturePolicyNotFound{TenantID: tenantID, Name: name}
	}
	return stored, nil
}

// SetPosturePolicy creates or replaces a tenant's posture policy. The module
// is compiled exactly as a gateway compiles it before anything is stored, so
// a policy that would refuse every one of the tenant's admissions is refused
// here instead.
func (s *Service) SetPosturePolicy(ctx context.Context, policy PosturePolicy) (*PosturePolicy, error) {
	if err := validateID("tenant_id", policy.TenantID); err != nil {
		return nil, err
	}
	if err := validatePolicyName(policy.Name); err != nil {
		return nil, err
	}
	if len(policy.Module) > maxModuleBytes {
		return nil, &ErrInvalidArgument{Field: "module", Reason: "longer than " + strconv.Itoa(maxModuleBytes) + " bytes"}
	}
	if _, err := vpncore.CompilePosturePolicy(ctx, vpncore.PosturePolicy{
		TenantID: policy.TenantID, Name: policy.Name, Module: policy.Module,
	}); err != nil {
		var invalid *vpncore.ErrPosturePolicyInvalid
		if errors.As(err, &invalid) {
			return nil, &ErrInvalidPosturePolicy{TenantID: policy.TenantID, Name: policy.Name, Reason: invalid.Reason}
		}
		return nil, &ErrPolicyEngineUnavailable{Cause: err}
	}
	record := &PosturePolicy{
		ID:        recordID(entityTypePosturePolicy, policy.TenantID, policy.Name),
		TenantID:  policy.TenantID,
		Name:      policy.Name,
		Module:    policy.Module,
		UpdatedAt: s.now().UTC(),
	}
	if _, err := s.policy(ctx, record); err != nil {
		return nil, err
	}
	if err := s.policies.Save(ctx, record); err != nil {
		return nil, &ErrStoreUnavailable{Op: "save posture policy", Cause: err}
	}
	return record, nil
}

// DeletePosturePolicy removes a tenant's posture policy; the tenant's peers
// are judged by the gateway default again.
func (s *Service) DeletePosturePolicy(ctx context.Context, tenantID, name string) error {
	stored, err := s.GetPosturePolicy(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if err := s.policies.Delete(ctx, stored); err != nil {
		return &ErrStoreUnavailable{Op: "delete posture policy", Cause: err}
	}
	return nil
}

// ListPosturePolicies returns the posture policies sorted by tenant and
// name; every tenant's when tenantID is empty.
func (s *Service) ListPosturePolicies(ctx context.Context, tenantID string) ([]*PosturePolicy, error) {
	policies, err := listAll(ctx, s.policies, func(p *PosturePolicy) bool {
		return tenantID == "" || p.TenantID == tenantID
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(policies, func(a, b *PosturePolicy) int { return strings.Compare(a.key(), b.key()) })
	return policies, nil
}

// Status returns the VPN session state each gateway last reported, sorted by
// gateway; only gatewayID's when it is set.
func (s *Service) Status(ctx context.Context, gatewayID string) ([]GatewayStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	src := s.snapshots.Load()
	if src == nil {
		return nil, &ErrStatusUnavailable{Reason: "no gateway telemetry store is wired; gateways report through the REST control plane"}
	}
	if gatewayID != "" {
		snap, err := src.store.Get(gatewayID)
		if err != nil {
			var nf gwstate.ErrSnapshotNotFound
			if errors.As(err, &nf) {
				return nil, &ErrGatewayNotFound{GatewayID: gatewayID}
			}
			return nil, &ErrStoreUnavailable{Op: "read gateway snapshot", Cause: err}
		}
		return []GatewayStatus{gatewayStatus(snap)}, nil
	}
	snaps, err := src.store.List()
	if err != nil {
		return nil, &ErrStoreUnavailable{Op: "list gateway snapshots", Cause: err}
	}
	out := make([]GatewayStatus, 0, len(snaps))
	for _, snap := range snaps {
		out = append(out, gatewayStatus(snap))
	}
	slices.SortFunc(out, func(a, b GatewayStatus) int { return strings.Compare(a.GatewayID, b.GatewayID) })
	return out, nil
}

// DesiredVPN is the vpn section of gatewayID's desired configuration: the
// whole enrolment set, every tenant posture policy, and the live leases
// gatewayID recorded, which it rebuilds its lease projection from on start.
// Expired leases are swept first, so none is served. It is never nil — an
// empty set is how a revocation of the last peer reaches the gateways.
func (s *Service) DesiredVPN(ctx context.Context, gatewayID string) (*gwstate.DesiredVPN, error) {
	if _, err := s.leases.Sweep(ctx); err != nil {
		return nil, err
	}
	leases, err := s.leases.ListByGateway(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	peers, err := s.ListPeers(ctx, "")
	if err != nil {
		return nil, err
	}
	policies, err := s.ListPosturePolicies(ctx, "")
	if err != nil {
		return nil, err
	}
	section := &gwstate.DesiredVPN{
		Peers:           make([]gwstate.DesiredVPNPeer, 0, len(peers)),
		PosturePolicies: make([]gwstate.DesiredVPNPosturePolicy, 0, len(policies)),
	}
	for _, p := range peers {
		section.Peers = append(section.Peers, gwstate.DesiredVPNPeer{
			TenantID: p.TenantID, DeviceID: p.DeviceID, Zones: slices.Clone(p.Zones),
		})
	}
	for _, p := range policies {
		section.PosturePolicies = append(section.PosturePolicies, gwstate.DesiredVPNPosturePolicy{
			TenantID: p.TenantID, Name: p.Name, Module: p.Module,
		})
	}
	for _, l := range leases {
		section.Leases = append(section.Leases, desiredLease(l))
	}
	return section, nil
}

// RecordGatewayLease records a lease gatewayID admitted or renewed, so the
// gateway can rebuild it after a restart. A lease another gateway issued is
// refused with ErrLeaseOwnedByOtherGateway.
func (s *Service) RecordGatewayLease(ctx context.Context, gatewayID string, lease *gwstate.DesiredVPNLease) error {
	if lease == nil {
		return &ErrInvalidArgument{Field: "lease", Reason: "required"}
	}
	address, err := netip.ParsePrefix(lease.Address)
	if err != nil {
		return &ErrInvalidArgument{Field: "address", Reason: err.Error()}
	}
	_, err = s.leases.Put(ctx, Lease{
		LeaseID:                 lease.ID,
		GatewayID:               gatewayID,
		TenantID:                lease.TenantID,
		DeviceID:                lease.DeviceID,
		Address:                 address,
		Zones:                   lease.Zones,
		DataPlane:               vpncore.DataPlaneKind(lease.DataPlane),
		WireGuardPublicKey:      lease.WireGuardPublicKey,
		ClientCertificateSHA256: lease.ClientCertificateSHA256,
		IssuedAt:                lease.IssuedAt,
		ExpiresAt:               lease.ExpiresAt,
		Renewals:                lease.Renewals,
		Verdict: vpncore.VerdictSummary{
			Passed:        lease.Verdict.Passed,
			Cryptographic: lease.Verdict.Cryptographic,
			ProfileID:     lease.Verdict.ProfileID,
		},
	})
	return err
}

// ReleaseGatewayLease forgets the tenant's lease leaseID that gatewayID
// revoked. A lease already gone is released, so a retried release succeeds;
// a lease another gateway issued is refused with ErrLeaseOwnedByOtherGateway.
func (s *Service) ReleaseGatewayLease(ctx context.Context, gatewayID, tenantID, leaseID string) error {
	err := s.leases.Delete(ctx, gatewayID, tenantID, leaseID)
	var notFound *vpncore.ErrLeaseNotFound
	if errors.As(err, &notFound) {
		return nil
	}
	return err
}

// desiredLease is a recorded lease as the gateway's desired configuration
// carries it.
func desiredLease(l *Lease) gwstate.DesiredVPNLease {
	return gwstate.DesiredVPNLease{
		ID:                      l.LeaseID,
		TenantID:                l.TenantID,
		DeviceID:                l.DeviceID,
		Address:                 l.Address.String(),
		Zones:                   slices.Clone(l.Zones),
		DataPlane:               string(l.DataPlane),
		WireGuardPublicKey:      slices.Clone(l.WireGuardPublicKey),
		ClientCertificateSHA256: slices.Clone(l.ClientCertificateSHA256),
		IssuedAt:                l.IssuedAt,
		ExpiresAt:               l.ExpiresAt,
		Renewals:                l.Renewals,
		Verdict: gwstate.DesiredVPNVerdict{
			Passed:        l.Verdict.Passed,
			Cryptographic: l.Verdict.Cryptographic,
			ProfileID:     l.Verdict.ProfileID,
		},
	}
}

// peer reads the record the probe's ID names: nil when there is none, and a
// collision when it belongs to another key.
func (s *Service) peer(ctx context.Context, probe *Peer) (*Peer, error) {
	stored, err := getRecord(ctx, s.peers, probe.ID)
	if err != nil || stored == nil {
		return nil, err
	}
	if stored.key() != probe.key() {
		return nil, &ErrKeyCollision{Kind: "peer", Key: probe.key(), Stored: stored.key()}
	}
	return stored, nil
}

// policy reads the record the probe's ID names: nil when there is none, and
// a collision when it belongs to another key.
func (s *Service) policy(ctx context.Context, probe *PosturePolicy) (*PosturePolicy, error) {
	stored, err := getRecord(ctx, s.policies, probe.ID)
	if err != nil || stored == nil {
		return nil, err
	}
	if stored.key() != probe.key() {
		return nil, &ErrKeyCollision{Kind: "posture policy", Key: probe.key(), Stored: stored.key()}
	}
	return stored, nil
}

// getRecord reads one record; a missing record is (nil, nil).
func getRecord[E entities.KeyValueEntity](ctx context.Context, dao *quicbaas.GenericDAO[E], id uint64) (E, error) {
	var zero E
	stored, err := dao.Get(ctx, id)
	if err != nil {
		var nf quicbaas.ErrNotFound
		if errors.As(err, &nf) {
			return zero, nil
		}
		return zero, &ErrStoreUnavailable{Op: "get", Cause: err}
	}
	return stored, nil
}

// listAll reads every record keep accepts.
func listAll[E entities.KeyValueEntity](ctx context.Context, dao *quicbaas.GenericDAO[E], keep func(E) bool) ([]E, error) {
	var out []E
	err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: listPageSize}, func(page datastore.PageResult[E]) error {
		for _, e := range page.Entities {
			if keep(e) {
				out = append(out, e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &ErrStoreUnavailable{Op: "list", Cause: err}
	}
	return out, nil
}

// gatewayStatus is a snapshot's VPN view.
func gatewayStatus(snap *gwstate.Snapshot) GatewayStatus {
	return GatewayStatus{GatewayID: snap.GatewayID, ReportedAt: snap.ReportedAt, VPN: snap.VPN}
}

// validateID checks a tenant, device or zone identifier.
func validateID(field, value string) error {
	switch {
	case value == "":
		return &ErrInvalidArgument{Field: field, Reason: "required"}
	case len(value) > maxIDLength:
		return &ErrInvalidArgument{Field: field, Reason: "longer than " + strconv.Itoa(maxIDLength) + " bytes"}
	case strings.ContainsFunc(value, unicode.IsControl):
		return &ErrInvalidArgument{Field: field, Reason: "contains a control character"}
	}
	return nil
}

// validateZones checks each zone and refuses duplicates.
func validateZones(zones []string) error {
	seen := make(map[string]bool, len(zones))
	for i, z := range zones {
		field := "zones[" + strconv.Itoa(i) + "]"
		if err := validateID(field, z); err != nil {
			return err
		}
		if seen[z] {
			return &ErrInvalidArgument{Field: field, Reason: "duplicate zone " + z}
		}
		seen[z] = true
	}
	return nil
}

// validatePolicyName checks a posture policy name: letters, digits, '_',
// '-' and '.', because the name is a URL path segment and a gateway
// configuration value.
func validatePolicyName(name string) error {
	if name == "" {
		return &ErrInvalidArgument{Field: "name", Reason: "required"}
	}
	if len(name) > maxPolicyNameLength {
		return &ErrInvalidArgument{Field: "name", Reason: "longer than " + strconv.Itoa(maxPolicyNameLength) + " bytes"}
	}
	for _, r := range name {
		if !isPolicyNameRune(r) {
			return &ErrInvalidArgument{Field: "name", Reason: "may contain only letters, digits, '_', '-' and '.'"}
		}
	}
	return nil
}

func isPolicyNameRune(r rune) bool {
	return r == '_' || r == '-' || r == '.' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
