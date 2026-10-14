package vpn

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	vpncore "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// entityTypeLease is the platform-store entity type of a VPN lease.
const entityTypeLease = "VPNLease"

// wireGuardKeySize is the length of a Curve25519 WireGuard public key.
const wireGuardKeySize = 32

// Lease is a VPN lease as the control plane keeps it: the admission record
// the issuing gateway writes through, so a restarted gateway rebuilds its
// projection instead of forgetting every client. It holds no secret: the
// client's WireGuard public key and the SHA-256 fingerprint of the mTLS
// client certificate the admission ran under are public material.
type Lease struct {
	ID uint64 `json:"id"`
	// LeaseID is the gateway-issued lease identifier.
	LeaseID string `json:"lease_id"`
	// GatewayID is the gateway that admitted the lease and alone writes it.
	GatewayID string                `json:"gateway_id"`
	TenantID  string                `json:"tenant_id"`
	DeviceID  string                `json:"device_id"`
	Address   netip.Prefix          `json:"address"`
	Zones     []string              `json:"zones,omitempty"`
	DataPlane vpncore.DataPlaneKind `json:"data_plane"`
	// WireGuardPublicKey is the peer key the WireGuard plane programs.
	WireGuardPublicKey []byte `json:"wireguard_public_key,omitempty"`
	// ClientCertificateSHA256 is the fingerprint the MASQUE plane binds a
	// session by.
	ClientCertificateSHA256 []byte                 `json:"client_certificate_sha256,omitempty"`
	IssuedAt                time.Time              `json:"issued_at"`
	ExpiresAt               time.Time              `json:"expires_at"`
	Renewals                int                    `json:"renewals,omitempty"`
	Verdict                 vpncore.VerdictSummary `json:"verdict"`
}

// EntityID implements entities.KeyValueEntity.
func (l *Lease) EntityID() uint64 { return l.ID }

// SetEntityID implements entities.KeyValueEntity.
func (l *Lease) SetEntityID(id uint64) { l.ID = id }

// key is the lease's place in the tenant's namespace.
func (l *Lease) key() string { return "tenant/" + l.TenantID + "/vpn/lease/" + l.LeaseID }

// Expired reports whether the lease has run out at now, by the same rule the
// gateway's sweep applies.
func (l *Lease) Expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// LeaseStore keeps VPN leases in the platform store. Every read or write the
// store cannot complete is ErrLeaseStoreUnavailable, the refusal the gateway's
// admission pipeline already raises for its own lease store.
type LeaseStore struct {
	leases *quicbaas.GenericDAO[*Lease]
	now    func() time.Time
	// mu serializes each read-check-write of a record. The platform store
	// deletes by entity ID alone, with no conditional delete, so Sweep
	// re-reads an expired record under mu and a renewing Put cannot land
	// between that read and the delete.
	mu sync.Mutex
}

// NewLeaseStore returns a lease store over storage.
func NewLeaseStore(storage quicbaas.Storage, logger *logging.Logger) (*LeaseStore, error) {
	if storage == nil {
		return nil, &ErrMissingDependency{Name: "a platform store"}
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &LeaseStore{
		leases: quicbaas.NewGenericDAO[*Lease](storage, entityTypeLease,
			func() *Lease { return &Lease{} }, logger),
		now: time.Now,
	}, nil
}

// Put stores lease, replacing the stored copy. A lease another gateway issued
// is refused with ErrLeaseOwnedByOtherGateway.
func (s *LeaseStore) Put(ctx context.Context, lease Lease) (*Lease, error) {
	if err := validateLease(&lease); err != nil {
		return nil, err
	}
	record := lease
	record.ID = recordID(entityTypeLease, lease.TenantID, lease.LeaseID)
	record.Zones = slices.Clone(lease.Zones)
	record.WireGuardPublicKey = slices.Clone(lease.WireGuardPublicKey)
	record.ClientCertificateSHA256 = slices.Clone(lease.ClientCertificateSHA256)
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.lease(ctx, &record)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.GatewayID != record.GatewayID {
		return nil, &ErrLeaseOwnedByOtherGateway{TenantID: record.TenantID, LeaseID: record.LeaseID, GatewayID: record.GatewayID}
	}
	if err := s.leases.Save(ctx, &record); err != nil {
		return nil, &vpncore.ErrLeaseStoreUnavailable{Cause: err}
	}
	return &record, nil
}

// Get returns the tenant's lease leaseID, or ErrLeaseNotFound.
func (s *LeaseStore) Get(ctx context.Context, tenantID, leaseID string) (*Lease, error) {
	if err := validateID("tenant_id", tenantID); err != nil {
		return nil, err
	}
	if err := validateID("lease_id", leaseID); err != nil {
		return nil, err
	}
	probe := &Lease{ID: recordID(entityTypeLease, tenantID, leaseID), TenantID: tenantID, LeaseID: leaseID}
	stored, err := s.lease(ctx, probe)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, &vpncore.ErrLeaseNotFound{LeaseID: vpncore.LeaseID(leaseID)}
	}
	return stored, nil
}

// Delete removes the tenant's lease leaseID on behalf of gatewayID. A lease
// another gateway issued is refused with ErrLeaseOwnedByOtherGateway.
func (s *LeaseStore) Delete(ctx context.Context, gatewayID, tenantID, leaseID string) error {
	if err := validateID("gateway_id", gatewayID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.Get(ctx, tenantID, leaseID)
	if err != nil {
		return err
	}
	if stored.GatewayID != gatewayID {
		return &ErrLeaseOwnedByOtherGateway{TenantID: tenantID, LeaseID: leaseID, GatewayID: gatewayID}
	}
	if err := s.leases.Delete(ctx, stored); err != nil {
		return &vpncore.ErrLeaseStoreUnavailable{Cause: err}
	}
	return nil
}

// List returns the tenant's leases, or every tenant's when tenantID is empty,
// ordered by issue time.
func (s *LeaseStore) List(ctx context.Context, tenantID string) ([]*Lease, error) {
	return s.list(ctx, func(l *Lease) bool { return tenantID == "" || l.TenantID == tenantID })
}

// ListByGateway returns the leases gatewayID issued, ordered by issue time:
// the projection that gateway rebuilds on start.
func (s *LeaseStore) ListByGateway(ctx context.Context, gatewayID string) ([]*Lease, error) {
	if err := validateID("gateway_id", gatewayID); err != nil {
		return nil, err
	}
	return s.list(ctx, func(l *Lease) bool { return l.GatewayID == gatewayID })
}

// Sweep removes every lease that has expired and returns how many it removed.
// A gateway sweeps its own leases as they run out; this one removes the
// leases of a gateway that stopped running before it could. A lease renewed
// after the sweep listed it is not removed.
func (s *LeaseStore) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	expired, err := s.list(ctx, func(l *Lease) bool { return l.Expired(now) })
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, l := range expired {
		deleted, err := s.deleteIfExpired(ctx, l, now)
		if err != nil {
			return removed, err
		}
		if deleted {
			removed++
		}
	}
	return removed, nil
}

// deleteIfExpired deletes the record listed as l only if the stored copy is
// still expired at now: a renewal saved since the list keeps its record.
func (s *LeaseStore) deleteIfExpired(ctx context.Context, l *Lease, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.lease(ctx, l)
	if err != nil {
		return false, err
	}
	if current == nil || !current.Expired(now) {
		return false, nil
	}
	if err := s.leases.Delete(ctx, current); err != nil {
		return false, &vpncore.ErrLeaseStoreUnavailable{Cause: err}
	}
	return true, nil
}

// lease reads the record probe names. A record ID another key already holds
// is refused with ErrKeyCollision.
func (s *LeaseStore) lease(ctx context.Context, probe *Lease) (*Lease, error) {
	stored, err := getRecord(ctx, s.leases, probe.ID)
	if err != nil {
		return nil, &vpncore.ErrLeaseStoreUnavailable{Cause: err}
	}
	if stored == nil {
		return nil, nil
	}
	if stored.key() != probe.key() {
		return nil, &ErrKeyCollision{Kind: "lease", Key: probe.key(), Stored: stored.key()}
	}
	return stored, nil
}

func (s *LeaseStore) list(ctx context.Context, keep func(*Lease) bool) ([]*Lease, error) {
	leases, err := listAll(ctx, s.leases, keep)
	if err != nil {
		return nil, &vpncore.ErrLeaseStoreUnavailable{Cause: err}
	}
	slices.SortFunc(leases, func(a, b *Lease) int {
		if c := a.IssuedAt.Compare(b.IssuedAt); c != 0 {
			return c
		}
		return strings.Compare(a.LeaseID, b.LeaseID)
	})
	return leases, nil
}

// validateLease refuses a lease the control plane would store incomplete.
func validateLease(l *Lease) error {
	for _, id := range [...]struct{ field, value string }{
		{"gateway_id", l.GatewayID},
		{"tenant_id", l.TenantID},
		{"device_id", l.DeviceID},
		{"lease_id", l.LeaseID},
	} {
		if err := validateID(id.field, id.value); err != nil {
			return err
		}
	}
	switch {
	case !l.Address.IsValid():
		return &ErrInvalidArgument{Field: "address", Reason: "required"}
	case !l.DataPlane.Known():
		return &ErrInvalidArgument{Field: "data_plane", Reason: "unknown data plane " + string(l.DataPlane)}
	case !l.ExpiresAt.After(l.IssuedAt):
		return &ErrInvalidArgument{Field: "expires_at", Reason: "not after issued_at"}
	case len(l.WireGuardPublicKey) != 0 && len(l.WireGuardPublicKey) != wireGuardKeySize:
		return &ErrInvalidArgument{Field: "wireguard_public_key", Reason: "not a 32-byte key"}
	case len(l.ClientCertificateSHA256) != 0 && len(l.ClientCertificateSHA256) != sha256.Size:
		return &ErrInvalidArgument{Field: "client_certificate_sha256", Reason: "not a SHA-256 fingerprint"}
	}
	return validateZones(l.Zones)
}
