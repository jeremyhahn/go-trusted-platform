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

package daemon

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// errGatewayFeatureNotConfigured aliases the exported sentinel from the quic
// package so that the QUIC gateway handler maps it to StatusUnavailable.
// Use quic.ErrGatewayFeatureNotConfigured directly; this alias avoids renaming
// every return site in this file.
var errGatewayFeatureNotConfigured = quic.ErrGatewayFeatureNotConfigured

// zoneGatewayAdapter bridges a gateway.ZoneService into the quic.GatewayServiceInterface.
// Gateway operations not covered by the zone service (status, BGP, IPAM) return
// errGatewayFeatureNotConfigured so that the QUIC handler emits StatusUnavailable
// rather than a panic or a misleading error.
//
// This adapter is injected into the QUIC GatewayHandler during daemon startup so
// that zone operations (Create/Update/Delete/List) work over QUIC even
// when no full gateway controller is configured.
type zoneGatewayAdapter struct {
	zoneSvc gateway.ZoneService
	// gatewaySnapshotQUICAdapter serves the telemetry snapshot sub-opcodes
	// from the gateway gRPC service when one is wired (#594).
	gatewaySnapshotQUICAdapter
}

// Compile-time check: zoneGatewayAdapter implements quic.GatewayServiceInterface.
var _ quic.GatewayServiceInterface = (*zoneGatewayAdapter)(nil)

// newZoneGatewayAdapter wraps a ZoneService as a GatewayServiceInterface.
func newZoneGatewayAdapter(svc gateway.ZoneService) *zoneGatewayAdapter {
	return &zoneGatewayAdapter{zoneSvc: svc}
}

// =============================================================================
// Non-zone methods — return "not configured" so QUIC handler emits Unavailable
// =============================================================================

func (a *zoneGatewayAdapter) Status(_ context.Context) (*quic.GatewayStatusInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) SetMode(_ context.Context, _ string) error {
	return errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) BGPStatus(_ context.Context) (*quic.BGPStatusInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) ListBGPPeers(_ context.Context) ([]*quic.BGPPeerInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) AnnouncePrefix(_ context.Context, _ string, _ *quic.AnnouncePrefixOptions) error {
	return errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) WithdrawPrefix(_ context.Context, _ string) error {
	return errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) ListPrefixes(_ context.Context) ([]*quic.PrefixInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) ListIPAMPools(_ context.Context, _ string) ([]*quic.IPAMPoolInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) GetIPAMPool(_ context.Context, _ string) (*quic.IPAMPoolInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) CreateIPAMPool(_ context.Context, _ *quic.CreateIPAMPoolOptions) (*quic.IPAMPoolInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) UpdateIPAMPool(_ context.Context, _ string, _ *quic.UpdateIPAMPoolOptions) (*quic.IPAMPoolInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) DeleteIPAMPool(_ context.Context, _ string) error {
	return errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) AllocateIP(_ context.Context, _ string, _ *quic.AllocateIPOptions) (*quic.IPAllocationInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) ReleaseIP(_ context.Context, _ string, _ string) error {
	return errGatewayFeatureNotConfigured
}

func (a *zoneGatewayAdapter) ListAllocations(_ context.Context, _ string) ([]*quic.IPAllocationInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

// =============================================================================
// Zone methods — delegate to the underlying ZoneService
// =============================================================================

// ListNetworkZones lists zones filtered by lifecycle role (empty = all).
func (a *zoneGatewayAdapter) ListNetworkZones(ctx context.Context, lifecycleRole string) ([]*quic.NetworkZoneInfo, error) {
	recs, err := a.zoneSvc.List(ctx, zone.LifecycleRole(lifecycleRole))
	if err != nil {
		return nil, mapZoneToQUICError(err)
	}
	out := make([]*quic.NetworkZoneInfo, 0, len(recs))
	for _, r := range recs {
		out = append(out, zoneRecordToQUICInfo(r, false))
	}
	return out, nil
}

// CreateNetworkZone creates a new trust zone.
func (a *zoneGatewayAdapter) CreateNetworkZone(ctx context.Context, opts *quic.CreateNetworkZoneOptions) (*quic.NetworkZoneInfo, error) {
	cfg := quicCreateOptsToZoneConfig(opts)
	rec, restartRequired, err := a.zoneSvc.Create(ctx, cfg)
	if err != nil {
		return nil, mapZoneToQUICError(err)
	}
	return zoneRecordToQUICInfo(rec, restartRequired), nil
}

// UpdateNetworkZone updates an existing trust zone.
func (a *zoneGatewayAdapter) UpdateNetworkZone(ctx context.Context, name string, opts *quic.UpdateNetworkZoneOptions) (*quic.NetworkZoneInfo, error) {
	cfg := quicUpdateOptsToZoneConfig(name, opts)
	rec, restartRequired, err := a.zoneSvc.Update(ctx, zone.Zone(name), cfg)
	if err != nil {
		return nil, mapZoneToQUICError(err)
	}
	return zoneRecordToQUICInfo(rec, restartRequired), nil
}

// DeleteNetworkZone deletes a trust zone by name.
func (a *zoneGatewayAdapter) DeleteNetworkZone(ctx context.Context, name string) (bool, error) {
	restartRequired, err := a.zoneSvc.Delete(ctx, zone.Zone(name))
	if err != nil {
		return false, mapZoneToQUICError(err)
	}
	return restartRequired, nil
}

// =============================================================================
// Error mapping
// =============================================================================

// mapZoneToQUICError translates gateway zone errors into quic.GatewayZoneError
// so the QUIC client receives the right status byte (NotFound,
// AlreadyExists, InvalidArgument) and the service's message.
func mapZoneToQUICError(err error) error {
	switch err.(type) {
	case gateway.ErrZoneNotFound:
		return quic.GatewayZoneError{Kind: quic.ErrGatewayZoneNotFound, Cause: err}
	case gateway.ErrZoneAlreadyExists:
		return quic.GatewayZoneError{Kind: quic.ErrGatewayZoneAlreadyExists, Cause: err}
	case gateway.ErrZoneValidation:
		return quic.GatewayZoneError{Kind: quic.ErrGatewayZoneInvalid, Cause: err}
	default:
		return err
	}
}

// =============================================================================
// Conversion helpers
// =============================================================================

// zoneRecordToQUICInfo converts a gateway.ZoneRecord to a quic.NetworkZoneInfo.
func zoneRecordToQUICInfo(r *gateway.ZoneRecord, restartRequired bool) *quic.NetworkZoneInfo {
	info := &quic.NetworkZoneInfo{
		Name:             string(r.Config.Name),
		Offset:           uint8(r.Config.Offset),
		PortClasses:      portClassStrings(r.Config.PortClasses),
		InternetIngress:  r.Config.InternetIngress,
		IsolateFrom:      zoneStrings(r.Config.IsolateFrom),
		AllowTo:          zonePathsToQUIC(r.Config.AllowTo),
		Services:         r.Config.Services,
		Isolate:          r.Config.Isolate,
		OOB:              r.Config.OOB,
		LifecycleRole:    string(r.Config.LifecycleRole),
		PrivilegedAccess: privilegedAccessToQUIC(r.Config.PrivilegedAccess),
		RestartRequired:  restartRequired,
		CreatedAt:        r.CreatedAt.Unix(),
		UpdatedAt:        r.UpdatedAt.Unix(),
	}
	if n := r.NumberingView(); n != nil {
		info.Numbering = &quic.NetworkZoneNumberingInfo{
			VLAN:    n.VLAN,
			Subnet4: n.Subnet4,
			Subnet6: n.Subnet6,
			Gateway: n.Gateway,
		}
	}
	return info
}

// quicCreateOptsToZoneConfig converts quic create options to zone.ZoneConfig.
func quicCreateOptsToZoneConfig(opts *quic.CreateNetworkZoneOptions) zone.ZoneConfig {
	if opts == nil {
		return zone.ZoneConfig{}
	}
	return zone.ZoneConfig{
		Name:             zone.Zone(opts.Name),
		Offset:           zone.Offset(opts.Offset),
		PortClasses:      portClassesFromStrings(opts.PortClasses),
		InternetIngress:  opts.InternetIngress,
		IsolateFrom:      zonesFromStrings(opts.IsolateFrom),
		AllowTo:          zonePathsFromQUIC(opts.AllowTo),
		Services:         opts.Services,
		Isolate:          opts.Isolate,
		OOB:              opts.OOB,
		LifecycleRole:    zone.LifecycleRole(opts.LifecycleRole),
		PrivilegedAccess: privilegedAccessFromQUIC(opts.PrivilegedAccess),
	}
}

// quicUpdateOptsToZoneConfig converts quic update options to zone.ZoneConfig.
func quicUpdateOptsToZoneConfig(name string, opts *quic.UpdateNetworkZoneOptions) zone.ZoneConfig {
	cfg := zone.ZoneConfig{Name: zone.Zone(name)}
	if opts == nil {
		return cfg
	}
	cfg.Offset = zone.Offset(opts.Offset)
	cfg.PortClasses = portClassesFromStrings(opts.PortClasses)
	cfg.InternetIngress = opts.InternetIngress
	cfg.IsolateFrom = zonesFromStrings(opts.IsolateFrom)
	cfg.AllowTo = zonePathsFromQUIC(opts.AllowTo)
	cfg.Services = opts.Services
	cfg.Isolate = opts.Isolate
	cfg.OOB = opts.OOB
	cfg.LifecycleRole = zone.LifecycleRole(opts.LifecycleRole)
	cfg.PrivilegedAccess = privilegedAccessFromQUIC(opts.PrivilegedAccess)
	return cfg
}

// zoneStrings converts zone names to strings.
func zoneStrings(in []zone.Zone) []string {
	out := make([]string, 0, len(in))
	for _, z := range in {
		out = append(out, string(z))
	}
	return out
}

// zonesFromStrings converts strings to zone names; nil for an empty input.
func zonesFromStrings(in []string) []zone.Zone {
	var out []zone.Zone
	for _, z := range in {
		out = append(out, zone.Zone(z))
	}
	return out
}

// portClassStrings converts port classes to strings.
func portClassStrings(in []zone.PortClass) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, string(c))
	}
	return out
}

// portClassesFromStrings converts strings to port classes; nil for an empty
// input.
func portClassesFromStrings(in []string) []zone.PortClass {
	var out []zone.PortClass
	for _, c := range in {
		out = append(out, zone.PortClass(c))
	}
	return out
}

// zonePathsToQUIC converts allow_to paths to their QUIC form.
func zonePathsToQUIC(in []zone.ZonePath) []quic.NetworkZonePathInfo {
	out := make([]quic.NetworkZonePathInfo, 0, len(in))
	for _, p := range in {
		out = append(out, quic.NetworkZonePathInfo{Zone: string(p.Zone), Services: p.Services})
	}
	return out
}

// zonePathsFromQUIC converts QUIC allow_to paths; nil for an empty input.
func zonePathsFromQUIC(in []quic.NetworkZonePathInfo) []zone.ZonePath {
	var out []zone.ZonePath
	for _, p := range in {
		out = append(out, zone.ZonePath{Zone: zone.Zone(p.Zone), Services: p.Services})
	}
	return out
}

// privilegedAccessToQUIC converts the audited override to its QUIC form.
func privilegedAccessToQUIC(pa *zone.PrivilegedAccess) *quic.NetworkZonePrivilegedAccessInfo {
	if pa == nil {
		return nil
	}
	return &quic.NetworkZonePrivilegedAccessInfo{Reason: pa.Reason, ApprovedBy: pa.ApprovedBy}
}

// privilegedAccessFromQUIC converts the QUIC audited override.
func privilegedAccessFromQUIC(pa *quic.NetworkZonePrivilegedAccessInfo) *zone.PrivilegedAccess {
	if pa == nil {
		return nil
	}
	return &zone.PrivilegedAccess{Reason: pa.Reason, ApprovedBy: pa.ApprovedBy}
}

// =============================================================================
// fullGatewayQUICAdapter
// =============================================================================

// fullGatewayQUICAdapter bridges both an ipam.Allocator and a gateway.ZoneService
// into the quic.GatewayServiceInterface. It is used to wire the QUIC gateway
// handler so that IPAM pool CRUD and zone operations are both available over QUIC.
//
// BGP, prefix, status, and allocation operations that have no in-process backing
// return errGatewayFeatureNotConfigured so the QUIC handler emits StatusUnavailable
// rather than a misleading error or a nil-pointer panic.
type fullGatewayQUICAdapter struct {
	ipamAlloc ipam.Allocator
	zoneSvc   gateway.ZoneService          // may be nil
	lb        GatewayLoadBalancerInterface // may be nil
	nat64     GatewayNAT64Interface        // may be nil
	// gatewaySnapshotQUICAdapter serves the telemetry snapshot sub-opcodes
	// from the gateway gRPC service when one is wired (#594).
	gatewaySnapshotQUICAdapter
}

// Compile-time check: fullGatewayQUICAdapter implements quic.GatewayServiceInterface.
var _ quic.GatewayServiceInterface = (*fullGatewayQUICAdapter)(nil)

// newFullGatewayQUICAdapter creates a fullGatewayQUICAdapter.
// ipamAlloc must be non-nil; zoneSvc may be nil (zone methods will return
// errGatewayFeatureNotConfigured in that case).
func newFullGatewayQUICAdapter(ipamAlloc ipam.Allocator, zoneSvc gateway.ZoneService, snapshots GatewaySnapshotReader) *fullGatewayQUICAdapter {
	return &fullGatewayQUICAdapter{
		ipamAlloc:                  ipamAlloc,
		zoneSvc:                    zoneSvc,
		gatewaySnapshotQUICAdapter: gatewaySnapshotQUICAdapter{reader: snapshots},
	}
}

// =============================================================================
// Non-IPAM / non-zone stubs
// =============================================================================

func (a *fullGatewayQUICAdapter) Status(_ context.Context) (*quic.GatewayStatusInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *fullGatewayQUICAdapter) SetMode(_ context.Context, _ string) error {
	return errGatewayFeatureNotConfigured
}

func (a *fullGatewayQUICAdapter) BGPStatus(_ context.Context) (*quic.BGPStatusInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *fullGatewayQUICAdapter) ListBGPPeers(_ context.Context) ([]*quic.BGPPeerInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

func (a *fullGatewayQUICAdapter) AnnouncePrefix(_ context.Context, _ string, _ *quic.AnnouncePrefixOptions) error {
	return errGatewayFeatureNotConfigured
}

func (a *fullGatewayQUICAdapter) WithdrawPrefix(_ context.Context, _ string) error {
	return errGatewayFeatureNotConfigured
}

func (a *fullGatewayQUICAdapter) ListPrefixes(_ context.Context) ([]*quic.PrefixInfo, error) {
	return nil, errGatewayFeatureNotConfigured
}

// AllocateIP allocates an address from poolID through the daemon's IPAM
// allocator -- the one gRPC and REST allocate from. It used to return
// "gateway feature not configured" while ListAllocations on the same adapter
// read that allocator, so QUIC could list allocations it could not make (#730).
//
// The QUIC owner is the device the address is allocated to (the response
// carries the allocation's DeviceID as owner) and is required, as device_id is
// on gRPC and REST. A requested ip_address allocates that address; ttl
// overrides the pool's lease, in seconds; labels are recorded as metadata.
// IPAM records no MAC address, so one is refused rather than dropped.
func (a *fullGatewayQUICAdapter) AllocateIP(ctx context.Context, poolID string, opts *quic.AllocateIPOptions) (*quic.IPAllocationInfo, error) {
	if opts == nil {
		opts = &quic.AllocateIPOptions{}
	}
	req, err := quicAllocationRequest(poolID, opts)
	if err != nil {
		return nil, err
	}
	allocate := a.ipamAlloc.Allocate
	if req.RequestedIP.IsValid() {
		allocate = a.ipamAlloc.AllocateSpecific
	}
	alloc, err := allocate(ctx, req)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	return ipamAllocationToQUICInfo(alloc), nil
}

// quicAllocationRequest validates a QUIC allocation and maps it onto the IPAM
// request.
func quicAllocationRequest(poolID string, opts *quic.AllocateIPOptions) (*ipam.AllocationRequest, error) {
	if opts.Owner == "" {
		return nil, quic.ErrGatewayMissingOwner
	}
	if opts.MACAddress != "" {
		return nil, quic.ErrGatewayMACNotRecorded
	}
	switch opts.Type {
	case "", "dynamic":
	case "static":
		if opts.IPAddress == "" {
			return nil, quic.ErrGatewayMissingIPAddress
		}
	default:
		return nil, quic.ErrGatewayInvalidAllocationType
	}
	req := &ipam.AllocationRequest{
		PoolID:        poolID,
		DeviceID:      opts.Owner,
		Hostname:      opts.Hostname,
		Metadata:      opts.Labels,
		LeaseDuration: time.Duration(opts.TTL) * time.Second,
	}
	if opts.IPAddress != "" {
		addr, err := netip.ParseAddr(opts.IPAddress)
		if err != nil {
			return nil, quic.ErrGatewayInvalidIPAddress
		}
		req.RequestedIP = addr
	}
	return req, nil
}

// ReleaseIP releases an allocated address. poolID is optional, as on gRPC and
// REST; when it is set, an address held in another pool is reported not found
// rather than released.
func (a *fullGatewayQUICAdapter) ReleaseIP(ctx context.Context, poolID string, ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return quic.ErrGatewayInvalidIPAddress
	}
	if poolID != "" {
		alloc, err := a.ipamAlloc.GetAllocation(ctx, addr)
		if err != nil {
			return mapIPAMToQUICError(err)
		}
		if alloc.PoolID != poolID {
			return quic.ErrGatewayAllocationNotFound
		}
	}
	return mapIPAMToQUICError(a.ipamAlloc.Release(ctx, addr))
}

func (a *fullGatewayQUICAdapter) ListAllocations(ctx context.Context, poolID string) ([]*quic.IPAllocationInfo, error) {
	allocs, err := activeAllocations(ctx, a.ipamAlloc, poolID)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	out := make([]*quic.IPAllocationInfo, 0, len(allocs))
	for _, alloc := range allocs {
		out = append(out, ipamAllocationToQUICInfo(alloc))
	}
	return out, nil
}

// ipamAllocationToQUICInfo converts an ipam.Allocation to the QUIC wire shape.
func ipamAllocationToQUICInfo(a *ipam.Allocation) *quic.IPAllocationInfo {
	info := &quic.IPAllocationInfo{
		ID:        a.ID,
		PoolID:    a.PoolID,
		IPAddress: a.IP.String(),
		Hostname:  a.Hostname,
		Owner:     a.DeviceID,
		Type:      "dynamic",
		Status:    string(a.Status),
		CreatedAt: a.AllocatedAt.Unix(),
		UpdatedAt: a.LastSeen.Unix(),
	}
	if !a.ExpiresAt.IsZero() {
		info.ExpiresAt = a.ExpiresAt.Unix()
	}
	return info
}

// =============================================================================
// IPAM pool operations — backed by ipamAlloc
// =============================================================================

// ListIPAMPools returns all pools, optionally filtered by zone.
func (a *fullGatewayQUICAdapter) ListIPAMPools(ctx context.Context, zoneFilter string) ([]*quic.IPAMPoolInfo, error) {
	pools, err := a.ipamAlloc.ListPoolsByZone(ctx, zoneFilter)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	out := make([]*quic.IPAMPoolInfo, 0, len(pools))
	for _, p := range pools {
		out = append(out, ipamPoolToQUICInfo(p))
	}
	return out, nil
}

// GetIPAMPool retrieves a single pool by ID.
func (a *fullGatewayQUICAdapter) GetIPAMPool(ctx context.Context, poolID string) (*quic.IPAMPoolInfo, error) {
	pool, err := a.ipamAlloc.GetPool(ctx, poolID)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	return ipamPoolToQUICInfo(pool), nil
}

// CreateIPAMPool creates a new IP address pool.
func (a *fullGatewayQUICAdapter) CreateIPAMPool(ctx context.Context, opts *quic.CreateIPAMPoolOptions) (*quic.IPAMPoolInfo, error) {
	if opts == nil {
		return nil, quic.ErrGatewayMissingPoolName
	}
	if opts.Name == "" {
		return nil, quic.ErrGatewayMissingPoolName
	}
	if opts.CIDR == "" {
		return nil, quic.ErrGatewayMissingPoolCIDR
	}
	cidr, err := netip.ParsePrefix(opts.CIDR)
	if err != nil {
		return nil, quic.ErrGatewayInvalidPoolCIDR
	}
	cidr = cidr.Masked()

	id := opts.ID
	if id == "" {
		id = uuid.New().String()
	}

	pool := &ipam.Pool{
		ID:          id,
		Name:        opts.Name,
		CIDR:        cidr,
		Zone:        opts.Zone,
		Description: opts.Description,
	}
	if opts.Gateway != "" {
		gw, parseErr := netip.ParseAddr(opts.Gateway)
		if parseErr != nil {
			return nil, quic.ErrGatewayInvalidIPAddress
		}
		pool.Gateway = gw
	}
	if opts.LeaseDuration > 0 {
		pool.DefaultLeaseDuration = time.Duration(opts.LeaseDuration)
	}
	reserved, rangeStart, rangeEnd, err := ipam.ParseWindow(opts.Reserved, opts.RangeStart, opts.RangeEnd)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	pool.Reserved = reserved
	pool.RangeStart = rangeStart
	pool.RangeEnd = rangeEnd

	if err := a.ipamAlloc.CreatePool(ctx, pool); err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	created, err := a.ipamAlloc.GetPool(ctx, id)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	return ipamPoolToQUICInfo(created), nil
}

// UpdateIPAMPool updates mutable fields on an existing pool. CIDR is immutable.
func (a *fullGatewayQUICAdapter) UpdateIPAMPool(ctx context.Context, poolID string, opts *quic.UpdateIPAMPoolOptions) (*quic.IPAMPoolInfo, error) {
	if poolID == "" {
		return nil, quic.ErrGatewayMissingPoolID
	}
	existing, err := a.ipamAlloc.GetPool(ctx, poolID)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	updated := existing.Clone()
	if opts != nil {
		if opts.Name != "" {
			updated.Name = opts.Name
		}
		if opts.Gateway != "" {
			gw, parseErr := netip.ParseAddr(opts.Gateway)
			if parseErr != nil {
				return nil, quic.ErrGatewayInvalidIPAddress
			}
			updated.Gateway = gw
		}
		if opts.Zone != "" {
			updated.Zone = opts.Zone
		}
		if opts.Description != "" {
			updated.Description = opts.Description
		}
		if opts.LeaseDuration > 0 {
			updated.DefaultLeaseDuration = time.Duration(opts.LeaseDuration)
		}
		if opts.UpdateWindow {
			reserved, rangeStart, rangeEnd, parseErr := ipam.ParseWindow(opts.Reserved, opts.RangeStart, opts.RangeEnd)
			if parseErr != nil {
				return nil, mapIPAMToQUICError(parseErr)
			}
			updated.Reserved = reserved
			updated.RangeStart = rangeStart
			updated.RangeEnd = rangeEnd
		}
	}
	if err := a.ipamAlloc.UpdatePool(ctx, updated); err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	refreshed, err := a.ipamAlloc.GetPool(ctx, poolID)
	if err != nil {
		return nil, mapIPAMToQUICError(err)
	}
	return ipamPoolToQUICInfo(refreshed), nil
}

// DeleteIPAMPool removes a pool. Returns ErrGatewayPoolNotFound if the pool
// does not exist, and wraps ErrPoolHasAllocations as an internal error with
// the original message so callers receive a meaningful response.
func (a *fullGatewayQUICAdapter) DeleteIPAMPool(ctx context.Context, poolID string) error {
	if poolID == "" {
		return quic.ErrGatewayMissingPoolID
	}
	return mapIPAMToQUICError(a.ipamAlloc.DeletePool(ctx, poolID))
}

// =============================================================================
// Zone operations — delegate to zoneGatewayAdapter helpers
// =============================================================================

// ListNetworkZones lists zones filtered by lifecycle role.
func (a *fullGatewayQUICAdapter) ListNetworkZones(ctx context.Context, lifecycleRole string) ([]*quic.NetworkZoneInfo, error) {
	if a.zoneSvc == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	recs, err := a.zoneSvc.List(ctx, zone.LifecycleRole(lifecycleRole))
	if err != nil {
		return nil, mapZoneToQUICError(err)
	}
	out := make([]*quic.NetworkZoneInfo, 0, len(recs))
	for _, r := range recs {
		out = append(out, zoneRecordToQUICInfo(r, false))
	}
	return out, nil
}

// CreateNetworkZone creates a new trust zone.
func (a *fullGatewayQUICAdapter) CreateNetworkZone(ctx context.Context, opts *quic.CreateNetworkZoneOptions) (*quic.NetworkZoneInfo, error) {
	if a.zoneSvc == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	cfg := quicCreateOptsToZoneConfig(opts)
	rec, restartRequired, err := a.zoneSvc.Create(ctx, cfg)
	if err != nil {
		return nil, mapZoneToQUICError(err)
	}
	return zoneRecordToQUICInfo(rec, restartRequired), nil
}

// UpdateNetworkZone updates an existing trust zone.
func (a *fullGatewayQUICAdapter) UpdateNetworkZone(ctx context.Context, name string, opts *quic.UpdateNetworkZoneOptions) (*quic.NetworkZoneInfo, error) {
	if a.zoneSvc == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	cfg := quicUpdateOptsToZoneConfig(name, opts)
	rec, restartRequired, err := a.zoneSvc.Update(ctx, zone.Zone(name), cfg)
	if err != nil {
		return nil, mapZoneToQUICError(err)
	}
	return zoneRecordToQUICInfo(rec, restartRequired), nil
}

// DeleteNetworkZone deletes a trust zone by name.
func (a *fullGatewayQUICAdapter) DeleteNetworkZone(ctx context.Context, name string) (bool, error) {
	if a.zoneSvc == nil {
		return false, errGatewayFeatureNotConfigured
	}
	restartRequired, err := a.zoneSvc.Delete(ctx, zone.Zone(name))
	if err != nil {
		return false, mapZoneToQUICError(err)
	}
	return restartRequired, nil
}

// =============================================================================
// Conversion and error-mapping helpers
// =============================================================================

// mapIPAMToQUICError translates ipam sentinel errors to the QUIC gateway
// sentinel errors recognised by quic.GatewayHandler.gatewayErrorResponse.
// isIPConflict reports whether err is the backends' typed refusal of a
// requested address that another allocation holds.
func isIPConflict(err error) bool {
	var conflict *ipam.ErrIPConflict
	return errors.As(err, &conflict)
}

func mapIPAMToQUICError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ipam.ErrPoolNotFound):
		return quic.ErrGatewayPoolNotFound
	case errors.Is(err, ipam.ErrPoolAlreadyExists),
		errors.Is(err, ipam.ErrPoolNameExists),
		errors.Is(err, ipam.ErrPoolCIDROverlaps):
		return quic.ErrGatewayPoolAlreadyExists
	case errors.Is(err, ipam.ErrPoolHasAllocations):
		// The QUIC handler maps this string through gatewayErrorResponse;
		// wrap it so callers get an informative InternalError.
		return quic.ErrGatewayPoolExhausted
	case errors.Is(err, ipam.ErrInvalidCIDR),
		errors.Is(err, ipam.ErrInvalidGateway):
		return quic.ErrGatewayInvalidPoolCIDR
	case errors.Is(err, ipam.ErrInvalidPoolName),
		errors.Is(err, ipam.ErrInvalidPoolID):
		return quic.ErrGatewayMissingPoolName
	case isIPAMWindowError(err):
		return quic.ErrGatewayIPAMWindowDetail{Reason: err.Error()}
	case errors.Is(err, ipam.ErrPoolExhausted):
		return quic.ErrGatewayPoolExhausted
	case errors.Is(err, ipam.ErrAllocationNotFound),
		errors.Is(err, ipam.ErrAllocationReleased):
		return quic.ErrGatewayAllocationNotFound
	case errors.Is(err, ipam.ErrIPAlreadyAllocated), isIPConflict(err):
		return quic.ErrGatewayIPAlreadyAllocated
	case errors.Is(err, ipam.ErrDeviceIDRequired):
		return quic.ErrGatewayMissingOwner
	case errors.Is(err, ipam.ErrInvalidIP),
		errors.Is(err, ipam.ErrIPNotInPool),
		errors.Is(err, ipam.ErrNetworkAddress),
		errors.Is(err, ipam.ErrBroadcastAddress):
		return quic.ErrGatewayInvalidIPAddress
	}
	return err
}

// ipamPoolToQUICInfo converts an ipam.Pool to a quic.IPAMPoolInfo wire type.
func ipamPoolToQUICInfo(p *ipam.Pool) *quic.IPAMPoolInfo {
	if p == nil {
		return nil
	}
	var cidr string
	if p.CIDR.IsValid() {
		cidr = p.CIDR.String()
	}
	var gw string
	if p.Gateway.IsValid() {
		gw = p.Gateway.String()
	}
	return &quic.IPAMPoolInfo{
		ID:           p.ID,
		Name:         p.Name,
		CIDR:         cidr,
		Gateway:      gw,
		Zone:         p.Zone,
		Description:  p.Description,
		TotalIPs:     int(p.TotalIPs),
		AllocatedIPs: int(p.AllocatedIPs),
		AvailableIPs: int(p.AvailableIPs),
		CreatedAt:    p.CreatedAt.Unix(),
		Reserved:     p.ReservedStrings(),
		RangeStart:   ipam.AddrString(p.RangeStart),
		RangeEnd:     ipam.AddrString(p.RangeEnd),
	}
}
