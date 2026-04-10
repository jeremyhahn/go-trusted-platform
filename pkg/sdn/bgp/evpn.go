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

package bgp

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// EVPN constants.
const (
	// MinVNI is the minimum valid VNI value.
	MinVNI uint32 = 1

	// MaxVNI is the maximum valid VNI value (2^24 - 1).
	MaxVNI uint32 = 16777215

	// TunnelTypeIngressReplication is the tunnel encapsulation type for VXLAN ingress replication.
	TunnelTypeIngressReplication uint8 = 6

	// evpnType2MinLen is the minimum length for Type-2 NLRI (without optional fields).
	evpnType2MinLen = 33

	// evpnType3MinLen is the minimum length for Type-3 NLRI.
	evpnType3MinLen = 17

	// evpnType5MinLen is the minimum length for Type-5 NLRI.
	evpnType5MinLen = 26
)

// RouteDistinguisher represents an 8-byte BGP Route Distinguisher.
type RouteDistinguisher struct {
	// Type indicates the RD format:
	// 0: Administrator is 2-byte ASN, Assigned is 4-byte number
	// 1: Administrator is 4-byte IP, Assigned is 2-byte number
	// 2: Administrator is 4-byte ASN, Assigned is 2-byte number
	Type uint16

	// Administrator is the ASN or IP address portion.
	Administrator uint32

	// AssignedNumber is the assigned number portion.
	AssignedNumber uint32
}

// Bytes returns the 8-byte encoding of the Route Distinguisher.
func (rd RouteDistinguisher) Bytes() [8]byte {
	var b [8]byte
	b[0] = byte(rd.Type >> 8)
	b[1] = byte(rd.Type)
	switch rd.Type {
	case 0:
		b[2] = byte(rd.Administrator >> 8)
		b[3] = byte(rd.Administrator)
		b[4] = byte(rd.AssignedNumber >> 24)
		b[5] = byte(rd.AssignedNumber >> 16)
		b[6] = byte(rd.AssignedNumber >> 8)
		b[7] = byte(rd.AssignedNumber)
	case 1, 2:
		b[2] = byte(rd.Administrator >> 24)
		b[3] = byte(rd.Administrator >> 16)
		b[4] = byte(rd.Administrator >> 8)
		b[5] = byte(rd.Administrator)
		b[6] = byte(rd.AssignedNumber >> 8)
		b[7] = byte(rd.AssignedNumber)
	}
	return b
}

// ParseRouteDistinguisher parses an 8-byte Route Distinguisher.
func ParseRouteDistinguisher(data [8]byte) RouteDistinguisher {
	rd := RouteDistinguisher{
		Type: binary.BigEndian.Uint16(data[0:2]),
	}
	switch rd.Type {
	case 0:
		rd.Administrator = uint32(binary.BigEndian.Uint16(data[2:4]))
		rd.AssignedNumber = binary.BigEndian.Uint32(data[4:8])
	case 1, 2:
		rd.Administrator = binary.BigEndian.Uint32(data[2:6])
		rd.AssignedNumber = uint32(binary.BigEndian.Uint16(data[6:8]))
	}
	return rd
}

// RouteTarget represents a BGP Extended Community Route Target.
type RouteTarget struct {
	// Type indicates the RT format (same as RD types).
	Type uint16

	// GlobalAdmin is the ASN or IP address portion.
	GlobalAdmin uint32

	// LocalAdmin is the local administrator portion.
	LocalAdmin uint32
}

// Bytes returns the 8-byte encoding of the Route Target Extended Community.
func (rt RouteTarget) Bytes() [8]byte {
	var b [8]byte
	switch rt.Type {
	case 0:
		b[0] = 0x00 // Transitive Two-Octet AS-Specific
		b[1] = 0x02 // Route Target
		b[2] = byte(rt.GlobalAdmin >> 8)
		b[3] = byte(rt.GlobalAdmin)
		b[4] = byte(rt.LocalAdmin >> 24)
		b[5] = byte(rt.LocalAdmin >> 16)
		b[6] = byte(rt.LocalAdmin >> 8)
		b[7] = byte(rt.LocalAdmin)
	case 1:
		b[0] = 0x01 // Transitive IPv4-Specific
		b[1] = 0x02 // Route Target
		b[2] = byte(rt.GlobalAdmin >> 24)
		b[3] = byte(rt.GlobalAdmin >> 16)
		b[4] = byte(rt.GlobalAdmin >> 8)
		b[5] = byte(rt.GlobalAdmin)
		b[6] = byte(rt.LocalAdmin >> 8)
		b[7] = byte(rt.LocalAdmin)
	case 2:
		b[0] = 0x02 // Transitive Four-Octet AS-Specific
		b[1] = 0x02 // Route Target
		b[2] = byte(rt.GlobalAdmin >> 24)
		b[3] = byte(rt.GlobalAdmin >> 16)
		b[4] = byte(rt.GlobalAdmin >> 8)
		b[5] = byte(rt.GlobalAdmin)
		b[6] = byte(rt.LocalAdmin >> 8)
		b[7] = byte(rt.LocalAdmin)
	}
	return b
}

// ParseRouteTarget parses an 8-byte Route Target Extended Community.
func ParseRouteTarget(data [8]byte) RouteTarget {
	rt := RouteTarget{}
	switch data[0] {
	case 0x00:
		rt.Type = 0
		rt.GlobalAdmin = uint32(binary.BigEndian.Uint16(data[2:4]))
		rt.LocalAdmin = binary.BigEndian.Uint32(data[4:8])
	case 0x01:
		rt.Type = 1
		rt.GlobalAdmin = binary.BigEndian.Uint32(data[2:6])
		rt.LocalAdmin = uint32(binary.BigEndian.Uint16(data[6:8]))
	case 0x02:
		rt.Type = 2
		rt.GlobalAdmin = binary.BigEndian.Uint32(data[2:6])
		rt.LocalAdmin = uint32(binary.BigEndian.Uint16(data[6:8]))
	}
	return rt
}

// MACIPEntry represents a local MAC/IP binding for Type-2 routes.
type MACIPEntry struct {
	// MAC is the hardware address.
	MAC net.HardwareAddr

	// IP is the associated IP address (optional for MAC-only routes).
	IP netip.Addr

	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// VTEPIP is the VTEP IP address where this MAC/IP resides.
	VTEPIP netip.Addr

	// Sequence is the MAC mobility sequence number.
	Sequence uint32

	// EthernetTagID is the Ethernet Tag ID (typically 0 for VXLAN).
	EthernetTagID uint32

	// CreatedAt is when this entry was created.
	CreatedAt time.Time

	// UpdatedAt is when this entry was last updated.
	UpdatedAt time.Time
}

// Key returns a unique key for this entry: "VNI:MAC".
func (e *MACIPEntry) Key() string {
	if e == nil {
		return ""
	}
	return formatKey(e.VNI, e.MAC.String())
}

// MACIPKey returns a unique key for MAC+IP: "VNI:MAC:IP".
func (e *MACIPEntry) MACIPKey() string {
	if e == nil {
		return ""
	}
	if !e.IP.IsValid() {
		return formatKey(e.VNI, e.MAC.String())
	}
	return formatKeyThree(e.VNI, e.MAC.String(), e.IP.String())
}

// HasIP returns true if this entry has an associated IP address.
func (e *MACIPEntry) HasIP() bool {
	return e != nil && e.IP.IsValid()
}

// Clone creates a deep copy of the entry.
func (e *MACIPEntry) Clone() *MACIPEntry {
	if e == nil {
		return nil
	}
	clone := &MACIPEntry{
		IP:            e.IP,
		VNI:           e.VNI,
		VTEPIP:        e.VTEPIP,
		Sequence:      e.Sequence,
		EthernetTagID: e.EthernetTagID,
		CreatedAt:     e.CreatedAt,
		UpdatedAt:     e.UpdatedAt,
	}
	if e.MAC != nil {
		clone.MAC = make(net.HardwareAddr, len(e.MAC))
		copy(clone.MAC, e.MAC)
	}
	return clone
}

// IMETEntry represents an Inclusive Multicast Ethernet Tag entry for Type-3 routes.
type IMETEntry struct {
	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// VTEPIP is the VTEP IP address participating in this VNI.
	VTEPIP netip.Addr

	// EthernetTagID is the Ethernet Tag ID (typically 0 for VXLAN).
	EthernetTagID uint32

	// TunnelType indicates the tunnel encapsulation type.
	TunnelType uint8

	// CreatedAt is when this entry was created.
	CreatedAt time.Time
}

// Key returns a unique key for this entry: "VNI:VTEPIP".
func (e *IMETEntry) Key() string {
	if e == nil {
		return ""
	}
	return formatKey(e.VNI, e.VTEPIP.String())
}

// Clone creates a deep copy of the entry.
func (e *IMETEntry) Clone() *IMETEntry {
	if e == nil {
		return nil
	}
	return &IMETEntry{
		VNI:           e.VNI,
		VTEPIP:        e.VTEPIP,
		EthernetTagID: e.EthernetTagID,
		TunnelType:    e.TunnelType,
		CreatedAt:     e.CreatedAt,
	}
}

// PrefixRoute represents a Type-5 IP Prefix route.
type PrefixRoute struct {
	// Prefix is the IP prefix being advertised.
	Prefix netip.Prefix

	// VNI is the VXLAN Network Identifier for the L3 VNI.
	VNI uint32

	// GatewayIP is the gateway IP address (optional).
	GatewayIP netip.Addr

	// NextHop is the BGP next-hop address (VTEP IP).
	NextHop netip.Addr

	// EthernetTagID is the Ethernet Tag ID.
	EthernetTagID uint32

	// RouteTargets are the route targets for this prefix.
	RouteTargets []RouteTarget

	// GatewayMAC is the gateway MAC address (optional).
	GatewayMAC net.HardwareAddr

	// CreatedAt is when this route was created.
	CreatedAt time.Time

	// UpdatedAt is when this route was last updated.
	UpdatedAt time.Time
}

// Key returns a unique key for this route: "VNI:Prefix".
func (r *PrefixRoute) Key() string {
	if r == nil {
		return ""
	}
	return formatKey(r.VNI, r.Prefix.String())
}

// HasGateway returns true if this route has a gateway IP.
func (r *PrefixRoute) HasGateway() bool {
	return r != nil && r.GatewayIP.IsValid()
}

// Clone creates a deep copy of the route.
func (r *PrefixRoute) Clone() *PrefixRoute {
	if r == nil {
		return nil
	}
	clone := &PrefixRoute{
		Prefix:        r.Prefix,
		VNI:           r.VNI,
		GatewayIP:     r.GatewayIP,
		NextHop:       r.NextHop,
		EthernetTagID: r.EthernetTagID,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
	if len(r.RouteTargets) > 0 {
		clone.RouteTargets = make([]RouteTarget, len(r.RouteTargets))
		copy(clone.RouteTargets, r.RouteTargets)
	}
	if r.GatewayMAC != nil {
		clone.GatewayMAC = make(net.HardwareAddr, len(r.GatewayMAC))
		copy(clone.GatewayMAC, r.GatewayMAC)
	}
	return clone
}

// EVPNRouteData represents the internal EVPN route data for processing.
type EVPNRouteData struct {
	// Type is the EVPN route type.
	Type EVPNRouteType

	// RD is the Route Distinguisher.
	RD RouteDistinguisher

	// RouteTargets are the route targets for import/export.
	RouteTargets []RouteTarget

	// MACIP holds Type-2 route data.
	MACIP *MACIPEntry

	// IMET holds Type-3 route data.
	IMET *IMETEntry

	// Prefix holds Type-5 route data.
	PrefixData *PrefixRoute

	// NextHop is the BGP next-hop address.
	NextHop netip.Addr

	// Label is the MPLS label (VNI in VXLAN context).
	Label uint32

	// IsWithdraw indicates if this is a route withdrawal.
	IsWithdraw bool

	// ReceivedAt is when this route was received.
	ReceivedAt time.Time
}

// Clone creates a deep copy of the route.
func (r *EVPNRouteData) Clone() *EVPNRouteData {
	if r == nil {
		return nil
	}
	clone := &EVPNRouteData{
		Type:       r.Type,
		RD:         r.RD,
		NextHop:    r.NextHop,
		Label:      r.Label,
		IsWithdraw: r.IsWithdraw,
		ReceivedAt: r.ReceivedAt,
	}
	if len(r.RouteTargets) > 0 {
		clone.RouteTargets = make([]RouteTarget, len(r.RouteTargets))
		copy(clone.RouteTargets, r.RouteTargets)
	}
	clone.MACIP = r.MACIP.Clone()
	clone.IMET = r.IMET.Clone()
	clone.PrefixData = r.PrefixData.Clone()
	return clone
}

// MACMobilityEntry tracks MAC mobility sequence numbers.
type MACMobilityEntry struct {
	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// MAC is the hardware address.
	MAC net.HardwareAddr

	// Sequence is the current mobility sequence number.
	Sequence uint32

	// CurrentVTEP is the VTEP where the MAC currently resides.
	CurrentVTEP netip.Addr

	// MoveCount tracks the number of times this MAC has moved.
	MoveCount uint32

	// LastMoveTime is when this MAC last moved.
	LastMoveTime time.Time
}

// Key returns a unique key for this entry: "VNI:MAC".
func (e *MACMobilityEntry) Key() string {
	if e == nil {
		return ""
	}
	return formatKey(e.VNI, e.MAC.String())
}

// EVPNSpeaker defines the interface for a BGP speaker that supports EVPN operations.
type EVPNSpeaker interface {
	// AddEVPNPath adds an EVPN path to the BGP RIB.
	AddEVPNPath(ctx context.Context, nlri []byte, attrs []byte) error

	// DeleteEVPNPath deletes an EVPN path from the BGP RIB.
	DeleteEVPNPath(ctx context.Context, nlri []byte) error

	// LocalASN returns the local ASN.
	LocalASN() uint32

	// RouterID returns the router ID.
	RouterID() netip.Addr
}

// EVPNRouteHandler is called when EVPN routes are received or withdrawn.
type EVPNRouteHandler func(ctx context.Context, route *EVPNRouteData) error

// EVPNManager handles EVPN route operations for VXLAN overlay networking.
type EVPNManager struct {
	speaker EVPNSpeaker
	logger  *slog.Logger

	// Local MAC/IP table for Type-2 routes (key: VNI:MAC)
	localMACs sync.Map

	// Remote MAC/IP table learned via EVPN (key: VNI:MAC)
	remoteMACs sync.Map

	// IP to MAC lookup table for ARP suppression (key: VNI:IP)
	ipToMAC sync.Map

	// MAC to IP lookup table for ARP suppression (key: VNI:MAC)
	macToIP sync.Map

	// IMET entries for Type-3 routes (key: VNI:VTEPIP)
	imetEntries sync.Map

	// Local IMET advertisements (key: VNI)
	localIMET sync.Map

	// VTEPs per VNI for BUM replication (key: VNI, value: map[VTEPIP]struct{})
	vniVTEPs sync.Map

	// Prefix routes for Type-5 (key: VNI:Prefix)
	prefixRoutes sync.Map

	// MAC mobility tracking (key: VNI:MAC)
	macMobility sync.Map

	// Route targets for import/export
	importRT []RouteTarget
	exportRT []RouteTarget

	// Route Distinguisher
	rd RouteDistinguisher

	// Local VTEP IP
	localVTEP netip.Addr

	// Route handlers
	handlers []EVPNRouteHandler

	// Manager state
	started atomic.Bool
}

// EVPNManagerConfig holds configuration for the EVPN manager.
type EVPNManagerConfig struct {
	// Speaker is the BGP speaker interface.
	Speaker EVPNSpeaker

	// Logger for logging operations.
	Logger *slog.Logger

	// RD is the Route Distinguisher.
	RD RouteDistinguisher

	// ImportRT are the route targets for route import.
	ImportRT []RouteTarget

	// ExportRT are the route targets for route export.
	ExportRT []RouteTarget

	// LocalVTEP is the local VTEP IP address.
	LocalVTEP netip.Addr
}

// Validate validates the EVPN manager configuration.
func (c *EVPNManagerConfig) Validate() error {
	if c.Speaker == nil {
		return ErrSpeakerNil
	}
	if c.Logger == nil {
		return ErrLoggerNil
	}
	if !c.LocalVTEP.IsValid() {
		return ErrInvalidIP{IP: c.LocalVTEP, Reason: "local VTEP IP is invalid"}
	}
	if c.LocalVTEP.IsUnspecified() {
		return ErrInvalidIP{IP: c.LocalVTEP, Reason: "local VTEP IP is unspecified"}
	}
	return nil
}

// NewEVPNManager creates a new EVPN manager.
func NewEVPNManager(config *EVPNManagerConfig) (*EVPNManager, error) {
	if config == nil {
		return nil, ErrEntryNil{EntryType: "EVPNManagerConfig"}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	m := &EVPNManager{
		speaker:   config.Speaker,
		logger:    config.Logger,
		rd:        config.RD,
		localVTEP: config.LocalVTEP,
	}

	if len(config.ImportRT) > 0 {
		m.importRT = make([]RouteTarget, len(config.ImportRT))
		copy(m.importRT, config.ImportRT)
	}

	if len(config.ExportRT) > 0 {
		m.exportRT = make([]RouteTarget, len(config.ExportRT))
		copy(m.exportRT, config.ExportRT)
	}

	return m, nil
}

// Start starts the EVPN manager.
func (m *EVPNManager) Start(ctx context.Context) error {
	if m.started.Swap(true) {
		return ErrManagerAlreadyStarted
	}
	m.logger.Info("EVPN manager started",
		slog.String("local_vtep", m.localVTEP.String()))
	return nil
}

// Stop stops the EVPN manager.
func (m *EVPNManager) Stop(ctx context.Context) error {
	if !m.started.Swap(false) {
		return ErrManagerNotStarted
	}
	m.logger.Info("EVPN manager stopped")
	return nil
}

// RegisterHandler registers a handler for EVPN route events.
func (m *EVPNManager) RegisterHandler(handler EVPNRouteHandler) {
	m.handlers = append(m.handlers, handler)
}

// --- Type-2: MAC/IP Advertisement ---

// AdvertiseMAC announces a local MAC address (Type-2 route without IP).
func (m *EVPNManager) AdvertiseMAC(ctx context.Context, entry *MACIPEntry) error {
	if entry == nil {
		return ErrEntryNil{EntryType: "MACIPEntry"}
	}
	if err := validateMACIPEntry(entry); err != nil {
		return err
	}

	// Store locally
	key := entry.Key()
	now := time.Now()
	entry.CreatedAt = now
	entry.UpdatedAt = now
	entry.VTEPIP = m.localVTEP
	m.localMACs.Store(key, entry.Clone())

	// Build and advertise Type-2 route
	nlri, err := m.buildType2NLRI(entry)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	attrs := m.buildEVPNAttributes(m.localVTEP, entry.VNI)
	if err := m.speaker.AddEVPNPath(ctx, nlri, attrs); err != nil {
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	m.logger.Debug("advertised MAC",
		slog.String("mac", entry.MAC.String()),
		slog.Uint64("vni", uint64(entry.VNI)))

	return nil
}

// WithdrawMAC withdraws a MAC advertisement.
func (m *EVPNManager) WithdrawMAC(ctx context.Context, vni uint32, mac net.HardwareAddr) error {
	if err := validateVNI(vni); err != nil {
		return err
	}
	if err := validateMAC(mac); err != nil {
		return err
	}

	key := formatKey(vni, mac.String())

	// Check if entry exists
	val, ok := m.localMACs.Load(key)
	if !ok {
		return ErrMACNotFound{VNI: vni, MAC: mac}
	}
	entry := val.(*MACIPEntry)

	// Build and withdraw Type-2 route
	nlri, err := m.buildType2NLRI(entry)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	if err := m.speaker.DeleteEVPNPath(ctx, nlri); err != nil {
		return ErrRouteWithdrawalFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	m.localMACs.Delete(key)

	m.logger.Debug("withdrew MAC",
		slog.String("mac", mac.String()),
		slog.Uint64("vni", uint64(vni)))

	return nil
}

// AdvertiseMACIP announces a MAC+IP binding (Type-2 route with IP for ARP suppression).
func (m *EVPNManager) AdvertiseMACIP(ctx context.Context, entry *MACIPEntry) error {
	if entry == nil {
		return ErrEntryNil{EntryType: "MACIPEntry"}
	}
	if !entry.HasIP() {
		return ErrInvalidIP{IP: entry.IP, Reason: "IP address required for MAC/IP advertisement"}
	}
	if err := validateMACIPEntry(entry); err != nil {
		return err
	}

	// Store locally
	key := entry.MACIPKey()
	now := time.Now()
	entry.CreatedAt = now
	entry.UpdatedAt = now
	entry.VTEPIP = m.localVTEP
	m.localMACs.Store(key, entry.Clone())

	// Update ARP suppression tables
	ipKey := formatKey(entry.VNI, entry.IP.String())
	macKey := entry.Key()
	m.ipToMAC.Store(ipKey, entry.MAC)
	m.macToIP.Store(macKey, entry.IP)

	// Build and advertise Type-2 route with IP
	nlri, err := m.buildType2NLRI(entry)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	attrs := m.buildEVPNAttributes(m.localVTEP, entry.VNI)
	if err := m.speaker.AddEVPNPath(ctx, nlri, attrs); err != nil {
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	m.logger.Debug("advertised MAC/IP",
		slog.String("mac", entry.MAC.String()),
		slog.String("ip", entry.IP.String()),
		slog.Uint64("vni", uint64(entry.VNI)))

	return nil
}

// WithdrawMACIP withdraws a MAC+IP advertisement.
func (m *EVPNManager) WithdrawMACIP(ctx context.Context, vni uint32, mac net.HardwareAddr, ip netip.Addr) error {
	if err := validateVNI(vni); err != nil {
		return err
	}
	if err := validateMAC(mac); err != nil {
		return err
	}
	if !ip.IsValid() {
		return ErrInvalidIP{IP: ip, Reason: "IP address is invalid"}
	}

	key := formatKeyThree(vni, mac.String(), ip.String())

	// Check if entry exists
	val, ok := m.localMACs.Load(key)
	if !ok {
		return ErrMACIPNotFound{VNI: vni, MAC: mac, IP: ip}
	}
	entry := val.(*MACIPEntry)

	// Build and withdraw Type-2 route
	nlri, err := m.buildType2NLRI(entry)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	if err := m.speaker.DeleteEVPNPath(ctx, nlri); err != nil {
		return ErrRouteWithdrawalFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}

	// Remove from ARP suppression tables
	ipKey := formatKey(vni, ip.String())
	macKey := formatKey(vni, mac.String())
	m.ipToMAC.Delete(ipKey)
	m.macToIP.Delete(macKey)
	m.localMACs.Delete(key)

	m.logger.Debug("withdrew MAC/IP",
		slog.String("mac", mac.String()),
		slog.String("ip", ip.String()),
		slog.Uint64("vni", uint64(vni)))

	return nil
}

// GetRemoteMAC looks up a remote MAC learned via EVPN.
func (m *EVPNManager) GetRemoteMAC(ctx context.Context, vni uint32, mac net.HardwareAddr) (*MACIPEntry, error) {
	if err := validateVNI(vni); err != nil {
		return nil, err
	}
	if err := validateMAC(mac); err != nil {
		return nil, err
	}

	key := formatKey(vni, mac.String())
	val, ok := m.remoteMACs.Load(key)
	if !ok {
		return nil, ErrMACNotFound{VNI: vni, MAC: mac}
	}

	entry := val.(*MACIPEntry)
	return entry.Clone(), nil
}

// ListRemoteMACs returns all remote MACs for a VNI.
func (m *EVPNManager) ListRemoteMACs(ctx context.Context, vni uint32) ([]*MACIPEntry, error) {
	if err := validateVNI(vni); err != nil {
		return nil, err
	}

	var entries []*MACIPEntry
	prefix := formatUint32(vni) + ":"

	m.remoteMACs.Range(func(key, value any) bool {
		k := key.(string)
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			entry := value.(*MACIPEntry)
			entries = append(entries, entry.Clone())
		}
		return true
	})

	return entries, nil
}

// --- Type-3: Inclusive Multicast ---

// AdvertiseIMET announces inclusive multicast for a VNI (ingress replication).
func (m *EVPNManager) AdvertiseIMET(ctx context.Context, vni uint32, vtepIP netip.Addr) error {
	if err := validateVNI(vni); err != nil {
		return err
	}
	if !vtepIP.IsValid() || vtepIP.IsUnspecified() {
		return ErrInvalidIP{IP: vtepIP, Reason: "VTEP IP is invalid or unspecified"}
	}

	entry := &IMETEntry{
		VNI:           vni,
		VTEPIP:        vtepIP,
		EthernetTagID: 0,
		TunnelType:    TunnelTypeIngressReplication,
		CreatedAt:     time.Now(),
	}

	// Store locally
	key := entry.Key()
	m.localIMET.Store(vni, entry.Clone())
	m.imetEntries.Store(key, entry.Clone())

	// Add to VNI VTEP list
	m.addVNIVTEP(vni, vtepIP)

	// Build and advertise Type-3 route
	nlri, err := m.buildType3NLRI(entry)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeInclusiveMulticast, Cause: err}
	}

	attrs := m.buildEVPNAttributes(vtepIP, vni)
	if err := m.speaker.AddEVPNPath(ctx, nlri, attrs); err != nil {
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeInclusiveMulticast, Cause: err}
	}

	m.logger.Debug("advertised IMET",
		slog.Uint64("vni", uint64(vni)),
		slog.String("vtep", vtepIP.String()))

	return nil
}

// WithdrawIMET withdraws inclusive multicast for a VNI.
func (m *EVPNManager) WithdrawIMET(ctx context.Context, vni uint32) error {
	if err := validateVNI(vni); err != nil {
		return err
	}

	// Check if entry exists
	val, ok := m.localIMET.Load(vni)
	if !ok {
		return ErrIMETNotFound{VNI: vni}
	}
	entry := val.(*IMETEntry)

	// Build and withdraw Type-3 route
	nlri, err := m.buildType3NLRI(entry)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeInclusiveMulticast, Cause: err}
	}

	if err := m.speaker.DeleteEVPNPath(ctx, nlri); err != nil {
		return ErrRouteWithdrawalFailed{RouteType: EVPNTypeInclusiveMulticast, Cause: err}
	}

	// Remove from stores
	key := entry.Key()
	m.localIMET.Delete(vni)
	m.imetEntries.Delete(key)
	m.removeVNIVTEP(vni, entry.VTEPIP)

	m.logger.Debug("withdrew IMET",
		slog.Uint64("vni", uint64(vni)))

	return nil
}

// GetIMETVTEPs returns all VTEPs participating in a VNI (for BUM replication).
func (m *EVPNManager) GetIMETVTEPs(ctx context.Context, vni uint32) ([]netip.Addr, error) {
	if err := validateVNI(vni); err != nil {
		return nil, err
	}

	val, ok := m.vniVTEPs.Load(vni)
	if !ok {
		return []netip.Addr{}, nil
	}

	vtepsMap := val.(*sync.Map)
	var vteps []netip.Addr

	vtepsMap.Range(func(key, _ any) bool {
		vtep := key.(netip.Addr)
		vteps = append(vteps, vtep)
		return true
	})

	return vteps, nil
}

// --- Type-5: IP Prefix ---

// AdvertisePrefix announces an IP prefix route (Type-5).
func (m *EVPNManager) AdvertisePrefix(ctx context.Context, prefix netip.Prefix, vni uint32, gatewayIP netip.Addr) error {
	if !prefix.IsValid() {
		return ErrPrefixInvalid{Prefix: prefix, Reason: "prefix is invalid"}
	}
	if err := validateVNI(vni); err != nil {
		return err
	}

	now := time.Now()
	route := &PrefixRoute{
		Prefix:        prefix,
		VNI:           vni,
		GatewayIP:     gatewayIP,
		NextHop:       m.localVTEP,
		EthernetTagID: 0,
		RouteTargets:  m.exportRT,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Store locally
	key := route.Key()
	m.prefixRoutes.Store(key, route.Clone())

	// Build and advertise Type-5 route
	nlri, err := m.buildType5NLRI(route)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeIPPrefix, Cause: err}
	}

	attrs := m.buildEVPNAttributes(m.localVTEP, vni)
	if err := m.speaker.AddEVPNPath(ctx, nlri, attrs); err != nil {
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeIPPrefix, Cause: err}
	}

	m.logger.Debug("advertised prefix",
		slog.String("prefix", prefix.String()),
		slog.Uint64("vni", uint64(vni)),
		slog.String("gateway", gatewayIP.String()))

	return nil
}

// WithdrawPrefix withdraws an IP prefix route.
func (m *EVPNManager) WithdrawPrefix(ctx context.Context, prefix netip.Prefix, vni uint32) error {
	if !prefix.IsValid() {
		return ErrPrefixInvalid{Prefix: prefix, Reason: "prefix is invalid"}
	}
	if err := validateVNI(vni); err != nil {
		return err
	}

	key := formatKey(vni, prefix.String())

	// Check if route exists
	val, ok := m.prefixRoutes.Load(key)
	if !ok {
		return ErrPrefixNotFound{VNI: vni, Prefix: prefix}
	}
	route := val.(*PrefixRoute)

	// Build and withdraw Type-5 route
	nlri, err := m.buildType5NLRI(route)
	if err != nil {
		return ErrRouteEncodingFailed{RouteType: EVPNTypeIPPrefix, Cause: err}
	}

	if err := m.speaker.DeleteEVPNPath(ctx, nlri); err != nil {
		return ErrRouteWithdrawalFailed{RouteType: EVPNTypeIPPrefix, Cause: err}
	}

	m.prefixRoutes.Delete(key)

	m.logger.Debug("withdrew prefix",
		slog.String("prefix", prefix.String()),
		slog.Uint64("vni", uint64(vni)))

	return nil
}

// GetPrefixRoutes returns all Type-5 routes for a VNI.
func (m *EVPNManager) GetPrefixRoutes(ctx context.Context, vni uint32) ([]*PrefixRoute, error) {
	if err := validateVNI(vni); err != nil {
		return nil, err
	}

	var routes []*PrefixRoute
	prefix := formatUint32(vni) + ":"

	m.prefixRoutes.Range(func(key, value any) bool {
		k := key.(string)
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			route := value.(*PrefixRoute)
			routes = append(routes, route.Clone())
		}
		return true
	})

	return routes, nil
}

// --- Route Building Helpers ---

// buildType2NLRI creates an EVPN Type-2 NLRI.
// Type-2 NLRI format:
// - Route Distinguisher (8 bytes)
// - Ethernet Tag ID (4 bytes)
// - MAC Address Length (1 byte) = 48
// - MAC Address (6 bytes)
// - IP Address Length (1 byte) = 0, 32, or 128
// - IP Address (0, 4, or 16 bytes)
// - MPLS Label (3 bytes)
func (m *EVPNManager) buildType2NLRI(entry *MACIPEntry) ([]byte, error) {
	ipLen := 0
	if entry.HasIP() {
		if entry.IP.Is4() {
			ipLen = 32
		} else {
			ipLen = 128
		}
	}

	// Calculate total length
	nlriLen := 8 + 4 + 1 + 6 + 1 + (ipLen / 8) + 3
	nlri := make([]byte, nlriLen+2) // +2 for route type and length

	nlri[0] = byte(EVPNTypeMACIPAdvertisement)
	nlri[1] = byte(nlriLen)

	offset := 2

	// Route Distinguisher
	rdBytes := m.rd.Bytes()
	copy(nlri[offset:], rdBytes[:])
	offset += 8

	// Ethernet Tag ID
	binary.BigEndian.PutUint32(nlri[offset:], entry.EthernetTagID)
	offset += 4

	// MAC Address Length (in bits)
	nlri[offset] = 48
	offset++

	// MAC Address
	copy(nlri[offset:], entry.MAC)
	offset += 6

	// IP Address Length (in bits)
	nlri[offset] = byte(ipLen)
	offset++

	// IP Address (if present)
	if ipLen > 0 {
		ipBytes := entry.IP.AsSlice()
		copy(nlri[offset:], ipBytes)
		offset += len(ipBytes)
	}

	// MPLS Label (VNI << 4, with bottom-of-stack bit)
	label := (entry.VNI << 4) | 0x01
	nlri[offset] = byte(label >> 16)
	nlri[offset+1] = byte(label >> 8)
	nlri[offset+2] = byte(label)

	return nlri, nil
}

// buildType3NLRI creates an EVPN Type-3 NLRI.
// Type-3 NLRI format:
// - Route Distinguisher (8 bytes)
// - Ethernet Tag ID (4 bytes)
// - IP Address Length (1 byte)
// - Originating Router's IP Address (4 or 16 bytes)
func (m *EVPNManager) buildType3NLRI(entry *IMETEntry) ([]byte, error) {
	ipLen := 32
	ipBytes := entry.VTEPIP.AsSlice()
	if entry.VTEPIP.Is6() {
		ipLen = 128
	}

	nlriLen := 8 + 4 + 1 + len(ipBytes)
	nlri := make([]byte, nlriLen+2) // +2 for route type and length

	nlri[0] = byte(EVPNTypeInclusiveMulticast)
	nlri[1] = byte(nlriLen)

	offset := 2

	// Route Distinguisher
	rdBytes := m.rd.Bytes()
	copy(nlri[offset:], rdBytes[:])
	offset += 8

	// Ethernet Tag ID
	binary.BigEndian.PutUint32(nlri[offset:], entry.EthernetTagID)
	offset += 4

	// IP Address Length (in bits)
	nlri[offset] = byte(ipLen)
	offset++

	// Originating Router's IP Address
	copy(nlri[offset:], ipBytes)

	return nlri, nil
}

// buildType5NLRI creates an EVPN Type-5 NLRI.
// Type-5 NLRI format:
// - Route Distinguisher (8 bytes)
// - Ethernet Segment Identifier (10 bytes, all zeros for single-homed)
// - Ethernet Tag ID (4 bytes)
// - IP Prefix Length (1 byte)
// - IP Prefix (variable)
// - Gateway IP (4 or 16 bytes)
// - MPLS Label (3 bytes)
func (m *EVPNManager) buildType5NLRI(route *PrefixRoute) ([]byte, error) {
	prefixBits := route.Prefix.Bits()
	prefixBytes := (prefixBits + 7) / 8
	prefixIP := route.Prefix.Addr().AsSlice()

	// Determine gateway IP size
	gwLen := 4
	var gwIP []byte
	if route.HasGateway() {
		gwIP = route.GatewayIP.AsSlice()
		gwLen = len(gwIP)
	} else {
		gwIP = make([]byte, 4) // zero gateway
	}

	// ESI (10 bytes, all zeros for single-homed)
	esiLen := 10

	nlriLen := 8 + esiLen + 4 + 1 + prefixBytes + gwLen + 3
	nlri := make([]byte, nlriLen+2) // +2 for route type and length

	nlri[0] = byte(EVPNTypeIPPrefix)
	nlri[1] = byte(nlriLen)

	offset := 2

	// Route Distinguisher
	rdBytes := m.rd.Bytes()
	copy(nlri[offset:], rdBytes[:])
	offset += 8

	// Ethernet Segment Identifier (all zeros)
	offset += esiLen

	// Ethernet Tag ID
	binary.BigEndian.PutUint32(nlri[offset:], route.EthernetTagID)
	offset += 4

	// IP Prefix Length
	nlri[offset] = byte(prefixBits)
	offset++

	// IP Prefix
	copy(nlri[offset:], prefixIP[:prefixBytes])
	offset += prefixBytes

	// Gateway IP
	copy(nlri[offset:], gwIP)
	offset += gwLen

	// MPLS Label (VNI << 4, with bottom-of-stack bit)
	label := (route.VNI << 4) | 0x01
	nlri[offset] = byte(label >> 16)
	nlri[offset+1] = byte(label >> 8)
	nlri[offset+2] = byte(label)

	return nlri, nil
}

// buildEVPNAttributes builds BGP path attributes for EVPN routes.
func (m *EVPNManager) buildEVPNAttributes(nextHop netip.Addr, vni uint32) []byte {
	// This is a simplified attribute builder. In production, you would use
	// the GoBGP attribute builder or construct proper BGP path attributes.
	// Attributes include: ORIGIN, AS_PATH, MP_REACH_NLRI, EXTENDED_COMMUNITIES

	// For now, we return a placeholder that would be replaced by proper
	// attribute encoding when integrating with the actual BGP speaker.
	attrs := make([]byte, 32)

	// Encode next-hop in first 16 bytes
	nhBytes := nextHop.AsSlice()
	copy(attrs[0:], nhBytes)

	// Encode VNI in next 4 bytes
	binary.BigEndian.PutUint32(attrs[16:], vni)

	// Encode route targets
	for i, rt := range m.exportRT {
		if i >= 1 { // Only first RT for simplicity
			break
		}
		rtBytes := rt.Bytes()
		copy(attrs[20:], rtBytes[:])
	}

	return attrs
}

// parseEVPNRoute parses EVPN NLRI into our internal types.
func parseEVPNRoute(nlri []byte) (*EVPNRouteData, error) {
	if len(nlri) < 2 {
		return nil, ErrNLRITooShort{Expected: 2, Actual: len(nlri)}
	}

	routeType := EVPNRouteType(nlri[0])
	length := int(nlri[1])

	if len(nlri) < length+2 {
		return nil, ErrNLRITooShort{Expected: length + 2, Actual: len(nlri)}
	}

	route := &EVPNRouteData{
		Type:       routeType,
		ReceivedAt: time.Now(),
	}

	// Parse Route Distinguisher (common to all types)
	if length < 8 {
		return nil, ErrNLRITooShort{Expected: 8, Actual: length}
	}
	var rdData [8]byte
	copy(rdData[:], nlri[2:10])
	route.RD = ParseRouteDistinguisher(rdData)

	switch routeType {
	case EVPNTypeMACIPAdvertisement:
		return parseType2Route(nlri, route)
	case EVPNTypeInclusiveMulticast:
		return parseType3Route(nlri, route)
	case EVPNTypeIPPrefix:
		return parseType5Route(nlri, route)
	default:
		return nil, ErrUnsupportedRouteType{RouteType: routeType}
	}
}

// parseType2Route parses a Type-2 MAC/IP Advertisement route.
func parseType2Route(nlri []byte, route *EVPNRouteData) (*EVPNRouteData, error) {
	if len(nlri) < evpnType2MinLen {
		return nil, ErrNLRITooShort{Expected: evpnType2MinLen, Actual: len(nlri)}
	}

	offset := 2 // Skip route type and length

	// Skip RD (already parsed)
	offset += 8

	// Ethernet Tag ID
	etag := binary.BigEndian.Uint32(nlri[offset:])
	offset += 4

	// MAC Address Length (should be 48)
	macLen := int(nlri[offset])
	offset++
	if macLen != 48 {
		return nil, ErrInvalidNLRI{Reason: "MAC length must be 48 bits"}
	}

	// MAC Address
	mac := make(net.HardwareAddr, 6)
	copy(mac, nlri[offset:offset+6])
	offset += 6

	// IP Address Length
	ipLen := int(nlri[offset])
	offset++

	var ip netip.Addr
	switch ipLen {
	case 32:
		ip = netip.AddrFrom4([4]byte{nlri[offset], nlri[offset+1], nlri[offset+2], nlri[offset+3]})
		offset += 4
	case 128:
		var ipBytes [16]byte
		copy(ipBytes[:], nlri[offset:offset+16])
		ip = netip.AddrFrom16(ipBytes)
		offset += 16
	}

	// MPLS Label (VNI)
	if offset+3 > len(nlri) {
		return nil, ErrNLRITooShort{Expected: offset + 3, Actual: len(nlri)}
	}
	label := uint32(nlri[offset])<<16 | uint32(nlri[offset+1])<<8 | uint32(nlri[offset+2])
	vni := label >> 4

	route.MACIP = &MACIPEntry{
		MAC:           mac,
		IP:            ip,
		VNI:           vni,
		EthernetTagID: etag,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	route.Label = vni

	return route, nil
}

// parseType3Route parses a Type-3 Inclusive Multicast route.
func parseType3Route(nlri []byte, route *EVPNRouteData) (*EVPNRouteData, error) {
	if len(nlri) < evpnType3MinLen {
		return nil, ErrNLRITooShort{Expected: evpnType3MinLen, Actual: len(nlri)}
	}

	offset := 2 // Skip route type and length

	// Skip RD (already parsed)
	offset += 8

	// Ethernet Tag ID
	etag := binary.BigEndian.Uint32(nlri[offset:])
	offset += 4

	// IP Address Length
	ipLen := int(nlri[offset])
	offset++

	var vtepIP netip.Addr
	switch ipLen {
	case 32:
		vtepIP = netip.AddrFrom4([4]byte{nlri[offset], nlri[offset+1], nlri[offset+2], nlri[offset+3]})
	case 128:
		var ipBytes [16]byte
		copy(ipBytes[:], nlri[offset:offset+16])
		vtepIP = netip.AddrFrom16(ipBytes)
	default:
		return nil, ErrInvalidNLRI{Reason: "invalid IP address length in Type-3 route"}
	}

	route.IMET = &IMETEntry{
		VTEPIP:        vtepIP,
		EthernetTagID: etag,
		TunnelType:    TunnelTypeIngressReplication,
		CreatedAt:     time.Now(),
	}

	return route, nil
}

// parseType5Route parses a Type-5 IP Prefix route.
func parseType5Route(nlri []byte, route *EVPNRouteData) (*EVPNRouteData, error) {
	if len(nlri) < evpnType5MinLen {
		return nil, ErrNLRITooShort{Expected: evpnType5MinLen, Actual: len(nlri)}
	}

	offset := 2 // Skip route type and length

	// Skip RD (already parsed)
	offset += 8

	// Skip ESI (10 bytes)
	offset += 10

	// Ethernet Tag ID
	etag := binary.BigEndian.Uint32(nlri[offset:])
	offset += 4

	// IP Prefix Length
	prefixLen := int(nlri[offset])
	offset++

	// Determine if IPv4 or IPv6 based on prefix length
	prefixBytes := (prefixLen + 7) / 8
	isIPv6 := prefixLen > 32 || (len(nlri) > offset+prefixBytes+16+3)

	var prefix netip.Prefix
	if isIPv6 {
		var ipBytes [16]byte
		copy(ipBytes[:], nlri[offset:offset+prefixBytes])
		addr := netip.AddrFrom16(ipBytes)
		prefix = netip.PrefixFrom(addr, prefixLen)
		offset += 16
	} else {
		var ipBytes [4]byte
		copy(ipBytes[:], nlri[offset:offset+prefixBytes])
		addr := netip.AddrFrom4(ipBytes)
		prefix = netip.PrefixFrom(addr, prefixLen)
		offset += 4
	}

	// Gateway IP
	var gwIP netip.Addr
	if isIPv6 {
		var gwBytes [16]byte
		copy(gwBytes[:], nlri[offset:offset+16])
		gwIP = netip.AddrFrom16(gwBytes)
		offset += 16
	} else {
		gwIP = netip.AddrFrom4([4]byte{nlri[offset], nlri[offset+1], nlri[offset+2], nlri[offset+3]})
		offset += 4
	}

	// MPLS Label (VNI)
	if offset+3 > len(nlri) {
		return nil, ErrNLRITooShort{Expected: offset + 3, Actual: len(nlri)}
	}
	label := uint32(nlri[offset])<<16 | uint32(nlri[offset+1])<<8 | uint32(nlri[offset+2])
	vni := label >> 4

	route.PrefixData = &PrefixRoute{
		Prefix:        prefix,
		VNI:           vni,
		GatewayIP:     gwIP,
		EthernetTagID: etag,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	route.Label = vni

	return route, nil
}

// encodeEVPNRoute encodes our internal types to EVPN NLRI.
func encodeEVPNRoute(route *EVPNRouteData, rd RouteDistinguisher) ([]byte, error) {
	if route == nil {
		return nil, ErrEntryNil{EntryType: "EVPNRouteData"}
	}

	switch route.Type {
	case EVPNTypeMACIPAdvertisement:
		if route.MACIP == nil {
			return nil, ErrInvalidEVPNRoute{RouteType: route.Type, Reason: "MACIP data is nil"}
		}
		// Use a temporary manager just for encoding
		m := &EVPNManager{rd: rd}
		return m.buildType2NLRI(route.MACIP)
	case EVPNTypeInclusiveMulticast:
		if route.IMET == nil {
			return nil, ErrInvalidEVPNRoute{RouteType: route.Type, Reason: "IMET data is nil"}
		}
		m := &EVPNManager{rd: rd}
		return m.buildType3NLRI(route.IMET)
	case EVPNTypeIPPrefix:
		if route.PrefixData == nil {
			return nil, ErrInvalidEVPNRoute{RouteType: route.Type, Reason: "Prefix data is nil"}
		}
		m := &EVPNManager{rd: rd}
		return m.buildType5NLRI(route.PrefixData)
	default:
		return nil, ErrUnsupportedRouteType{RouteType: route.Type}
	}
}

// --- MAC Mobility ---

// HandleMACMove processes MAC mobility (same MAC from different VTEP).
func (m *EVPNManager) HandleMACMove(ctx context.Context, entry *MACIPEntry) error {
	if entry == nil {
		return ErrEntryNil{EntryType: "MACIPEntry"}
	}
	if err := validateMACIPEntry(entry); err != nil {
		return err
	}

	key := entry.Key()

	// Check if MAC exists with different VTEP
	val, exists := m.remoteMACs.Load(key)
	if !exists {
		// New MAC, just add it
		m.remoteMACs.Store(key, entry.Clone())
		if entry.HasIP() {
			ipKey := formatKey(entry.VNI, entry.IP.String())
			m.ipToMAC.Store(ipKey, entry.MAC)
			m.macToIP.Store(key, entry.IP)
		}
		return nil
	}

	existing := val.(*MACIPEntry)

	// Check if from same VTEP - just update
	if existing.VTEPIP == entry.VTEPIP {
		entry.Sequence = existing.Sequence
		entry.UpdatedAt = time.Now()
		m.remoteMACs.Store(key, entry.Clone())
		return nil
	}

	// MAC moved to different VTEP
	mobKey := key
	var mobility *MACMobilityEntry
	mobVal, mobExists := m.macMobility.Load(mobKey)
	if mobExists {
		mobility = mobVal.(*MACMobilityEntry)
	} else {
		mobility = &MACMobilityEntry{
			VNI: entry.VNI,
			MAC: entry.MAC,
		}
	}

	// Validate sequence number
	if entry.Sequence < mobility.Sequence {
		return ErrMACMobilityConflict{
			VNI:         entry.VNI,
			MAC:         entry.MAC,
			OldVTEP:     existing.VTEPIP,
			NewVTEP:     entry.VTEPIP,
			OldSequence: mobility.Sequence,
			NewSequence: entry.Sequence,
		}
	}

	// Update mobility tracking
	mobility.Sequence = entry.Sequence
	mobility.CurrentVTEP = entry.VTEPIP
	mobility.MoveCount++
	mobility.LastMoveTime = time.Now()
	m.macMobility.Store(mobKey, mobility)

	// Update MAC entry
	entry.UpdatedAt = time.Now()
	m.remoteMACs.Store(key, entry.Clone())

	// Update ARP suppression tables
	if entry.HasIP() {
		ipKey := formatKey(entry.VNI, entry.IP.String())
		m.ipToMAC.Store(ipKey, entry.MAC)
		m.macToIP.Store(key, entry.IP)
	}

	m.logger.Info("MAC moved",
		slog.String("mac", entry.MAC.String()),
		slog.Uint64("vni", uint64(entry.VNI)),
		slog.String("old_vtep", existing.VTEPIP.String()),
		slog.String("new_vtep", entry.VTEPIP.String()),
		slog.Uint64("sequence", uint64(entry.Sequence)))

	return nil
}

// GetMACSequence returns the current mobility sequence for a MAC.
func (m *EVPNManager) GetMACSequence(vni uint32, mac net.HardwareAddr) uint32 {
	key := formatKey(vni, mac.String())

	val, ok := m.macMobility.Load(key)
	if !ok {
		return 0
	}

	mobility := val.(*MACMobilityEntry)
	return mobility.Sequence
}

// IncrementMACSequence increments MAC mobility sequence and returns the new value.
func (m *EVPNManager) IncrementMACSequence(vni uint32, mac net.HardwareAddr) uint32 {
	key := formatKey(vni, mac.String())

	val, ok := m.macMobility.Load(key)
	if !ok {
		mobility := &MACMobilityEntry{
			VNI:          vni,
			MAC:          mac,
			Sequence:     1,
			CurrentVTEP:  m.localVTEP,
			LastMoveTime: time.Now(),
		}
		m.macMobility.Store(key, mobility)
		return 1
	}

	mobility := val.(*MACMobilityEntry)
	mobility.Sequence++
	mobility.LastMoveTime = time.Now()
	m.macMobility.Store(key, mobility)
	return mobility.Sequence
}

// --- Event Handling ---

// OnRouteReceived processes incoming EVPN routes.
func (m *EVPNManager) OnRouteReceived(ctx context.Context, route *EVPNRouteData) error {
	if route == nil {
		return ErrEntryNil{EntryType: "EVPNRouteData"}
	}

	switch route.Type {
	case EVPNTypeMACIPAdvertisement:
		return m.handleType2Received(ctx, route)
	case EVPNTypeInclusiveMulticast:
		return m.handleType3Received(ctx, route)
	case EVPNTypeIPPrefix:
		return m.handleType5Received(ctx, route)
	default:
		return ErrUnsupportedRouteType{RouteType: route.Type}
	}
}

// OnRouteWithdrawn processes EVPN route withdrawals.
func (m *EVPNManager) OnRouteWithdrawn(ctx context.Context, route *EVPNRouteData) error {
	if route == nil {
		return ErrEntryNil{EntryType: "EVPNRouteData"}
	}

	switch route.Type {
	case EVPNTypeMACIPAdvertisement:
		return m.handleType2Withdrawn(ctx, route)
	case EVPNTypeInclusiveMulticast:
		return m.handleType3Withdrawn(ctx, route)
	case EVPNTypeIPPrefix:
		return m.handleType5Withdrawn(ctx, route)
	default:
		return ErrUnsupportedRouteType{RouteType: route.Type}
	}
}

// handleType2Received processes a received Type-2 route.
func (m *EVPNManager) handleType2Received(ctx context.Context, route *EVPNRouteData) error {
	if route.MACIP == nil {
		return ErrInvalidEVPNRoute{RouteType: EVPNTypeMACIPAdvertisement, Reason: "MACIP data is nil"}
	}

	entry := route.MACIP.Clone()
	entry.VTEPIP = route.NextHop

	// Handle MAC mobility
	if err := m.HandleMACMove(ctx, entry); err != nil {
		return err
	}

	// Notify handlers
	for _, handler := range m.handlers {
		if err := handler(ctx, route); err != nil {
			m.logger.Error("handler error", slog.Any("error", err))
		}
	}

	return nil
}

// handleType3Received processes a received Type-3 route.
func (m *EVPNManager) handleType3Received(ctx context.Context, route *EVPNRouteData) error {
	if route.IMET == nil {
		return ErrInvalidEVPNRoute{RouteType: EVPNTypeInclusiveMulticast, Reason: "IMET data is nil"}
	}

	entry := route.IMET.Clone()

	// Store IMET entry
	key := entry.Key()
	m.imetEntries.Store(key, entry)

	// Add VTEP to VNI's VTEP list
	m.addVNIVTEP(entry.VNI, entry.VTEPIP)

	// Notify handlers
	for _, handler := range m.handlers {
		if err := handler(ctx, route); err != nil {
			m.logger.Error("handler error", slog.Any("error", err))
		}
	}

	return nil
}

// handleType5Received processes a received Type-5 route.
func (m *EVPNManager) handleType5Received(ctx context.Context, route *EVPNRouteData) error {
	if route.PrefixData == nil {
		return ErrInvalidEVPNRoute{RouteType: EVPNTypeIPPrefix, Reason: "Prefix data is nil"}
	}

	prefixRoute := route.PrefixData.Clone()
	prefixRoute.NextHop = route.NextHop

	// Store prefix route
	key := prefixRoute.Key()
	m.prefixRoutes.Store(key, prefixRoute)

	// Notify handlers
	for _, handler := range m.handlers {
		if err := handler(ctx, route); err != nil {
			m.logger.Error("handler error", slog.Any("error", err))
		}
	}

	return nil
}

// handleType2Withdrawn processes a Type-2 route withdrawal.
func (m *EVPNManager) handleType2Withdrawn(ctx context.Context, route *EVPNRouteData) error {
	if route.MACIP == nil {
		return ErrInvalidEVPNRoute{RouteType: EVPNTypeMACIPAdvertisement, Reason: "MACIP data is nil"}
	}

	entry := route.MACIP
	key := entry.Key()

	// Remove from remote MACs
	m.remoteMACs.Delete(key)

	// Remove from ARP suppression tables
	if entry.HasIP() {
		ipKey := formatKey(entry.VNI, entry.IP.String())
		m.ipToMAC.Delete(ipKey)
		m.macToIP.Delete(key)
	}

	// Notify handlers
	route.IsWithdraw = true
	for _, handler := range m.handlers {
		if err := handler(ctx, route); err != nil {
			m.logger.Error("handler error", slog.Any("error", err))
		}
	}

	return nil
}

// handleType3Withdrawn processes a Type-3 route withdrawal.
func (m *EVPNManager) handleType3Withdrawn(ctx context.Context, route *EVPNRouteData) error {
	if route.IMET == nil {
		return ErrInvalidEVPNRoute{RouteType: EVPNTypeInclusiveMulticast, Reason: "IMET data is nil"}
	}

	entry := route.IMET
	key := entry.Key()

	// Remove IMET entry
	m.imetEntries.Delete(key)

	// Remove VTEP from VNI's VTEP list
	m.removeVNIVTEP(entry.VNI, entry.VTEPIP)

	// Notify handlers
	route.IsWithdraw = true
	for _, handler := range m.handlers {
		if err := handler(ctx, route); err != nil {
			m.logger.Error("handler error", slog.Any("error", err))
		}
	}

	return nil
}

// handleType5Withdrawn processes a Type-5 route withdrawal.
func (m *EVPNManager) handleType5Withdrawn(ctx context.Context, route *EVPNRouteData) error {
	if route.PrefixData == nil {
		return ErrInvalidEVPNRoute{RouteType: EVPNTypeIPPrefix, Reason: "Prefix data is nil"}
	}

	prefixRoute := route.PrefixData
	key := prefixRoute.Key()

	// Remove prefix route
	m.prefixRoutes.Delete(key)

	// Notify handlers
	route.IsWithdraw = true
	for _, handler := range m.handlers {
		if err := handler(ctx, route); err != nil {
			m.logger.Error("handler error", slog.Any("error", err))
		}
	}

	return nil
}

// --- ARP Suppression ---

// LookupIPForMAC returns IP for a MAC (for ARP suppression).
func (m *EVPNManager) LookupIPForMAC(vni uint32, mac net.HardwareAddr) (netip.Addr, bool) {
	key := formatKey(vni, mac.String())
	val, ok := m.macToIP.Load(key)
	if !ok {
		return netip.Addr{}, false
	}
	return val.(netip.Addr), true
}

// LookupMACForIP returns MAC for an IP (for ARP suppression).
func (m *EVPNManager) LookupMACForIP(vni uint32, ip netip.Addr) (net.HardwareAddr, bool) {
	key := formatKey(vni, ip.String())
	val, ok := m.ipToMAC.Load(key)
	if !ok {
		return nil, false
	}
	return val.(net.HardwareAddr), true
}

// --- Helper Functions ---

// addVNIVTEP adds a VTEP to a VNI's VTEP list.
func (m *EVPNManager) addVNIVTEP(vni uint32, vtep netip.Addr) {
	val, _ := m.vniVTEPs.LoadOrStore(vni, &sync.Map{})
	vtepsMap := val.(*sync.Map)
	vtepsMap.Store(vtep, struct{}{})
}

// removeVNIVTEP removes a VTEP from a VNI's VTEP list.
func (m *EVPNManager) removeVNIVTEP(vni uint32, vtep netip.Addr) {
	val, ok := m.vniVTEPs.Load(vni)
	if !ok {
		return
	}
	vtepsMap := val.(*sync.Map)
	vtepsMap.Delete(vtep)
}

// formatKey formats a VNI and string as "VNI:str".
func formatKey(vni uint32, s string) string {
	return formatUint32(vni) + ":" + s
}

// formatKeyThree formats a VNI and two strings as "VNI:s1:s2".
func formatKeyThree(vni uint32, s1, s2 string) string {
	return formatUint32(vni) + ":" + s1 + ":" + s2
}

// formatUint32 formats a uint32 as a string without using fmt.
func formatUint32(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 10)
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(buf[i:])
}

// validateVNI validates that a VNI is within the valid range.
func validateVNI(vni uint32) error {
	if vni < MinVNI || vni > MaxVNI {
		return ErrInvalidVNI{VNI: vni, Reason: "must be between 1 and 16777215"}
	}
	return nil
}

// validateMAC validates that a MAC address is not nil and has the correct length.
func validateMAC(mac net.HardwareAddr) error {
	if mac == nil {
		return ErrInvalidMAC{MAC: nil, Reason: "MAC address is nil"}
	}
	if len(mac) != 6 {
		return ErrInvalidMAC{MAC: mac, Reason: "MAC address must be 6 bytes"}
	}
	return nil
}

// validateMACIPEntry validates a MACIPEntry.
func validateMACIPEntry(entry *MACIPEntry) error {
	if entry == nil {
		return ErrEntryNil{EntryType: "MACIPEntry"}
	}
	if err := validateVNI(entry.VNI); err != nil {
		return err
	}
	if err := validateMAC(entry.MAC); err != nil {
		return err
	}
	return nil
}
