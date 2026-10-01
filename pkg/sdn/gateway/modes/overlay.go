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

// Package modes provides SDN gateway mode handlers for different networking scenarios.
package modes

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// OpenFlow table IDs for overlay mode pipeline.
//
// Tables 20, 21, and 25 are populated only when the gateway firewall or NAT
// services are enabled (pkg/sdn/gateway/services/firewall); tables 26, 28
// and 29 only when the load balancer is
// (pkg/sdn/gateway/services/loadbalancer). Table 27 is reserved for the
// NAT64 translator hand-off (#601). The base
// pipeline installed by installOpenFlowPipeline never references them: the
// table 10 default continues straight to table 30, and the firewall service
// diverts into table 20 with a higher-priority table 10 flow it owns
// (installed on Start, removed on Stop), so the disabled-path pipeline
// stays byte-identical.
const (
	TableIngress        uint8 = 0  // Ingress classification
	TableVXLANDecap     uint8 = 10 // VXLAN decapsulation (VNI -> VLAN)
	TableAuthentication uint8 = 20 // Cert-based authentication
	TableCTGate         uint8 = 20 // Conntrack gate (firewall service; shares table 20)
	TableCTVerdict      uint8 = 21 // Conntrack verdict (firewall service)
	TableNAT            uint8 = 25 // NAT commit (NAT service)
	TableLoadBalancer   uint8 = 26 // Load balancer VIP dispatch (load-balancer service)
	TableNAT64          uint8 = 27 // NAT64 translator hand-off (nat64 service)
	TableLBHairpin      uint8 = 28 // Load balancer hairpin SNAT (load-balancer service)
	TableLBReply        uint8 = 29 // Load balancer reply reverse NAT (load-balancer service)
	TableMACLearning    uint8 = 30 // MAC learning / L2 forwarding
	TableARP            uint8 = 40 // ARP handling (suppression)
	TableL3Routing      uint8 = 50 // L3 routing (anycast gateway)
	TableEgress         uint8 = 60 // Egress (port or tunnel)
)

// MACEntrySource indicates where a MAC entry was learned from.
type MACEntrySource uint8

const (
	// MACSourceLocal indicates a locally learned MAC.
	MACSourceLocal MACEntrySource = iota
	// MACSourceRemote indicates a MAC learned via EVPN.
	MACSourceRemote
	// MACSourceStatic indicates a statically configured MAC.
	MACSourceStatic
)

// String returns a string representation of the MAC entry source.
func (s MACEntrySource) String() string {
	switch s {
	case MACSourceLocal:
		return "local"
	case MACSourceRemote:
		return "remote"
	case MACSourceStatic:
		return "static"
	default:
		return "unknown"
	}
}

// MACEntry represents a MAC address entry in the forwarding database.
type MACEntry struct {
	// MAC is the hardware address.
	MAC net.HardwareAddr

	// IP is the associated IP address (optional).
	IP netip.Addr

	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// VTEPIP is the VTEP IP where this MAC resides.
	// For local entries, this is the local VTEP IP.
	VTEPIP netip.Addr

	// OFPort is the OpenFlow port number for local entries.
	// Zero for remote entries (traffic goes through tunnel).
	OFPort int32

	// Source indicates how this entry was learned.
	Source MACEntrySource

	// Sequence is the MAC mobility sequence number.
	Sequence uint32

	// CreatedAt is when this entry was created.
	CreatedAt time.Time

	// UpdatedAt is when this entry was last updated.
	UpdatedAt time.Time

	// ExpiresAt is when this entry expires (zero means no expiration).
	ExpiresAt time.Time
}

// IsExpired returns true if the entry has expired.
func (e *MACEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// Clone creates a deep copy of the MAC entry.
func (e *MACEntry) Clone() *MACEntry {
	if e == nil {
		return nil
	}
	clone := &MACEntry{
		IP:        e.IP,
		VNI:       e.VNI,
		VTEPIP:    e.VTEPIP,
		OFPort:    e.OFPort,
		Source:    e.Source,
		Sequence:  e.Sequence,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
		ExpiresAt: e.ExpiresAt,
	}
	if e.MAC != nil {
		clone.MAC = make(net.HardwareAddr, len(e.MAC))
		copy(clone.MAC, e.MAC)
	}
	return clone
}

// ARPOperation represents an ARP operation type.
type ARPOperation uint16

const (
	// ARPRequest is an ARP request operation.
	ARPRequest ARPOperation = 1
	// ARPReply is an ARP reply operation.
	ARPReply ARPOperation = 2
)

// ARPPacket represents a parsed ARP packet.
type ARPPacket struct {
	// Operation is the ARP operation (request or reply).
	Operation ARPOperation

	// SenderMAC is the sender hardware address.
	SenderMAC net.HardwareAddr

	// SenderIP is the sender protocol address.
	SenderIP netip.Addr

	// TargetMAC is the target hardware address.
	TargetMAC net.HardwareAddr

	// TargetIP is the target protocol address.
	TargetIP netip.Addr

	// VNI is the VNI this ARP was received on.
	VNI uint32

	// InPort is the OpenFlow port the packet was received on.
	InPort int32
}

// ARPResponse represents an ARP response to send.
type ARPResponse struct {
	// ShouldRespond indicates whether we should respond locally.
	ShouldRespond bool

	// ReplyMAC is the MAC address to respond with (if ShouldRespond is true).
	ReplyMAC net.HardwareAddr

	// ShouldFlood indicates whether to flood the ARP request.
	ShouldFlood bool

	// FloodVTEPs is the list of VTEPs to flood to (for BUM traffic).
	FloodVTEPs []netip.Addr
}

// VNIMapping represents a VNI to VLAN mapping.
type VNIMapping struct {
	VNI       uint32
	VLAN      uint16
	CreatedAt time.Time
}

// OverlayModeStatus represents the current status of the overlay mode.
type OverlayModeStatus struct {
	// Running indicates whether the overlay mode is running.
	Running bool

	// LocalVTEP is the local VTEP IP address.
	LocalVTEP netip.Addr

	// VNICount is the number of configured VNIs.
	VNICount int

	// TunnelCount is the number of active VXLAN tunnels.
	TunnelCount int

	// LocalMACCount is the number of locally learned MACs.
	LocalMACCount int

	// RemoteMACCount is the number of remotely learned MACs.
	RemoteMACCount int

	// ARPSuppressionEnabled indicates whether ARP suppression is active.
	ARPSuppressionEnabled bool

	// AnycastGatewayConfigured indicates whether anycast gateway is configured.
	AnycastGatewayConfigured bool

	// StartedAt is when the overlay mode was started.
	StartedAt time.Time

	// Uptime is the duration the overlay mode has been running.
	Uptime time.Duration
}

// OverlayOVSClient defines the OVS client interface required by the overlay handler.
// This interface allows for dependency injection and testing.
type OverlayOVSClient interface {
	// AddVXLANPort creates a VXLAN port on the specified bridge.
	AddVXLANPort(ctx context.Context, bridge, port string, remoteIP string, vni uint32, dstPort uint16) error

	// DeletePort removes a port from the specified bridge.
	DeletePort(ctx context.Context, bridge, port string) error

	// GetOFPort retrieves the OpenFlow port number for an interface.
	GetOFPort(ctx context.Context, portName string) (int32, error)

	// IsConnected returns true if connected to OVSDB.
	IsConnected() bool
}

// OverlayOpenFlowClient defines the OpenFlow client interface required by the overlay handler.
type OverlayOpenFlowClient interface {
	// AddFlow adds a flow entry to the bridge.
	AddFlow(ctx context.Context, flow *openflow.FlowMod) error

	// SendFlowMods adds a batch of flow entries in a single OpenFlow
	// transaction (all flow mods followed by one barrier).
	SendFlowMods(ctx context.Context, flows []*openflow.FlowMod) error

	// DeleteFlow deletes flows matching the criteria.
	DeleteFlow(ctx context.Context, flow *openflow.FlowMod) error

	// IsConnected returns whether the client is connected.
	IsConnected() bool
}

// OverlayModeConfig holds configuration for the overlay mode handler.
type OverlayModeConfig struct {
	// VTEPConfig is the VTEP configuration.
	VTEPConfig *vxlan.VTEPConfig

	// EVPNConfig is the EVPN manager configuration.
	EVPNConfig *bgp.EVPNManagerConfig

	// ARPSuppression enables ARP suppression.
	ARPSuppression bool

	// AnycastGatewayIP is the distributed anycast gateway IP.
	AnycastGatewayIP netip.Addr

	// AnycastGatewayMAC is the distributed anycast gateway MAC.
	// This MAC is shared across all nodes for seamless L3 routing.
	AnycastGatewayMAC net.HardwareAddr

	// BridgeName is the OVS bridge name.
	BridgeName string

	// MACEntryTimeout is the timeout for learned MAC entries.
	// Zero means no timeout.
	MACEntryTimeout time.Duration

	// Logger for logging operations.
	Logger *slog.Logger
}

// Validate validates the overlay mode configuration.
func (c *OverlayModeConfig) Validate() error {
	if c.VTEPConfig == nil {
		return ErrVTEPConfigNil
	}
	if err := c.VTEPConfig.Validate(); err != nil {
		return err
	}
	if c.BridgeName == "" {
		return ErrBridgeNameEmpty
	}
	if c.Logger == nil {
		return ErrLoggerNil
	}
	// EVPNConfig is optional - can run without BGP/EVPN
	// AnycastGatewayIP and AnycastGatewayMAC are optional
	return nil
}

// replicationList wraps a slice of VTEP addresses for use in sync.Map.
// Using a pointer to a struct allows CompareAndSwap to work correctly
// since pointers are comparable while slices are not.
type replicationList struct {
	vteps []netip.Addr
}

// OverlayModeHandler handles VXLAN overlay networking for east-west VM/container traffic.
type OverlayModeHandler struct {
	config      *OverlayModeConfig
	vtepManager *vxlan.VTEPManager
	evpnManager *bgp.EVPNManager
	ovsClient   OverlayOVSClient
	ofClient    OverlayOpenFlowClient
	logger      *slog.Logger

	// VNI to VLAN mappings
	vniMappings sync.Map // map[uint32]*VNIMapping

	// Local MAC table (key: "VNI:MAC")
	localMACs sync.Map // map[string]*MACEntry

	// Remote MAC table (key: "VNI:MAC")
	remoteMACs sync.Map // map[string]*MACEntry

	// ARP suppression table (key: "VNI:IP" -> MAC)
	arpTable sync.Map // map[string]net.HardwareAddr

	// Replication list per VNI (key: VNI -> *replicationList)
	replicationLists sync.Map // map[uint32]*replicationList

	// Running state
	running atomic.Bool

	// Start time
	startedAt time.Time

	// Shutdown coordination
	done chan struct{}
	wg   sync.WaitGroup
}

// NewOverlayModeHandler creates a new overlay mode handler.
func NewOverlayModeHandler(
	config *OverlayModeConfig,
	ovsClient OverlayOVSClient,
	ofClient OverlayOpenFlowClient,
) (*OverlayModeHandler, error) {
	if config == nil {
		return nil, ErrConfigNil
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if ovsClient == nil {
		return nil, ErrOVSClientNil
	}
	if ofClient == nil {
		return nil, ErrOpenFlowClientNil
	}

	handler := &OverlayModeHandler{
		config:    config,
		ovsClient: ovsClient,
		ofClient:  ofClient,
		logger:    config.Logger,
		done:      make(chan struct{}),
	}

	// Create VTEP manager using the OVS client interface
	vtepManager, err := vxlan.NewVTEPManager(
		*config.VTEPConfig,
		ovsClient,
		config.BridgeName,
		config.Logger,
	)
	if err != nil {
		return nil, &ErrOverlayInitFailed{Component: "VTEPManager", Cause: err}
	}
	handler.vtepManager = vtepManager

	// Create EVPN manager if configured
	if config.EVPNConfig != nil {
		evpnManager, err := bgp.NewEVPNManager(config.EVPNConfig)
		if err != nil {
			return nil, &ErrOverlayInitFailed{Component: "EVPNManager", Cause: err}
		}
		handler.evpnManager = evpnManager
	}

	return handler, nil
}

// Start starts the overlay mode handler.
func (h *OverlayModeHandler) Start(ctx context.Context) error {
	if h.running.Swap(true) {
		return ErrAlreadyRunning
	}

	h.startedAt = time.Now()
	h.done = make(chan struct{})

	// Start VTEP manager
	if err := h.vtepManager.Start(ctx); err != nil {
		h.running.Store(false)
		return &ErrOverlayStartFailed{Component: "VTEPManager", Cause: err}
	}

	// Start EVPN manager if configured
	if h.evpnManager != nil {
		if err := h.evpnManager.Start(ctx); err != nil {
			h.vtepManager.Stop()
			h.running.Store(false)
			return &ErrOverlayStartFailed{Component: "EVPNManager", Cause: err}
		}

		// Register EVPN route handler
		h.evpnManager.RegisterHandler(h.handleEVPNRoute)
	}

	// Install base OpenFlow pipeline
	if err := h.installOpenFlowPipeline(ctx); err != nil {
		h.stopComponents(ctx)
		h.running.Store(false)
		return &ErrOverlayStartFailed{Component: "OpenFlow", Cause: err}
	}

	h.logger.Info("overlay mode started",
		slog.String("local_vtep", h.config.VTEPConfig.LocalIP.String()),
		slog.Bool("arp_suppression", h.config.ARPSuppression),
		slog.Bool("anycast_gateway", h.config.AnycastGatewayIP.IsValid()),
	)

	return nil
}

// Stop stops the overlay mode handler.
func (h *OverlayModeHandler) Stop(ctx context.Context) error {
	if !h.running.Swap(false) {
		return nil
	}

	// Signal shutdown
	close(h.done)

	// Wait for goroutines
	h.wg.Wait()

	// Stop components
	h.stopComponents(ctx)

	h.logger.Info("overlay mode stopped")
	return nil
}

// stopComponents stops all sub-components.
func (h *OverlayModeHandler) stopComponents(ctx context.Context) {
	if h.evpnManager != nil {
		if err := h.evpnManager.Stop(ctx); err != nil {
			h.logger.Error("failed to stop EVPN manager", slog.Any("error", err))
		}
	}

	if err := h.vtepManager.Stop(); err != nil {
		h.logger.Error("failed to stop VTEP manager", slog.Any("error", err))
	}
}

// AddVNI adds a VNI to the overlay.
func (h *OverlayModeHandler) AddVNI(ctx context.Context, vni uint32, vlan uint16) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if err := validateVNI(vni); err != nil {
		return err
	}
	if vlan > 4094 {
		return ErrVLANOutOfRange
	}

	// Check if VNI already exists
	if _, exists := h.vniMappings.Load(vni); exists {
		return ErrVNIAlreadyExists
	}

	mapping := &VNIMapping{
		VNI:       vni,
		VLAN:      vlan,
		CreatedAt: time.Now(),
	}
	h.vniMappings.Store(vni, mapping)

	// Install VNI-specific flows
	if err := h.installVNIFlows(ctx, vni, vlan); err != nil {
		h.vniMappings.Delete(vni)
		return &ErrVNIOperationFailed{VNI: vni, Operation: "add", Cause: err}
	}

	// Advertise IMET for this VNI (Type-3) if EVPN is configured
	if h.evpnManager != nil {
		if err := h.evpnManager.AdvertiseIMET(ctx, vni, h.config.VTEPConfig.LocalIP); err != nil {
			h.logger.Warn("failed to advertise IMET",
				slog.Uint64("vni", uint64(vni)),
				slog.Any("error", err),
			)
		}
	}

	h.logger.Info("VNI added",
		slog.Uint64("vni", uint64(vni)),
		slog.Int("vlan", int(vlan)),
	)

	return nil
}

// RemoveVNI removes a VNI from the overlay.
func (h *OverlayModeHandler) RemoveVNI(ctx context.Context, vni uint32) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	val, exists := h.vniMappings.Load(vni)
	if !exists {
		return ErrVNINotFound
	}
	mapping := val.(*VNIMapping)

	// Withdraw IMET if EVPN is configured
	if h.evpnManager != nil {
		if err := h.evpnManager.WithdrawIMET(ctx, vni); err != nil {
			h.logger.Warn("failed to withdraw IMET",
				slog.Uint64("vni", uint64(vni)),
				slog.Any("error", err),
			)
		}
	}

	// Remove VNI-specific flows
	if err := h.removeVNIFlows(ctx, vni, mapping.VLAN); err != nil {
		return &ErrVNIOperationFailed{VNI: vni, Operation: "remove", Cause: err}
	}

	// Clean up MAC entries for this VNI
	h.cleanupVNIMACs(vni)

	// Remove replication list
	h.replicationLists.Delete(vni)

	h.vniMappings.Delete(vni)

	h.logger.Info("VNI removed", slog.Uint64("vni", uint64(vni)))

	return nil
}

// LearnMAC learns a MAC address from local or remote sources.
func (h *OverlayModeHandler) LearnMAC(
	ctx context.Context,
	mac net.HardwareAddr,
	ip netip.Addr,
	vni uint32,
	vtepIP netip.Addr,
) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if err := validateMAC(mac); err != nil {
		return err
	}
	if err := validateVNI(vni); err != nil {
		return err
	}

	key := formatMACKey(vni, mac)
	now := time.Now()

	isLocal := vtepIP == h.config.VTEPConfig.LocalIP || !vtepIP.IsValid()

	entry := &MACEntry{
		MAC:       mac,
		IP:        ip,
		VNI:       vni,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if isLocal {
		entry.Source = MACSourceLocal
		entry.VTEPIP = h.config.VTEPConfig.LocalIP

		// Set expiration if configured
		if h.config.MACEntryTimeout > 0 {
			entry.ExpiresAt = now.Add(h.config.MACEntryTimeout)
		}

		h.localMACs.Store(key, entry)

		// Install local forwarding flow
		if err := h.installLocalMACFlow(ctx, entry); err != nil {
			return &ErrMACOperationFailed{MAC: mac, Operation: "learn-local", Cause: err}
		}

		// Advertise via EVPN Type-2 if configured
		if h.evpnManager != nil {
			evpnEntry := &bgp.MACIPEntry{
				MAC:    mac,
				IP:     ip,
				VNI:    vni,
				VTEPIP: h.config.VTEPConfig.LocalIP,
			}
			if ip.IsValid() {
				if err := h.evpnManager.AdvertiseMACIP(ctx, evpnEntry); err != nil {
					h.logger.Warn("failed to advertise MAC/IP",
						slog.String("mac", mac.String()),
						slog.Any("error", err),
					)
				}
			} else {
				if err := h.evpnManager.AdvertiseMAC(ctx, evpnEntry); err != nil {
					h.logger.Warn("failed to advertise MAC",
						slog.String("mac", mac.String()),
						slog.Any("error", err),
					)
				}
			}
		}
	} else {
		entry.Source = MACSourceRemote
		entry.VTEPIP = vtepIP

		h.remoteMACs.Store(key, entry)

		// Install remote forwarding flow (tunnel to VTEP)
		if err := h.installRemoteMACFlow(ctx, entry); err != nil {
			return &ErrMACOperationFailed{MAC: mac, Operation: "learn-remote", Cause: err}
		}
	}

	// Update ARP table if IP is provided
	if ip.IsValid() && h.config.ARPSuppression {
		arpKey := formatARPKey(vni, ip)
		h.arpTable.Store(arpKey, mac)
	}

	h.logger.Debug("MAC learned",
		slog.String("mac", mac.String()),
		slog.String("ip", ip.String()),
		slog.Uint64("vni", uint64(vni)),
		slog.String("source", entry.Source.String()),
	)

	return nil
}

// LookupMAC looks up a MAC address in the forwarding database.
func (h *OverlayModeHandler) LookupMAC(
	ctx context.Context,
	mac net.HardwareAddr,
	vni uint32,
) (*MACEntry, error) {
	if !h.running.Load() {
		return nil, ErrNotRunning
	}

	if err := validateMAC(mac); err != nil {
		return nil, err
	}

	key := formatMACKey(vni, mac)

	// Check local MACs first
	if val, ok := h.localMACs.Load(key); ok {
		entry := val.(*MACEntry)
		if !entry.IsExpired() {
			return entry.Clone(), nil
		}
		// Entry expired, remove it
		h.localMACs.Delete(key)
	}

	// Check remote MACs
	if val, ok := h.remoteMACs.Load(key); ok {
		entry := val.(*MACEntry)
		return entry.Clone(), nil
	}

	return nil, ErrMACNotFound
}

// HandleARP handles an ARP request for ARP suppression.
func (h *OverlayModeHandler) HandleARP(ctx context.Context, arp *ARPPacket) (*ARPResponse, error) {
	if !h.running.Load() {
		return nil, ErrNotRunning
	}

	if arp == nil {
		return nil, ErrARPPacketNil
	}

	response := &ARPResponse{
		ShouldRespond: false,
		ShouldFlood:   false,
	}

	// Only handle ARP requests
	if arp.Operation != ARPRequest {
		return response, nil
	}

	// If ARP suppression is disabled, flood
	if !h.config.ARPSuppression {
		response.ShouldFlood = true
		response.FloodVTEPs = h.getReplicationList(arp.VNI)
		return response, nil
	}

	// Check if target IP is the anycast gateway
	if h.config.AnycastGatewayIP.IsValid() && arp.TargetIP == h.config.AnycastGatewayIP {
		response.ShouldRespond = true
		response.ReplyMAC = h.config.AnycastGatewayMAC
		h.logger.Debug("ARP response for anycast gateway",
			slog.String("target_ip", arp.TargetIP.String()),
		)
		return response, nil
	}

	// Look up target IP in ARP table
	arpKey := formatARPKey(arp.VNI, arp.TargetIP)
	if val, ok := h.arpTable.Load(arpKey); ok {
		mac := val.(net.HardwareAddr)
		response.ShouldRespond = true
		response.ReplyMAC = mac
		h.logger.Debug("ARP suppressed",
			slog.String("target_ip", arp.TargetIP.String()),
			slog.String("reply_mac", mac.String()),
		)
		return response, nil
	}

	// Try EVPN manager lookup
	if h.evpnManager != nil {
		if mac, ok := h.evpnManager.LookupMACForIP(arp.VNI, arp.TargetIP); ok {
			response.ShouldRespond = true
			response.ReplyMAC = mac
			// Cache in local ARP table
			h.arpTable.Store(arpKey, mac)
			h.logger.Debug("ARP suppressed via EVPN",
				slog.String("target_ip", arp.TargetIP.String()),
				slog.String("reply_mac", mac.String()),
			)
			return response, nil
		}
	}

	// Not found, flood to all VTEPs in the VNI
	response.ShouldFlood = true
	response.FloodVTEPs = h.getReplicationList(arp.VNI)

	h.logger.Debug("ARP flood",
		slog.String("target_ip", arp.TargetIP.String()),
		slog.Int("vtep_count", len(response.FloodVTEPs)),
	)

	return response, nil
}

// GetStatus returns the current overlay mode status.
func (h *OverlayModeHandler) GetStatus() *OverlayModeStatus {
	status := &OverlayModeStatus{
		Running:                  h.running.Load(),
		ARPSuppressionEnabled:    h.config.ARPSuppression,
		AnycastGatewayConfigured: h.config.AnycastGatewayIP.IsValid(),
	}

	if status.Running {
		status.LocalVTEP = h.config.VTEPConfig.LocalIP
		status.StartedAt = h.startedAt
		status.Uptime = time.Since(h.startedAt)
		status.TunnelCount = h.vtepManager.TunnelCount()

		// Count VNIs
		h.vniMappings.Range(func(_, _ any) bool {
			status.VNICount++
			return true
		})

		// Count local MACs
		h.localMACs.Range(func(_, _ any) bool {
			status.LocalMACCount++
			return true
		})

		// Count remote MACs
		h.remoteMACs.Range(func(_, _ any) bool {
			status.RemoteMACCount++
			return true
		})
	}

	return status
}

// AddRemoteVTEP adds a remote VTEP to the replication list for a VNI.
func (h *OverlayModeHandler) AddRemoteVTEP(ctx context.Context, vni uint32, vtepIP netip.Addr) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if !vtepIP.IsValid() || vtepIP.IsUnspecified() {
		return ErrInvalidVTEPIP
	}

	// Create tunnel to remote VTEP
	_, err := h.vtepManager.AddTunnel(ctx, vtepIP, vxlan.VNI(vni))
	if err != nil && err != vxlan.ErrTunnelExists {
		return &ErrVTEPOperationFailed{VTEPIP: vtepIP, Operation: "add-tunnel", Cause: err}
	}

	// Add to replication list
	h.addToReplicationList(vni, vtepIP)

	h.logger.Debug("remote VTEP added",
		slog.Uint64("vni", uint64(vni)),
		slog.String("vtep", vtepIP.String()),
	)

	return nil
}

// RemoveRemoteVTEP removes a remote VTEP from the replication list.
func (h *OverlayModeHandler) RemoveRemoteVTEP(ctx context.Context, vni uint32, vtepIP netip.Addr) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	// Remove from replication list
	h.removeFromReplicationList(vni, vtepIP)

	// Remove tunnel (if no other VNIs use it)
	if !h.vtepInUse(vtepIP) {
		if err := h.vtepManager.RemoveTunnel(ctx, vtepIP, vxlan.VNI(vni)); err != nil {
			h.logger.Warn("failed to remove tunnel",
				slog.String("vtep", vtepIP.String()),
				slog.Any("error", err),
			)
		}
	}

	h.logger.Debug("remote VTEP removed",
		slog.Uint64("vni", uint64(vni)),
		slog.String("vtep", vtepIP.String()),
	)

	return nil
}

// handleEVPNRoute handles incoming EVPN routes.
func (h *OverlayModeHandler) handleEVPNRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	if route == nil {
		return nil
	}

	switch route.Type {
	case bgp.EVPNTypeMACIPAdvertisement:
		return h.handleType2Route(ctx, route)
	case bgp.EVPNTypeInclusiveMulticast:
		return h.handleType3Route(ctx, route)
	case bgp.EVPNTypeIPPrefix:
		return h.handleType5Route(ctx, route)
	}

	return nil
}

// handleType2Route handles EVPN Type-2 MAC/IP advertisement routes.
func (h *OverlayModeHandler) handleType2Route(ctx context.Context, route *bgp.EVPNRouteData) error {
	if route.MACIP == nil {
		return nil
	}

	entry := route.MACIP

	if route.IsWithdraw {
		// Remove MAC entry
		key := formatMACKey(entry.VNI, entry.MAC)
		h.remoteMACs.Delete(key)

		// Remove from ARP table
		if entry.IP.IsValid() {
			arpKey := formatARPKey(entry.VNI, entry.IP)
			h.arpTable.Delete(arpKey)
		}

		// Remove flow
		if err := h.removeRemoteMACFlow(ctx, entry.VNI, entry.MAC); err != nil {
			h.logger.Warn("failed to remove remote MAC flow",
				slog.String("mac", entry.MAC.String()),
				slog.Any("error", err),
			)
		}

		h.logger.Debug("remote MAC withdrawn",
			slog.String("mac", entry.MAC.String()),
			slog.String("vtep", entry.VTEPIP.String()),
		)
	} else {
		// Learn remote MAC
		if err := h.LearnMAC(ctx, entry.MAC, entry.IP, entry.VNI, entry.VTEPIP); err != nil {
			return err
		}
	}

	return nil
}

// handleType3Route handles EVPN Type-3 inclusive multicast routes.
func (h *OverlayModeHandler) handleType3Route(ctx context.Context, route *bgp.EVPNRouteData) error {
	if route.IMET == nil {
		return nil
	}

	entry := route.IMET

	if route.IsWithdraw {
		// Remove VTEP from replication list
		if err := h.RemoveRemoteVTEP(ctx, entry.VNI, entry.VTEPIP); err != nil {
			h.logger.Warn("failed to remove remote VTEP",
				slog.String("vtep", entry.VTEPIP.String()),
				slog.Any("error", err),
			)
		}
	} else {
		// Add VTEP to replication list
		if err := h.AddRemoteVTEP(ctx, entry.VNI, entry.VTEPIP); err != nil {
			return err
		}
	}

	return nil
}

// handleType5Route handles EVPN Type-5 IP prefix routes.
func (h *OverlayModeHandler) handleType5Route(ctx context.Context, route *bgp.EVPNRouteData) error {
	if route.PrefixData == nil {
		return nil
	}

	// Type-5 routes are handled at the L3 routing layer
	// Install/remove routes in the routing table
	if route.IsWithdraw {
		h.logger.Debug("Type-5 route withdrawn",
			slog.String("prefix", route.PrefixData.Prefix.String()),
		)
	} else {
		h.logger.Debug("Type-5 route received",
			slog.String("prefix", route.PrefixData.Prefix.String()),
			slog.String("next_hop", route.NextHop.String()),
		)
	}

	return nil
}

// installOpenFlowPipeline installs the base OpenFlow pipeline as a single
// batched OpenFlow transaction.
func (h *OverlayModeHandler) installOpenFlowPipeline(ctx context.Context) error {
	flows := []*openflow.FlowMod{
		// Table 0: Ingress - classify packets, goto VXLANDecap
		buildGotoTableFlow(TableIngress, 0, TableVXLANDecap),
		// Table 10: VXLAN Decap - default to MAC learning
		buildGotoTableFlow(TableVXLANDecap, 0, TableMACLearning),
		// Table 30: MAC Learning - default to ARP table
		buildGotoTableFlow(TableMACLearning, 0, TableARP),
		// Table 40: ARP - default to L3 routing
		buildGotoTableFlow(TableARP, 0, TableL3Routing),
		// Table 50: L3 Routing - default to egress
		buildGotoTableFlow(TableL3Routing, 0, TableEgress),
		// Table 60: Egress - default drop (no output action)
		buildDropFlow(TableEgress, 0),
	}

	for _, flow := range flows {
		h.logger.Debug("installing pipeline flow",
			slog.Int("table", int(flow.TableID)),
			slog.Int("priority", int(flow.Priority)),
		)
	}

	if err := h.ofClient.SendFlowMods(ctx, flows); err != nil {
		return &ErrOverlayInitFailed{Component: "openflow pipeline batch", Cause: err}
	}

	// Install anycast gateway flows if configured
	if h.config.AnycastGatewayIP.IsValid() && h.config.AnycastGatewayMAC != nil {
		if err := h.installAnycastGatewayFlows(ctx); err != nil {
			return err
		}
	}

	return nil
}

// buildGotoTableFlow builds a flow that jumps to another table.
func buildGotoTableFlow(tableID uint8, priority uint16, gotoTable uint8) *openflow.FlowMod {
	flow := openflow.NewFlowMod(0)
	flow.TableID = tableID
	flow.Priority = priority
	flow.Instructions = append(flow.Instructions, openflow.NewInstructionGotoTable(gotoTable))
	return flow
}

// buildDropFlow builds a flow that drops packets (no actions).
func buildDropFlow(tableID uint8, priority uint16) *openflow.FlowMod {
	flow := openflow.NewFlowMod(0)
	flow.TableID = tableID
	flow.Priority = priority
	// No actions = drop
	return flow
}

// installVNIFlows installs flows for a specific VNI as a single batched
// OpenFlow transaction.
func (h *OverlayModeHandler) installVNIFlows(ctx context.Context, vni uint32, vlan uint16) error {
	// Table 10: VNI -> VLAN mapping for VXLAN decap
	// Match on tunnel ID (VNI), push VLAN, goto MAC learning
	decapFlow := openflow.NewFlowMod(0)
	decapFlow.TableID = TableVXLANDecap
	decapFlow.Priority = 100
	decapFlow.Match = openflow.NewMatch()
	// Add tunnel ID match using OXM field
	tunnelIDBytes := make([]byte, 8)
	openflow.ByteOrder.PutUint64(tunnelIDBytes, uint64(vni))
	decapFlow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, tunnelIDBytes, nil)

	// Push VLAN and goto MAC learning
	pushVLAN := openflow.NewActionPushVLAN(0x8100)
	setVLAN := openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, encodeVLAN(vlan))
	applyActions := openflow.NewInstructionApplyActions(pushVLAN, setVLAN)
	gotoMACLearning := openflow.NewInstructionGotoTable(TableMACLearning)
	decapFlow.Instructions = append(decapFlow.Instructions, applyActions, gotoMACLearning)

	// Table 60: VLAN -> VNI mapping for VXLAN encap
	encapFlow := openflow.NewFlowMod(0)
	encapFlow.TableID = TableEgress
	encapFlow.Priority = 100
	encapFlow.Match = openflow.NewMatch()
	encapFlow.Match.AddVLANVid(vlan)

	// Pop VLAN and set tunnel ID
	popVLAN := openflow.NewActionPopVLAN()
	setTunnelID := openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, tunnelIDBytes)
	applyActionsEncap := openflow.NewInstructionApplyActions(popVLAN, setTunnelID)
	encapFlow.Instructions = append(encapFlow.Instructions, applyActionsEncap)

	h.logger.Debug("installing VNI flow batch",
		slog.Uint64("vni", uint64(vni)),
		slog.Uint64("vlan", uint64(vlan)),
	)

	if err := h.ofClient.SendFlowMods(ctx, []*openflow.FlowMod{decapFlow, encapFlow}); err != nil {
		return &ErrFlowOperationFailed{Table: TableVXLANDecap, Operation: "install VNI flow batch", Cause: err}
	}

	return nil
}

// removeVNIFlows removes flows for a specific VNI.
func (h *OverlayModeHandler) removeVNIFlows(ctx context.Context, vni uint32, vlan uint16) error {
	// Remove decap flow
	decapFlow := openflow.NewFlowMod(0)
	decapFlow.TableID = TableVXLANDecap
	decapFlow.Match = openflow.NewMatch()
	tunnelIDBytes := make([]byte, 8)
	openflow.ByteOrder.PutUint64(tunnelIDBytes, uint64(vni))
	decapFlow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, tunnelIDBytes, nil)
	if err := h.ofClient.DeleteFlow(ctx, decapFlow); err != nil {
		h.logger.Warn("failed to delete VNI decap flow", slog.Any("error", err))
	}

	// Remove encap flow
	encapFlow := openflow.NewFlowMod(0)
	encapFlow.TableID = TableEgress
	encapFlow.Match = openflow.NewMatch()
	encapFlow.Match.AddVLANVid(vlan)
	if err := h.ofClient.DeleteFlow(ctx, encapFlow); err != nil {
		h.logger.Warn("failed to delete VNI encap flow", slog.Any("error", err))
	}

	return nil
}

// installLocalMACFlow installs a flow for a locally learned MAC.
func (h *OverlayModeHandler) installLocalMACFlow(ctx context.Context, entry *MACEntry) error {
	flow := openflow.NewFlowMod(0)
	flow.TableID = TableMACLearning
	flow.Priority = 200
	flow.Match = openflow.NewMatch()
	flow.Match.AddEthDst(entry.MAC)

	// Add tunnel ID match
	tunnelIDBytes := make([]byte, 8)
	openflow.ByteOrder.PutUint64(tunnelIDBytes, uint64(entry.VNI))
	flow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, tunnelIDBytes, nil)

	// Output to local port
	output := openflow.NewActionOutput(uint32(entry.OFPort), 0)
	applyActions := openflow.NewInstructionApplyActions(output)
	flow.Instructions = append(flow.Instructions, applyActions)

	return h.ofClient.AddFlow(ctx, flow)
}

// installRemoteMACFlow installs a flow for a remotely learned MAC.
func (h *OverlayModeHandler) installRemoteMACFlow(ctx context.Context, entry *MACEntry) error {
	// Get tunnel port for remote VTEP
	tunnel, err := h.vtepManager.GetTunnel(entry.VTEPIP, vxlan.VNI(entry.VNI))
	if err != nil {
		// Create tunnel if it doesn't exist
		tunnel, err = h.vtepManager.AddTunnel(ctx, entry.VTEPIP, vxlan.VNI(entry.VNI))
		if err != nil {
			return err
		}
	}

	flow := openflow.NewFlowMod(0)
	flow.TableID = TableMACLearning
	flow.Priority = 200
	flow.Match = openflow.NewMatch()
	flow.Match.AddEthDst(entry.MAC)

	// Add tunnel ID match
	tunnelIDBytes := make([]byte, 8)
	openflow.ByteOrder.PutUint64(tunnelIDBytes, uint64(entry.VNI))
	flow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, tunnelIDBytes, nil)

	// Output to tunnel port
	output := openflow.NewActionOutput(uint32(tunnel.OFPort), 0)
	applyActions := openflow.NewInstructionApplyActions(output)
	flow.Instructions = append(flow.Instructions, applyActions)

	return h.ofClient.AddFlow(ctx, flow)
}

// removeRemoteMACFlow removes a flow for a remote MAC.
func (h *OverlayModeHandler) removeRemoteMACFlow(ctx context.Context, vni uint32, mac net.HardwareAddr) error {
	flow := openflow.NewFlowMod(0)
	flow.TableID = TableMACLearning
	flow.Match = openflow.NewMatch()
	flow.Match.AddEthDst(mac)

	// Add tunnel ID match
	tunnelIDBytes := make([]byte, 8)
	openflow.ByteOrder.PutUint64(tunnelIDBytes, uint64(vni))
	flow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, tunnelIDBytes, nil)

	return h.ofClient.DeleteFlow(ctx, flow)
}

// installAnycastGatewayFlows installs flows for the distributed anycast
// gateway as a single batched OpenFlow transaction.
func (h *OverlayModeHandler) installAnycastGatewayFlows(ctx context.Context) error {
	// ARP responder for anycast gateway IP
	// Match ARP requests for the anycast gateway IP
	arpFlow := openflow.NewFlowMod(0)
	arpFlow.TableID = TableARP
	arpFlow.Priority = 200
	arpFlow.Match = openflow.NewMatch()
	arpFlow.Match.AddEthType(0x0806) // ARP

	// Match ARP operation (request = 1)
	arpOpBytes := make([]byte, 2)
	openflow.ByteOrder.PutUint16(arpOpBytes, 1)
	arpFlow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpOp, arpOpBytes, nil)

	// Match target IP = anycast gateway IP
	ipBytes := h.config.AnycastGatewayIP.As4()
	arpFlow.Match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTpa, ipBytes[:], nil)

	// Note: Full ARP responder would require NX extensions for move/load actions
	// For now, we send to controller for handling or use a simplified approach
	// This is a placeholder - production would use Nicira extensions
	controller := openflow.NewActionOutput(openflow.OFPPController, 128)
	applyActions := openflow.NewInstructionApplyActions(controller)
	arpFlow.Instructions = append(arpFlow.Instructions, applyActions)

	// L3 routing: packets to anycast gateway MAC go to routing table
	l3Flow := openflow.NewFlowMod(0)
	l3Flow.TableID = TableMACLearning
	l3Flow.Priority = 300
	l3Flow.Match = openflow.NewMatch()
	l3Flow.Match.AddEthDst(h.config.AnycastGatewayMAC)

	gotoL3 := openflow.NewInstructionGotoTable(TableL3Routing)
	l3Flow.Instructions = append(l3Flow.Instructions, gotoL3)

	h.logger.Debug("installing anycast gateway flow batch",
		slog.String("gateway_ip", h.config.AnycastGatewayIP.String()),
		slog.String("gateway_mac", h.config.AnycastGatewayMAC.String()),
	)

	if err := h.ofClient.SendFlowMods(ctx, []*openflow.FlowMod{arpFlow, l3Flow}); err != nil {
		return &ErrFlowOperationFailed{Table: TableARP, Operation: "install anycast gateway flow batch", Cause: err}
	}

	return nil
}

// cleanupVNIMACs removes all MAC entries for a VNI.
func (h *OverlayModeHandler) cleanupVNIMACs(vni uint32) {
	prefix := formatVNIPrefix(vni)

	h.localMACs.Range(func(key, _ any) bool {
		k := key.(string)
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			h.localMACs.Delete(key)
		}
		return true
	})

	h.remoteMACs.Range(func(key, _ any) bool {
		k := key.(string)
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			h.remoteMACs.Delete(key)
		}
		return true
	})
}

// getReplicationList returns the list of VTEPs for BUM traffic replication.
func (h *OverlayModeHandler) getReplicationList(vni uint32) []netip.Addr {
	val, ok := h.replicationLists.Load(vni)
	if !ok {
		return nil
	}
	list := val.(*replicationList)
	result := make([]netip.Addr, len(list.vteps))
	copy(result, list.vteps)
	return result
}

// addToReplicationList adds a VTEP to the replication list for a VNI.
func (h *OverlayModeHandler) addToReplicationList(vni uint32, vtepIP netip.Addr) {
	for {
		newList := &replicationList{vteps: []netip.Addr{vtepIP}}
		val, loaded := h.replicationLists.LoadOrStore(vni, newList)
		if !loaded {
			return
		}

		oldList := val.(*replicationList)
		// Check if already exists
		for _, v := range oldList.vteps {
			if v == vtepIP {
				return
			}
		}

		// Add to list - create new slice to avoid modifying original
		updatedVteps := make([]netip.Addr, len(oldList.vteps)+1)
		copy(updatedVteps, oldList.vteps)
		updatedVteps[len(oldList.vteps)] = vtepIP
		updatedList := &replicationList{vteps: updatedVteps}

		if h.replicationLists.CompareAndSwap(vni, val, updatedList) {
			return
		}
		// CAS failed, retry
	}
}

// removeFromReplicationList removes a VTEP from the replication list.
func (h *OverlayModeHandler) removeFromReplicationList(vni uint32, vtepIP netip.Addr) {
	for {
		val, ok := h.replicationLists.Load(vni)
		if !ok {
			return
		}

		oldList := val.(*replicationList)
		updatedVteps := make([]netip.Addr, 0, len(oldList.vteps))
		found := false
		for _, v := range oldList.vteps {
			if v == vtepIP {
				found = true
				continue
			}
			updatedVteps = append(updatedVteps, v)
		}

		if !found {
			return
		}

		if len(updatedVteps) == 0 {
			// Try to delete - use CompareAndDelete if available, otherwise just delete
			h.replicationLists.CompareAndDelete(vni, val)
			return
		}

		updatedList := &replicationList{vteps: updatedVteps}
		if h.replicationLists.CompareAndSwap(vni, val, updatedList) {
			return
		}
		// CAS failed, retry
	}
}

// vtepInUse checks if a VTEP is in use by any VNI.
func (h *OverlayModeHandler) vtepInUse(vtepIP netip.Addr) bool {
	inUse := false
	h.replicationLists.Range(func(_, value any) bool {
		list := value.(*replicationList)
		for _, v := range list.vteps {
			if v == vtepIP {
				inUse = true
				return false
			}
		}
		return true
	})
	return inUse
}

// Helper functions

func formatMACKey(vni uint32, mac net.HardwareAddr) string {
	return formatUint32(vni) + ":" + mac.String()
}

func formatARPKey(vni uint32, ip netip.Addr) string {
	return formatUint32(vni) + ":" + ip.String()
}

func formatVNIPrefix(vni uint32) string {
	return formatUint32(vni) + ":"
}

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

func validateVNI(vni uint32) error {
	if vni < 1 || vni > 16777215 {
		return ErrVNIOutOfRange
	}
	return nil
}

func validateMAC(mac net.HardwareAddr) error {
	if mac == nil {
		return ErrMACNil
	}
	if len(mac) != 6 {
		return ErrMACInvalid
	}
	return nil
}

// encodeVLAN encodes a VLAN ID with the OFPVID_PRESENT bit.
func encodeVLAN(vlan uint16) []byte {
	value := make([]byte, 2)
	// VLAN VID uses 13 bits, bit 12 is OFPVID_PRESENT (0x1000)
	openflow.ByteOrder.PutUint16(value, vlan|0x1000)
	return value
}
