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

package ipxe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// PXE vendor classes
	vendorClassPXEClient = "PXEClient"
	vendorClassIPXE      = "iPXE"

	// PXE option 43 (vendor-specific information) sub-options used to make
	// UEFI PXE firmware boot the bootfile we offer instead of doing Boot
	// Server discovery (which this simple DHCP+TFTP server doesn't answer).
	pxeDiscoveryControlSubOption = byte(0x06) // PXE_DISCOVERY_CONTROL
	pxeDiscoveryUseBootfile      = byte(0x08) // bit 3: download bootfile, skip discovery
	pxeVendorOptionEnd           = byte(0xff) // PXE option END marker

	// Client architectures
	archBIOSx86 = uint16(0x0000)
	archEFIx64  = uint16(0x0007)
	archEFIx86  = uint16(0x0006)
	archEFIBC   = uint16(0x0009)
)

// DHCPConfig holds the internal DHCP server configuration.
type DHCPConfig struct {
	Interface      string
	ServerIP       net.IP
	BroadcastIP    net.IP
	SubnetMask     net.IP
	RangeStart     net.IP
	RangeEnd       net.IP
	LeaseTime      time.Duration
	Router         net.IP
	DNSServers     []net.IP
	TFTPServerName string
	TFTPServerIP   net.IP
	// BootFilename is the legacy single-arch default. When
	// BootFilenameByArch is set, that map wins for any matching
	// arch; BootFilename is used only as a fallback for
	// architectures not present in the map.
	BootFilename string
	// BootFilenameByArch maps DHCP option-93 client architecture
	// values to TFTP boot filenames. The DHCP server consults this
	// map when responding to non-iPXE PXE clients so that legacy
	// BIOS, UEFI x64, and UEFI IA32 clients each receive a
	// firmware-appropriate image. Empty map -> use BootFilename
	// uniformly.
	BootFilenameByArch map[uint16]string
	IPXEScript         string
	UseRawSocket       bool
	RespondToAll       bool // When true, respond to all DHCP clients, not just PXE-tagged ones. Use in bootstrap mode when this is the only DHCP server.
}

// lease represents a DHCP IP lease.
type lease struct {
	IP        net.IP
	MAC       net.HardwareAddr
	ExpiresAt time.Time
}

// PacketConnFactory creates packet connections for the DHCP server.
// This interface allows dependency injection for testing.
type PacketConnFactory interface {
	// CreateConn creates a packet connection for the DHCP server.
	CreateConn(iface string, serverIP net.IP, useRawSocket bool) (net.PacketConn, error)
}

// DefaultPacketConnFactory is the default implementation that creates real network connections.
type DefaultPacketConnFactory struct{}

// CreateConn creates a real packet connection.
func (f *DefaultPacketConnFactory) CreateConn(iface string, serverIP net.IP, useRawSocket bool) (net.PacketConn, error) {
	if useRawSocket {
		return NewServerRawConn(iface, serverIP, 67)
	}
	laddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 67,
	}
	return net.ListenUDP("udp4", laddr)
}

// DHCPServerOption is a functional option for configuring the DHCP server.
type DHCPServerOption func(*DHCPServer)

// WithIPAllocator sets a custom IP allocator for the DHCP server.
// This allows integration with external IPAM systems.
func WithIPAllocator(allocator IPAllocator) DHCPServerOption {
	return func(s *DHCPServer) {
		s.allocator = allocator
	}
}

// WithPacketConnFactory sets a custom packet connection factory.
func WithPacketConnFactory(factory PacketConnFactory) DHCPServerOption {
	return func(s *DHCPServer) {
		s.connFactory = factory
	}
}

// DHCPServer implements a DHCP server for PXE boot support.
type DHCPServer struct {
	config      *DHCPConfig
	serverIP    net.IP
	broadcastIP net.IP
	logger      *logging.Logger
	leases      map[string]*lease
	mu          sync.RWMutex
	nextIP      net.IP
	connFactory PacketConnFactory
	allocator   IPAllocator // Optional IPAM-backed allocator
}

// NewDHCPServer creates a new DHCP server instance from a DHCPConfig.
func NewDHCPServer(cfg *DHCPConfig, logger *logging.Logger, opts ...DHCPServerOption) (*DHCPServer, error) {
	if cfg == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "DHCP config is nil"}}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Validate required fields
	if cfg.ServerIP == nil {
		return nil, &SentinelCauseError{Sentinel: ErrNoServerIP, Cause: &MessageError{Msg: "server IP is required"}}
	}

	if cfg.RangeStart == nil || cfg.RangeEnd == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidIPRange, Cause: &MessageError{Msg: "IP range must be specified"}}
	}

	// Set default lease time if not specified
	if cfg.LeaseTime == 0 {
		cfg.LeaseTime = DefaultLeaseTime
	}

	// Calculate broadcast IP if not set
	if cfg.BroadcastIP == nil && cfg.SubnetMask != nil {
		cfg.BroadcastIP = calculateBroadcastIP(cfg.ServerIP, cfg.SubnetMask)
	}

	server := &DHCPServer{
		config:      cfg,
		serverIP:    cfg.ServerIP,
		broadcastIP: cfg.BroadcastIP,
		logger:      logger,
		leases:      make(map[string]*lease),
		nextIP:      cfg.RangeStart,
		connFactory: &DefaultPacketConnFactory{},
	}

	// Apply functional options
	for _, opt := range opts {
		opt(server)
	}

	return server, nil
}

// SetConnFactory sets a custom packet connection factory for testing.
func (s *DHCPServer) SetConnFactory(factory PacketConnFactory) {
	s.connFactory = factory
}

// SetAllocator sets a custom IP allocator.
// This method allows changing the allocator after server creation.
func (s *DHCPServer) SetAllocator(allocator IPAllocator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allocator = allocator
}

// GetAllocator returns the current IP allocator (may be nil).
func (s *DHCPServer) GetAllocator() IPAllocator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allocator
}

// Start starts the DHCP server.
func (s *DHCPServer) Start(ctx context.Context) error {
	s.logger.Info("Starting DHCP server",
		"interface", s.config.Interface,
		"server_ip", s.serverIP.String(),
		"range_start", s.config.RangeStart.String(),
		"range_end", s.config.RangeEnd.String())

	// Use the connection factory to create the packet connection
	conn, err := s.connFactory.CreateConn(s.config.Interface, s.serverIP, s.config.UseRawSocket)
	if err != nil {
		return &WrappedError{Msg: "failed to create connection", Err: err}
	}

	server, err := server4.NewServer(s.config.Interface, nil, s.handleDHCP, server4.WithConn(conn))
	if err != nil {
		return &WrappedError{Msg: "failed to create DHCP server", Err: err}
	}

	// Run server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(); err != nil {
			errChan <- &WrappedError{Msg: "DHCP server error", Err: err}
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down DHCP server")
		return server.Close()
	case err := <-errChan:
		return err
	}
}

// handleDHCP handles incoming DHCP requests.
func (s *DHCPServer) handleDHCP(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	s.logger.Debug("Received DHCP packet",
		"type", req.MessageType().String(),
		"mac", req.ClientHWAddr.String(),
		"xid", fmt.Sprintf("0x%x", req.TransactionID))

	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.handleDiscover(conn, peer, req)
	case dhcpv4.MessageTypeRequest:
		s.handleRequest(conn, peer, req)
	case dhcpv4.MessageTypeRelease:
		s.handleRelease(req)
	default:
		s.logger.Debug("Ignoring DHCP message type", "type", req.MessageType().String())
	}
}

// handleDiscover handles DHCP Discover messages.
func (s *DHCPServer) handleDiscover(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	isPXE := s.isPXEClient(req)
	if !isPXE && !s.config.RespondToAll {
		s.logger.Debug("Ignoring non-PXE client", "mac", req.ClientHWAddr.String())
		return
	}

	clientArch := s.getClientArch(req)
	isIPXE := s.isIPXEClient(req)

	s.logger.Info("DHCP Discover",
		"pxe", isPXE,
		"mac", req.ClientHWAddr.String(),
		"arch", fmt.Sprintf("0x%04x", clientArch),
		"is_ipxe", isIPXE)

	// Get or assign IP
	ip, err := s.getOrAssignIP(req.ClientHWAddr)
	if err != nil {
		s.logger.Error(err, "mac", req.ClientHWAddr.String())
		return
	}

	// Build DHCP Offer
	offer, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		s.logger.Error(err)
		return
	}

	offer.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	offer.YourIPAddr = ip
	offer.ServerIPAddr = s.serverIP
	offer.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
	offer.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.config.LeaseTime))

	if s.config.SubnetMask != nil {
		// Convert net.IP to net.IPMask
		mask := net.IPMask(s.config.SubnetMask.To4())
		offer.UpdateOption(dhcpv4.OptSubnetMask(mask))
	}

	if s.config.Router != nil {
		offer.UpdateOption(dhcpv4.OptRouter(s.config.Router))
	}

	if len(s.config.DNSServers) > 0 {
		offer.UpdateOption(dhcpv4.OptDNS(s.config.DNSServers...))
	}

	// Add PXE-specific options
	s.addPXEOptions(offer, clientArch, isIPXE)

	// Send offer
	if err := s.sendDHCPReply(conn, peer, req, offer); err != nil {
		s.logger.Error(err)
		return
	}

	s.logger.Debug("Sent DHCP Offer",
		"mac", req.ClientHWAddr.String(),
		"ip", ip.String())
}

// handleRequest handles DHCP Request messages.
func (s *DHCPServer) handleRequest(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	isPXE := s.isPXEClient(req)
	if !isPXE && !s.config.RespondToAll {
		s.logger.Debug("Ignoring non-PXE request", "mac", req.ClientHWAddr.String())
		return
	}

	clientArch := s.getClientArch(req)
	isIPXE := s.isIPXEClient(req)

	s.logger.Info("DHCP Request",
		"pxe", isPXE,
		"mac", req.ClientHWAddr.String(),
		"arch", fmt.Sprintf("0x%04x", clientArch),
		"is_ipxe", isIPXE)

	// Confirm lease
	ip, err := s.confirmLease(req.ClientHWAddr, req.RequestedIPAddress())
	if err != nil {
		s.logger.Error(err, "mac", req.ClientHWAddr.String())
		return
	}

	// Build DHCP ACK
	ack, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		s.logger.Error(err)
		return
	}

	ack.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	ack.YourIPAddr = ip
	ack.ServerIPAddr = s.serverIP
	ack.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
	ack.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.config.LeaseTime))

	if s.config.SubnetMask != nil {
		// Convert net.IP to net.IPMask
		mask := net.IPMask(s.config.SubnetMask.To4())
		ack.UpdateOption(dhcpv4.OptSubnetMask(mask))
	}

	if s.config.Router != nil {
		ack.UpdateOption(dhcpv4.OptRouter(s.config.Router))
	}

	if len(s.config.DNSServers) > 0 {
		ack.UpdateOption(dhcpv4.OptDNS(s.config.DNSServers...))
	}

	// Add PXE-specific options
	s.addPXEOptions(ack, clientArch, isIPXE)

	// Send ACK
	if err := s.sendDHCPReply(conn, peer, req, ack); err != nil {
		s.logger.Error(err)
		return
	}

	s.logger.Info("Sent DHCP ACK",
		"mac", req.ClientHWAddr.String(),
		"ip", ip.String(),
		"boot_file", ack.BootFileName)
}

// handleRelease handles DHCP Release messages.
func (s *DHCPServer) handleRelease(req *dhcpv4.DHCPv4) {
	s.logger.Debug("Received DHCP Release", "mac", req.ClientHWAddr.String())

	// Use allocator if available
	if s.allocator != nil {
		ctx := context.Background()
		if err := s.allocator.Release(ctx, req.ClientHWAddr); err != nil {
			s.logger.Error(err, "mac", req.ClientHWAddr.String())
		}
		return
	}

	// Use built-in lease management
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leases, req.ClientHWAddr.String())
}

// addPXEOptions adds PXE-specific DHCP options to the reply.
func (s *DHCPServer) addPXEOptions(reply *dhcpv4.DHCPv4, clientArch uint16, isIPXE bool) {
	if isIPXE {
		// iPXE client - chain to HTTP script
		if s.config.IPXEScript != "" {
			reply.BootFileName = s.config.IPXEScript
			s.logger.Debug("Setting iPXE script", "script", s.config.IPXEScript)
		}
	} else {
		// Non-iPXE client - provide initial bootloader. The chosen
		// filename varies by client architecture so legacy BIOS
		// clients get a 16-bit binary they can execute and UEFI
		// clients get an EFI binary their firmware can load.
		if filename := s.bootFilenameForArch(clientArch); filename != "" {
			reply.BootFileName = filename
			s.logger.Debug("Setting boot filename",
				"filename", filename,
				"arch", fmt.Sprintf("0x%04x", clientArch))
		}

		// Set TFTP server
		if s.config.TFTPServerName != "" {
			reply.ServerHostName = s.config.TFTPServerName
		}
		if s.config.TFTPServerIP != nil {
			reply.ServerIPAddr = s.config.TFTPServerIP
		}

		// Echo the "PXEClient" vendor class (option 60) in the reply. UEFI
		// PXE firmware requires the OFFER/ACK to identify itself as a PXE
		// server, otherwise it rejects the reply and keeps re-DISCOVERing
		// (observed as PXE-E18 "Server response timeout" and no boot-file
		// download). Legacy BIOS option ROMs (e.g. Intel Boot Agent) are
		// lenient and boot without this, which is why legacy PXE worked while
		// UEFI PXE silently looped. See RFC 4578.
		reply.UpdateOption(dhcpv4.OptClassIdentifier(vendorClassPXEClient))

		// PXE option 43 (vendor-specific information) with PXE_DISCOVERY_CONTROL
		// (sub-option 6) bit 3 = 0x08: "download the boot file named in THIS
		// reply without performing PXE Boot Server discovery". Once option 60
		// marks us as a PXEClient server, ATEN UEFI firmware otherwise enters
		// Boot Server Discovery (unicast to UDP 4011 / multicast), gets no
		// response from this simple DHCP+TFTP server, and fails with PXE-E18
		// instead of TFTP-ing the offered NBP. Setting bit 3 tells it to use
		// the bootfile + next-server it already has. (PXE 2.1 spec §2.2.1,
		// Table PXE_DISCOVERY_CONTROL.) Trailing 0xFF is the PXE option END.
		reply.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, []byte{
			pxeDiscoveryControlSubOption, 0x01, pxeDiscoveryUseBootfile,
			pxeVendorOptionEnd,
		}))
	}
}

// bootFilenameForArch returns the TFTP boot filename appropriate
// for the given DHCP option-93 client architecture value. It
// consults s.config.BootFilenameByArch first, then falls back to
// s.config.BootFilename when the architecture isn't mapped.
//
// Mapping a UEFI binary to a legacy BIOS PXE ROM produces a silent
// boot failure and a DISCOVER loop, so callers that build a
// DHCPConfig manually should populate BootFilenameByArch via
// DefaultBootFilenameByArch unless they have a single-arch fleet.
func (s *DHCPServer) bootFilenameForArch(clientArch uint16) string {
	if f, ok := s.config.BootFilenameByArch[clientArch]; ok && f != "" {
		return f
	}
	return s.config.BootFilename
}

// DefaultBootFilenameByArch returns the standard architecture-to-
// bootfile mapping used when the operator hasn't customized it.
// The filenames here must match the entries that TFTPServer
// loadFirmware populates.
func DefaultBootFilenameByArch() map[uint16]string {
	return map[uint16]string{
		archBIOSx86: "undionly.kpxe",
		archEFIx86:  "ipxe32.efi",
		archEFIx64:  "ipxe.efi",
		archEFIBC:   "ipxe.efi",
	}
}

// isPXEClient checks if the request is from a PXE client.
func (s *DHCPServer) isPXEClient(req *dhcpv4.DHCPv4) bool {
	// Check for PXE vendor class identifier (option 60)
	vendorClass := req.Options.Get(dhcpv4.OptionClassIdentifier)
	if len(vendorClass) > 0 {
		vendorStr := string(vendorClass)
		if len(vendorStr) >= len(vendorClassPXEClient) &&
			vendorStr[:len(vendorClassPXEClient)] == vendorClassPXEClient {
			return true
		}
	}

	// Check for client system architecture (option 93)
	if req.Options.Has(dhcpv4.OptionClientSystemArchitectureType) {
		return true
	}

	return false
}

// isIPXEClient checks if the request is from an iPXE client.
func (s *DHCPServer) isIPXEClient(req *dhcpv4.DHCPv4) bool {
	// Check user class (option 77)
	userClass := req.Options.Get(dhcpv4.OptionUserClassInformation)
	if len(userClass) > 0 && string(userClass) == vendorClassIPXE {
		return true
	}

	// Check vendor class identifier (option 60)
	vendorClass := req.Options.Get(dhcpv4.OptionClassIdentifier)
	if len(vendorClass) > 0 && string(vendorClass) == vendorClassIPXE {
		return true
	}

	return false
}

// getClientArch extracts the client architecture from DHCP options.
func (s *DHCPServer) getClientArch(req *dhcpv4.DHCPv4) uint16 {
	archOpt := req.GetOneOption(dhcpv4.OptionClientSystemArchitectureType)
	if len(archOpt) >= 2 {
		return uint16(archOpt[0])<<8 | uint16(archOpt[1])
	}
	return archBIOSx86 // Default to BIOS x86
}

// getOrAssignIP gets an existing lease or assigns a new IP address.
// If an IPAllocator is configured, it will be used for allocation.
func (s *DHCPServer) getOrAssignIP(mac net.HardwareAddr) (net.IP, error) {
	// Use allocator if available
	if s.allocator != nil {
		ctx := context.Background()
		return s.allocator.Allocate(ctx, mac, "")
	}

	// Use built-in allocation
	s.mu.Lock()
	defer s.mu.Unlock()

	macStr := mac.String()

	// Check if we have an existing lease
	if l, exists := s.leases[macStr]; exists {
		if time.Now().Before(l.ExpiresAt) {
			s.logger.Debug("Reusing existing lease",
				"mac", macStr,
				"ip", l.IP.String(),
				"expires", l.ExpiresAt)
			return l.IP, nil
		}
		// Lease expired, will reassign
		delete(s.leases, macStr)
	}

	// Assign new IP
	ip := s.findAvailableIP()
	if ip == nil {
		return nil, ErrNoAvailableIPs
	}

	// Create lease
	s.leases[macStr] = &lease{
		IP:        ip,
		MAC:       mac,
		ExpiresAt: time.Now().Add(s.config.LeaseTime),
	}

	s.logger.Debug("Assigned new lease",
		"mac", macStr,
		"ip", ip.String(),
		"expires", s.leases[macStr].ExpiresAt)

	return ip, nil
}

// confirmLease confirms and updates a lease for the given MAC address.
// If an IPAllocator is configured, it will renew the allocation.
func (s *DHCPServer) confirmLease(mac net.HardwareAddr, requestedIP net.IP) (net.IP, error) {
	// Use allocator if available
	if s.allocator != nil {
		ctx := context.Background()

		// Try to get existing lease first
		l, err := s.allocator.GetLease(ctx, mac)
		if err == nil {
			// Renew the existing lease
			if err := s.allocator.Renew(ctx, mac); err != nil {
				s.logger.Debug("Failed to renew lease, allocating new",
					"mac", mac.String(),
					"error", err)
				// Fall through to allocate new
			} else {
				return l.IP, nil
			}
		}

		// No existing lease or renewal failed, allocate new
		return s.allocator.Allocate(ctx, mac, "")
	}

	// Use built-in lease management
	s.mu.Lock()
	defer s.mu.Unlock()

	macStr := mac.String()

	// Check if we have an existing lease
	if l, exists := s.leases[macStr]; exists {
		// Update expiration
		l.ExpiresAt = time.Now().Add(s.config.LeaseTime)
		s.logger.Debug("Confirmed lease",
			"mac", macStr,
			"ip", l.IP.String(),
			"expires", l.ExpiresAt)
		return l.IP, nil
	}

	// No existing lease, assign new one
	ip := s.findAvailableIP()
	if ip == nil {
		return nil, ErrNoAvailableIPs
	}

	// Create lease
	s.leases[macStr] = &lease{
		IP:        ip,
		MAC:       mac,
		ExpiresAt: time.Now().Add(s.config.LeaseTime),
	}

	s.logger.Debug("Created new lease",
		"mac", macStr,
		"ip", ip.String(),
		"expires", s.leases[macStr].ExpiresAt)

	return ip, nil
}

// findAvailableIP finds an available IP address in the configured range.
func (s *DHCPServer) findAvailableIP() net.IP {
	// Start from nextIP
	current := make(net.IP, len(s.nextIP))
	copy(current, s.nextIP)

	// Search for available IP
	for compareIPs(current, s.config.RangeEnd) <= 0 {
		// Check if IP is in use
		inUse := false
		for _, l := range s.leases {
			if l.IP.Equal(current) && time.Now().Before(l.ExpiresAt) {
				inUse = true
				break
			}
		}

		if !inUse {
			// Found available IP, update nextIP for next search
			s.nextIP = incrementIP(current)
			if compareIPs(s.nextIP, s.config.RangeEnd) > 0 {
				s.nextIP = make(net.IP, len(s.config.RangeStart))
				copy(s.nextIP, s.config.RangeStart)
			}
			return current
		}

		current = incrementIP(current)
	}

	// Wrap around to start of range
	current = make(net.IP, len(s.config.RangeStart))
	copy(current, s.config.RangeStart)

	for compareIPs(current, s.nextIP) < 0 {
		// Check if IP is in use
		inUse := false
		for _, l := range s.leases {
			if l.IP.Equal(current) && time.Now().Before(l.ExpiresAt) {
				inUse = true
				break
			}
		}

		if !inUse {
			s.nextIP = incrementIP(current)
			return current
		}

		current = incrementIP(current)
	}

	return nil
}

// incrementIP increments an IP address by 1.
func incrementIP(ip net.IP) net.IP {
	// Make a copy
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// Increment from the last byte
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}

	return newIP
}

// compareIPs compares two IP addresses.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareIPs(a, b net.IP) int {
	// Normalize to IPv4
	a = a.To4()
	b = b.To4()

	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// sendDHCPReply sends a DHCP reply packet.
func (s *DHCPServer) sendDHCPReply(conn net.PacketConn, peer net.Addr, req, reply *dhcpv4.DHCPv4) error {
	// Determine destination address
	var dst net.Addr

	// If the request has a giaddr (relay agent), send to the relay
	if !req.GatewayIPAddr.IsUnspecified() && !req.GatewayIPAddr.Equal(net.IPv4zero) {
		dst = &net.UDPAddr{
			IP:   req.GatewayIPAddr,
			Port: 67,
		}
	} else if req.IsBroadcast() || req.ClientIPAddr.IsUnspecified() || req.ClientIPAddr.Equal(net.IPv4zero) {
		// Broadcast
		dst = &net.UDPAddr{
			IP:   s.broadcastIP,
			Port: 68,
		}
		reply.SetBroadcast()
	} else {
		// Unicast to client
		dst = &net.UDPAddr{
			IP:   req.ClientIPAddr,
			Port: 68,
		}
	}

	_, err := conn.WriteTo(reply.ToBytes(), dst)
	return err
}
