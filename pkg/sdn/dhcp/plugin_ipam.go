// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// DHCP Option codes for T1 and T2 timers (RFC 2132)
var (
	OptionRenewalTimeValue   dhcpv4.GenericOptionCode = 58
	OptionRebindingTimeValue dhcpv4.GenericOptionCode = 59
)

// PluginName is the name used in CoreDHCP configuration.
const PluginName = "platform-ipam"

// MessageHandler is a handler function for DHCP messages.
type MessageHandler func(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool)

// IPAMPlugin bridges CoreDHCP to the platform IPAM system.
type IPAMPlugin struct {
	allocator    ipam.Allocator
	poolID       string
	leaseStore   *LeaseStore
	defaultLease time.Duration
	options      DHCPOptions
	handlers     map[dhcpv4.MessageType]MessageHandler
	logger       *slog.Logger
	mu           sync.RWMutex
	closed       atomic.Bool
}

// IPAMPluginOption configures an IPAMPlugin.
type IPAMPluginOption func(*IPAMPlugin)

// WithLogger sets the logger for the plugin.
func WithLogger(logger *slog.Logger) IPAMPluginOption {
	return func(p *IPAMPlugin) {
		p.logger = logger
	}
}

// WithLeaseStore sets a custom lease store.
func WithLeaseStore(ls *LeaseStore) IPAMPluginOption {
	return func(p *IPAMPlugin) {
		p.leaseStore = ls
	}
}

// WithDefaultLease sets the default lease duration.
func WithDefaultLease(d time.Duration) IPAMPluginOption {
	return func(p *IPAMPlugin) {
		p.defaultLease = d
	}
}

// NewIPAMPlugin creates a new IPAM plugin instance.
func NewIPAMPlugin(allocator ipam.Allocator, poolID string, opts DHCPOptions, pluginOpts ...IPAMPluginOption) (*IPAMPlugin, error) {
	if allocator == nil {
		return nil, ErrAllocatorRequired
	}
	if poolID == "" {
		return nil, ErrPoolIDRequired
	}

	// Validate and set defaults for options
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	p := &IPAMPlugin{
		allocator:    allocator,
		poolID:       poolID,
		leaseStore:   NewLeaseStore(),
		defaultLease: opts.LeaseTime,
		options:      opts,
		logger:       slog.Default(),
	}

	// Apply options
	for _, opt := range pluginOpts {
		opt(p)
	}

	// Initialize message handlers using map-based dispatch
	p.handlers = map[dhcpv4.MessageType]MessageHandler{
		dhcpv4.MessageTypeDiscover: p.handleDiscover,
		dhcpv4.MessageTypeRequest:  p.handleRequest,
		dhcpv4.MessageTypeRelease:  p.handleRelease,
		dhcpv4.MessageTypeDecline:  p.handleDecline,
		dhcpv4.MessageTypeInform:   p.handleInform,
	}

	return p, nil
}

// Handler4 returns the DHCPv4 handler function.
func (p *IPAMPlugin) Handler4() handler.Handler4 {
	return func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		if p.closed.Load() {
			return nil, true
		}

		ctx := context.Background()

		// Use map-based dispatch for O(1) lookup
		if handler, ok := p.handlers[req.MessageType()]; ok {
			return handler(ctx, req, resp)
		}

		// Unknown message type - continue chain
		return resp, false
	}
}

// handleDiscover handles DHCPDISCOVER messages.
func (p *IPAMPlugin) handleDiscover(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mac := req.ClientHWAddr

	p.logger.Debug("handling DHCPDISCOVER",
		slog.String("mac", mac.String()),
		slog.String("hostname", req.HostName()))

	// Check for existing lease
	if lease, ok := p.leaseStore.GetByMAC(mac); ok && lease.IsActive() {
		// Renew existing lease in IPAM
		if err := p.allocator.Renew(ctx, lease.IP); err == nil {
			p.logger.Debug("renewing existing lease",
				slog.String("mac", mac.String()),
				slog.String("ip", lease.IP.String()))
			return p.buildOffer(req, resp, lease.IP), true
		}
		// Lease renewal failed, allocate new IP
		_ = p.leaseStore.Remove(lease.IP)
	}

	// Allocate new IP from IPAM
	allocation, err := p.allocator.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   p.poolID,
		DeviceID: mac.String(),
		Hostname: req.HostName(),
		Metadata: map[string]string{
			"dhcp_client":  "true",
			"message_type": "discover",
		},
		LeaseDuration: p.defaultLease,
	})
	if err != nil {
		p.logger.Error("failed to allocate IP",
			slog.String("mac", mac.String()),
			slog.String("error", err.Error()))
		// Pool exhausted or error - don't respond
		return nil, true
	}

	// Create lease record
	now := time.Now()
	lease := &Lease{
		IP:        allocation.IP,
		MAC:       mac,
		Hostname:  req.HostName(),
		PoolID:    p.poolID,
		ClientID:  req.Options.Get(dhcpv4.OptionClientIdentifier),
		LeasedAt:  now,
		ExpiresAt: now.Add(p.defaultLease),
		State:     LeaseStateActive,
	}
	if err := p.leaseStore.Add(lease); err != nil {
		p.logger.Error("failed to add lease",
			slog.String("mac", mac.String()),
			slog.String("error", err.Error()))
		// Release the allocation since we couldn't track it
		_ = p.allocator.Release(ctx, allocation.IP)
		return nil, true
	}

	p.logger.Info("allocated IP for DISCOVER",
		slog.String("mac", mac.String()),
		slog.String("ip", allocation.IP.String()))

	return p.buildOffer(req, resp, allocation.IP), true
}

// handleRequest handles DHCPREQUEST messages.
func (p *IPAMPlugin) handleRequest(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mac := req.ClientHWAddr

	p.logger.Debug("handling DHCPREQUEST",
		slog.String("mac", mac.String()),
		slog.String("hostname", req.HostName()))

	// Get requested IP from options or ciaddr
	requestedIP := p.getRequestedIP(req)
	if !requestedIP.IsValid() {
		p.logger.Warn("no requested IP in DHCPREQUEST",
			slog.String("mac", mac.String()))
		return p.buildNak(req, resp), true
	}

	// Check if we have a lease for this MAC
	existingLease, hasLease := p.leaseStore.GetByMAC(mac)
	if hasLease && existingLease.IP == requestedIP {
		// Renew existing lease
		if err := p.allocator.Renew(ctx, requestedIP); err != nil {
			p.logger.Warn("failed to renew lease in IPAM",
				slog.String("mac", mac.String()),
				slog.String("ip", requestedIP.String()),
				slog.String("error", err.Error()))
			return p.buildNak(req, resp), true
		}

		// Update lease store
		if err := p.leaseStore.Renew(requestedIP, p.defaultLease); err != nil {
			p.logger.Warn("failed to renew lease locally",
				slog.String("mac", mac.String()),
				slog.String("ip", requestedIP.String()),
				slog.String("error", err.Error()))
		}

		p.logger.Info("renewed lease for REQUEST",
			slog.String("mac", mac.String()),
			slog.String("ip", requestedIP.String()))

		return p.buildAck(req, resp, requestedIP), true
	}

	// Check if IP is already leased to another MAC
	if leaseByIP, ok := p.leaseStore.GetByIP(requestedIP); ok {
		if leaseByIP.MAC.String() != mac.String() {
			p.logger.Warn("IP already leased to another client",
				slog.String("mac", mac.String()),
				slog.String("requested_ip", requestedIP.String()),
				slog.String("existing_mac", leaseByIP.MAC.String()))
			return p.buildNak(req, resp), true
		}
	}

	// Try to allocate specific IP for new client
	allocation, err := p.allocator.AllocateSpecific(ctx, &ipam.AllocationRequest{
		PoolID:      p.poolID,
		DeviceID:    mac.String(),
		Hostname:    req.HostName(),
		RequestedIP: requestedIP,
		Metadata: map[string]string{
			"dhcp_client":  "true",
			"message_type": "request",
		},
		LeaseDuration: p.defaultLease,
	})
	if err != nil {
		p.logger.Warn("failed to allocate specific IP",
			slog.String("mac", mac.String()),
			slog.String("requested_ip", requestedIP.String()),
			slog.String("error", err.Error()))
		return p.buildNak(req, resp), true
	}

	// Create lease record
	now := time.Now()
	lease := &Lease{
		IP:        allocation.IP,
		MAC:       mac,
		Hostname:  req.HostName(),
		PoolID:    p.poolID,
		ClientID:  req.Options.Get(dhcpv4.OptionClientIdentifier),
		LeasedAt:  now,
		ExpiresAt: now.Add(p.defaultLease),
		State:     LeaseStateActive,
	}
	if err := p.leaseStore.Add(lease); err != nil {
		p.logger.Error("failed to add lease",
			slog.String("mac", mac.String()),
			slog.String("error", err.Error()))
		_ = p.allocator.Release(ctx, allocation.IP)
		return p.buildNak(req, resp), true
	}

	p.logger.Info("allocated specific IP for REQUEST",
		slog.String("mac", mac.String()),
		slog.String("ip", allocation.IP.String()))

	return p.buildAck(req, resp, allocation.IP), true
}

// handleRelease handles DHCPRELEASE messages.
func (p *IPAMPlugin) handleRelease(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mac := req.ClientHWAddr
	clientIP := req.ClientIPAddr

	p.logger.Debug("handling DHCPRELEASE",
		slog.String("mac", mac.String()),
		slog.String("ip", clientIP.String()))

	if clientIP == nil || clientIP.IsUnspecified() {
		p.logger.Warn("no client IP in DHCPRELEASE",
			slog.String("mac", mac.String()))
		return nil, true
	}

	releasedIP, ok := netip.AddrFromSlice(clientIP.To4())
	if !ok {
		releasedIP, ok = netip.AddrFromSlice(clientIP.To16())
		if !ok {
			p.logger.Warn("invalid client IP in DHCPRELEASE",
				slog.String("mac", mac.String()))
			return nil, true
		}
	}

	// Verify the lease belongs to this MAC
	lease, ok := p.leaseStore.GetByIP(releasedIP)
	if !ok {
		p.logger.Warn("no lease found for DHCPRELEASE",
			slog.String("mac", mac.String()),
			slog.String("ip", releasedIP.String()))
		return nil, true
	}

	if lease.MAC.String() != mac.String() {
		p.logger.Warn("lease MAC mismatch in DHCPRELEASE",
			slog.String("mac", mac.String()),
			slog.String("lease_mac", lease.MAC.String()),
			slog.String("ip", releasedIP.String()))
		return nil, true
	}

	// Release from IPAM
	if err := p.allocator.Release(ctx, releasedIP); err != nil {
		p.logger.Warn("failed to release IP from IPAM",
			slog.String("mac", mac.String()),
			slog.String("ip", releasedIP.String()),
			slog.String("error", err.Error()))
	}

	// Update lease state and remove
	_ = p.leaseStore.SetState(releasedIP, LeaseStateReleased)
	if err := p.leaseStore.Remove(releasedIP); err != nil {
		p.logger.Warn("failed to remove lease",
			slog.String("mac", mac.String()),
			slog.String("ip", releasedIP.String()),
			slog.String("error", err.Error()))
	}

	p.logger.Info("released IP",
		slog.String("mac", mac.String()),
		slog.String("ip", releasedIP.String()))

	// DHCPRELEASE doesn't get a response
	return nil, true
}

// handleDecline handles DHCPDECLINE messages.
func (p *IPAMPlugin) handleDecline(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mac := req.ClientHWAddr

	p.logger.Debug("handling DHCPDECLINE",
		slog.String("mac", mac.String()))

	// Get the declined IP from options
	requestedIP := p.getRequestedIP(req)
	if !requestedIP.IsValid() {
		p.logger.Warn("no declined IP in DHCPDECLINE",
			slog.String("mac", mac.String()))
		return nil, true
	}

	// Mark the lease as declined
	_ = p.leaseStore.SetState(requestedIP, LeaseStateDeclined)

	// Remove the lease
	if err := p.leaseStore.Remove(requestedIP); err != nil {
		p.logger.Warn("failed to remove declined lease",
			slog.String("mac", mac.String()),
			slog.String("ip", requestedIP.String()),
			slog.String("error", err.Error()))
	}

	// Release from IPAM (it will be unavailable for a while due to conflict detection)
	if err := p.allocator.Release(context.Background(), requestedIP); err != nil {
		p.logger.Warn("failed to release declined IP from IPAM",
			slog.String("mac", mac.String()),
			slog.String("ip", requestedIP.String()),
			slog.String("error", err.Error()))
	}

	p.logger.Warn("client declined IP",
		slog.String("mac", mac.String()),
		slog.String("ip", requestedIP.String()))

	// DHCPDECLINE doesn't get a response
	return nil, true
}

// handleInform handles DHCPINFORM messages.
func (p *IPAMPlugin) handleInform(ctx context.Context, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	mac := req.ClientHWAddr
	clientIP := req.ClientIPAddr

	p.logger.Debug("handling DHCPINFORM",
		slog.String("mac", mac.String()),
		slog.String("ip", clientIP.String()))

	// DHCPINFORM clients have their own IP, they just want configuration
	if clientIP == nil || clientIP.IsUnspecified() {
		p.logger.Warn("no client IP in DHCPINFORM",
			slog.String("mac", mac.String()))
		return nil, true
	}

	// Build ACK with configuration options but no IP lease
	informIP, ok := netip.AddrFromSlice(clientIP.To4())
	if !ok {
		informIP, ok = netip.AddrFromSlice(clientIP.To16())
		if !ok {
			p.logger.Warn("invalid client IP in DHCPINFORM",
				slog.String("mac", mac.String()))
			return nil, true
		}
	}

	// Build response with configuration options
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	p.addCommonOptions(resp)

	// DHCPINFORM responses don't include lease time
	resp.Options.Del(dhcpv4.OptionIPAddressLeaseTime)
	resp.Options.Del(OptionRenewalTimeValue)
	resp.Options.Del(OptionRebindingTimeValue)

	// Set the client's existing IP
	resp.YourIPAddr = clientIP

	p.logger.Info("sent configuration for DHCPINFORM",
		slog.String("mac", mac.String()),
		slog.String("ip", informIP.String()))

	return resp, true
}

// buildOffer builds a DHCPOFFER response.
func (p *IPAMPlugin) buildOffer(req, resp *dhcpv4.DHCPv4, ip netip.Addr) *dhcpv4.DHCPv4 {
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	resp.YourIPAddr = ip.AsSlice()
	resp.UpdateOption(dhcpv4.OptServerIdentifier(resp.ServerIPAddr))

	p.addCommonOptions(resp)
	p.addLeaseOptions(resp)

	return resp
}

// buildAck builds a DHCPACK response.
func (p *IPAMPlugin) buildAck(req, resp *dhcpv4.DHCPv4, ip netip.Addr) *dhcpv4.DHCPv4 {
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	resp.YourIPAddr = ip.AsSlice()
	resp.UpdateOption(dhcpv4.OptServerIdentifier(resp.ServerIPAddr))

	p.addCommonOptions(resp)
	p.addLeaseOptions(resp)

	return resp
}

// buildNak builds a DHCPNAK response.
func (p *IPAMPlugin) buildNak(req, resp *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
	resp.UpdateOption(dhcpv4.OptServerIdentifier(resp.ServerIPAddr))

	// NAK should have minimal options
	return resp
}

// addCommonOptions adds common DHCP options to the response.
func (p *IPAMPlugin) addCommonOptions(resp *dhcpv4.DHCPv4) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.options.SubnetMask != nil {
		resp.UpdateOption(dhcpv4.OptSubnetMask(p.options.SubnetMask))
	}

	if p.options.Router.IsValid() {
		resp.UpdateOption(dhcpv4.OptRouter(p.options.Router.AsSlice()))
	}

	if len(p.options.DNS) > 0 {
		dnsServers := make([]net.IP, len(p.options.DNS))
		for i, dns := range p.options.DNS {
			dnsServers[i] = dns.AsSlice()
		}
		resp.UpdateOption(dhcpv4.OptDNS(dnsServers...))
	}

	if p.options.DomainName != "" {
		resp.UpdateOption(dhcpv4.OptDomainName(p.options.DomainName))
	}

	if len(p.options.NTPServers) > 0 {
		ntpServers := make([]net.IP, len(p.options.NTPServers))
		for i, ntp := range p.options.NTPServers {
			ntpServers[i] = ntp.AsSlice()
		}
		resp.UpdateOption(dhcpv4.OptNTPServers(ntpServers...))
	}

	if p.options.MTU > 0 {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionInterfaceMTU, []byte{
			byte(p.options.MTU >> 8),
			byte(p.options.MTU),
		}))
	}

	if p.options.Hostname != "" {
		resp.UpdateOption(dhcpv4.OptHostName(p.options.Hostname))
	}
}

// addLeaseOptions adds lease time options to the response.
func (p *IPAMPlugin) addLeaseOptions(resp *dhcpv4.DHCPv4) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	leaseTime := uint32(p.options.LeaseTime.Seconds())
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Duration(leaseTime) * time.Second))

	// Add T1 (renewal) time - option 58
	renewalTime := uint32(p.options.RenewalTime.Seconds())
	renewalBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(renewalBytes, renewalTime)
	resp.UpdateOption(dhcpv4.OptGeneric(OptionRenewalTimeValue, renewalBytes))

	// Add T2 (rebinding) time - option 59
	rebindTime := uint32(p.options.RebindTime.Seconds())
	rebindBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(rebindBytes, rebindTime)
	resp.UpdateOption(dhcpv4.OptGeneric(OptionRebindingTimeValue, rebindBytes))
}

// getRequestedIP extracts the requested IP from a DHCP request.
func (p *IPAMPlugin) getRequestedIP(req *dhcpv4.DHCPv4) netip.Addr {
	// First check the Requested IP Address option (option 50)
	if requestedIPOpt := req.Options.Get(dhcpv4.OptionRequestedIPAddress); requestedIPOpt != nil {
		if len(requestedIPOpt) >= 4 {
			ip, ok := netip.AddrFromSlice(requestedIPOpt)
			if ok && ip.IsValid() {
				return ip
			}
		}
	}

	// Fall back to ciaddr
	if req.ClientIPAddr != nil && !req.ClientIPAddr.IsUnspecified() {
		ip, ok := netip.AddrFromSlice(req.ClientIPAddr.To4())
		if ok && ip.IsValid() {
			return ip
		}
		ip, ok = netip.AddrFromSlice(req.ClientIPAddr.To16())
		if ok && ip.IsValid() {
			return ip
		}
	}

	return netip.Addr{}
}

// GetLeaseStore returns the lease store for inspection.
func (p *IPAMPlugin) GetLeaseStore() *LeaseStore {
	return p.leaseStore
}

// GetPoolID returns the pool ID.
func (p *IPAMPlugin) GetPoolID() string {
	return p.poolID
}

// GetOptions returns a copy of the DHCP options.
func (p *IPAMPlugin) GetOptions() DHCPOptions {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return *p.options.Clone()
}

// SetOptions updates the DHCP options.
func (p *IPAMPlugin) SetOptions(opts DHCPOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.options = opts
	p.defaultLease = opts.LeaseTime
	return nil
}

// Close closes the plugin and releases resources.
func (p *IPAMPlugin) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		return p.leaseStore.Close()
	}
	return ErrPluginClosed
}
