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

package dhcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// CoreDHCPServer wraps CoreDHCP with multi-interface and IPAM support.
// It implements the Server interface for DHCP operations.
type CoreDHCPServer struct {
	config      *ServerConfig
	allocator   ipam.Allocator
	servers     map[string]*server4.Server // per-interface servers
	plugins     map[string]*IPAMPlugin     // per-interface IPAM plugins
	leases      *LeaseStore
	stats       *StatsCollector
	running     atomic.Bool
	logger      *slog.Logger
	mu          sync.RWMutex
	cancelFuncs map[string]context.CancelFunc
}

// CoreDHCPServerOption configures a CoreDHCPServer.
type CoreDHCPServerOption func(*CoreDHCPServer)

// WithCoreDHCPLogger sets the logger for the server.
func WithCoreDHCPLogger(logger *slog.Logger) CoreDHCPServerOption {
	return func(s *CoreDHCPServer) {
		s.logger = logger
	}
}

// WithCoreDHCPLeaseStore sets a custom lease store.
func WithCoreDHCPLeaseStore(ls *LeaseStore) CoreDHCPServerOption {
	return func(s *CoreDHCPServer) {
		s.leases = ls
	}
}

// NewCoreDHCPServer creates a new CoreDHCP-based server.
func NewCoreDHCPServer(cfg *ServerConfig, allocator ipam.Allocator, opts ...CoreDHCPServerOption) (*CoreDHCPServer, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if allocator == nil {
		return nil, ErrNilIPAMAllocator
	}

	s := &CoreDHCPServer{
		config:      cfg.Clone(),
		allocator:   allocator,
		servers:     make(map[string]*server4.Server),
		plugins:     make(map[string]*IPAMPlugin),
		leases:      NewLeaseStore(),
		stats:       NewStatsCollector(),
		logger:      slog.Default(),
		cancelFuncs: make(map[string]context.CancelFunc),
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Start starts DHCP servers on all configured interfaces.
func (s *CoreDHCPServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return ErrServerAlreadyRunning
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Start a server per interface
	for i := range s.config.Interfaces {
		iface := &s.config.Interfaces[i]
		if err := s.startInterfaceServer(ctx, iface); err != nil {
			// Cleanup already started servers
			s.stopAllServersLocked()
			return &ErrInterfaceOperation{
				Interface: iface.Name,
				Operation: "start",
				Cause:     err,
			}
		}
	}

	s.stats.Start()
	s.running.Store(true)

	s.logger.Info("CoreDHCP server started",
		slog.Int("interfaces", len(s.config.Interfaces)))

	return nil
}

// Stop stops all DHCP servers.
func (s *CoreDHCPServer) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return ErrServerNotRunning
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.stopAllServersLocked()
	s.running.Store(false)

	s.logger.Info("CoreDHCP server stopped")

	return nil
}

// stopAllServersLocked stops all servers (must be called with mutex held).
func (s *CoreDHCPServer) stopAllServersLocked() {
	// Cancel all server contexts
	for name, cancel := range s.cancelFuncs {
		cancel()
		delete(s.cancelFuncs, name)
	}

	// Close all servers
	for name, srv := range s.servers {
		if srv != nil {
			srv.Close()
		}
		delete(s.servers, name)
	}

	// Close all plugins
	for name, plugin := range s.plugins {
		if plugin != nil {
			plugin.Close()
		}
		delete(s.plugins, name)
	}
}

// startInterfaceServer starts a DHCP server on a single interface.
func (s *CoreDHCPServer) startInterfaceServer(ctx context.Context, iface *InterfaceConfig) error {
	// Validate DHCP options
	if err := iface.Options.Validate(); err != nil {
		return err
	}

	// Create IPAM plugin for this interface
	plugin, err := NewIPAMPlugin(
		s.allocator,
		iface.PoolID,
		iface.Options,
		WithLogger(s.logger),
		WithLeaseStore(s.leases),
		WithDefaultLease(iface.Options.LeaseTime),
	)
	if err != nil {
		return &WrappedError{Msg: "failed to create IPAM plugin", Err: err}
	}

	// Create handler function for server4
	handlerFunc := s.createHandlerFunc(plugin)

	// Create server with listening address
	listenAddr := fmt.Sprintf("%s:67", iface.Address.String())
	if !iface.Address.IsValid() {
		// Listen on interface address if not specified
		listenAddr = ":67"
	}

	srv, err := server4.NewServer(
		iface.Name,
		&net.UDPAddr{
			IP:   iface.Address.AsSlice(),
			Port: 67,
		},
		handlerFunc,
	)
	if err != nil {
		plugin.Close()
		return &WrappedError{Msg: fmt.Sprintf("failed to create server for %s", iface.Name), Err: err}
	}

	// Create cancellable context for this server
	serverCtx, cancel := context.WithCancel(ctx)
	s.cancelFuncs[iface.Name] = cancel

	// Start server in background
	go func() {
		s.logger.Info("starting DHCP server on interface",
			slog.String("interface", iface.Name),
			slog.String("address", listenAddr),
			slog.String("pool", iface.PoolID))

		if err := srv.Serve(); err != nil {
			select {
			case <-serverCtx.Done():
				// Server was stopped intentionally
				return
			default:
				s.logger.Error("DHCP server error",
					slog.String("interface", iface.Name),
					slog.String("error", err.Error()))
				s.stats.IncError()
			}
		}
	}()

	s.servers[iface.Name] = srv
	s.plugins[iface.Name] = plugin

	return nil
}

// createHandlerFunc creates the DHCP handler function with statistics.
func (s *CoreDHCPServer) createHandlerFunc(plugin *IPAMPlugin) server4.Handler {
	// Wrap the plugin handler with statistics collection
	return func(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
		s.stats.IncPacketsReceived()

		// Record message type statistics
		s.recordMessageTypeStats(req.MessageType())

		// Create response
		resp, err := dhcpv4.NewReplyFromRequest(req)
		if err != nil {
			s.logger.Error("failed to create DHCP response",
				slog.String("error", err.Error()))
			s.stats.IncError()
			return
		}

		// Call the plugin handler
		result, stop := plugin.Handler4()(req, resp)

		if result != nil && !stop {
			s.stats.IncPacketsSent()
			s.recordResponseStats(result.MessageType())

			// Send response
			if _, err := conn.WriteTo(result.ToBytes(), peer); err != nil {
				s.logger.Error("failed to send DHCP response",
					slog.String("error", err.Error()))
				s.stats.IncError()
			}
		}

		// Update active leases count
		s.stats.SetActiveLeases(s.leases.CountActive())
	}
}

// recordMessageTypeStats records statistics for incoming message types.
func (s *CoreDHCPServer) recordMessageTypeStats(msgType dhcpv4.MessageType) {
	switch msgType {
	case dhcpv4.MessageTypeDiscover:
		s.stats.IncDiscover()
	case dhcpv4.MessageTypeRequest:
		s.stats.IncRequest()
	case dhcpv4.MessageTypeRelease:
		s.stats.IncRelease()
	case dhcpv4.MessageTypeDecline:
		s.stats.IncDecline()
	case dhcpv4.MessageTypeInform:
		s.stats.IncInform()
	}
}

// recordResponseStats records statistics for outgoing message types.
func (s *CoreDHCPServer) recordResponseStats(msgType dhcpv4.MessageType) {
	switch msgType {
	case dhcpv4.MessageTypeOffer:
		s.stats.IncOffer()
	case dhcpv4.MessageTypeAck:
		s.stats.IncAck()
	case dhcpv4.MessageTypeNak:
		s.stats.IncNak()
	}
}

// Running returns true if the server is running.
func (s *CoreDHCPServer) Running() bool {
	return s.running.Load()
}

// GetLease retrieves a lease by MAC address.
func (s *CoreDHCPServer) GetLease(mac net.HardwareAddr) (*Lease, bool) {
	if len(mac) == 0 {
		return nil, false
	}
	return s.leases.GetByMAC(mac)
}

// GetLeaseByIP retrieves a lease by IP address.
func (s *CoreDHCPServer) GetLeaseByIP(ip netip.Addr) (*Lease, bool) {
	if !ip.IsValid() {
		return nil, false
	}
	return s.leases.GetByIP(ip)
}

// ListLeases returns all active leases.
func (s *CoreDHCPServer) ListLeases() []*Lease {
	return s.leases.AllActive()
}

// ReleaseLease releases a lease by MAC address.
func (s *CoreDHCPServer) ReleaseLease(mac net.HardwareAddr) error {
	if len(mac) == 0 {
		return ErrInvalidMAC
	}

	// Get the lease to find the IP
	lease, ok := s.leases.GetByMAC(mac)
	if !ok {
		return ErrLeaseNotFound
	}

	// Release from IPAM
	ctx := context.Background()
	if err := s.allocator.Release(ctx, lease.IP); err != nil {
		s.logger.Warn("failed to release IP from IPAM",
			slog.String("mac", mac.String()),
			slog.String("ip", lease.IP.String()),
			slog.String("error", err.Error()))
	}

	// Update lease state and remove from store
	if err := s.leases.SetState(lease.IP, LeaseStateReleased); err != nil {
		s.logger.Warn("failed to update lease state",
			slog.String("mac", mac.String()),
			slog.String("error", err.Error()))
	}

	if err := s.leases.RemoveByMAC(mac); err != nil {
		return err
	}

	s.stats.DecActiveLeases()
	s.logger.Info("lease released",
		slog.String("mac", mac.String()),
		slog.String("ip", lease.IP.String()))

	return nil
}

// Stats returns server statistics.
func (s *CoreDHCPServer) Stats() ServerStats {
	return s.stats.Snapshot()
}

// GetLeaseStore returns the lease store for direct access.
func (s *CoreDHCPServer) GetLeaseStore() *LeaseStore {
	return s.leases
}

// GetConfig returns a copy of the server configuration.
func (s *CoreDHCPServer) GetConfig() *ServerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Clone()
}

// GetInterfacePlugin returns the IPAM plugin for a specific interface.
func (s *CoreDHCPServer) GetInterfacePlugin(interfaceName string) (*IPAMPlugin, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plugin, ok := s.plugins[interfaceName]
	return plugin, ok
}

// UpdateInterfaceOptions updates DHCP options for a specific interface.
func (s *CoreDHCPServer) UpdateInterfaceOptions(interfaceName string, opts DHCPOptions) error {
	s.mu.RLock()
	plugin, ok := s.plugins[interfaceName]
	s.mu.RUnlock()

	if !ok {
		return ErrInterfaceNotFound
	}

	return plugin.SetOptions(opts)
}

// ExpireLeases marks expired leases and returns the count.
func (s *CoreDHCPServer) ExpireLeases() int {
	count := s.leases.ExpireOld()
	s.stats.SetActiveLeases(s.leases.CountActive())
	return count
}

// Ensure CoreDHCPServer implements Server interface at compile time.
var _ Server = (*CoreDHCPServer)(nil)
