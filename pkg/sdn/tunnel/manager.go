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

package tunnel

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"syscall"

	vnl "github.com/vishvananda/netlink"
)

// managedTunnel tracks a tunnel and its config.
type managedTunnel struct {
	config TunnelConfig
}

// Manager creates, updates, and removes GRE/IPIP tunnels via Linux netlink.
// All operations are idempotent and safe for concurrent use.
type Manager struct {
	tunnels map[string]*managedTunnel
	mu      sync.RWMutex
	logger  *slog.Logger
	nl      netlinkOps
}

// NewManager creates a new tunnel manager.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		tunnels: make(map[string]*managedTunnel),
		logger:  logger,
		nl:      &realNetlinkOps{},
	}
}

// newManagerWithOps creates a manager with a custom netlinkOps (for testing).
func newManagerWithOps(logger *slog.Logger, nl netlinkOps) *Manager {
	return &Manager{
		tunnels: make(map[string]*managedTunnel),
		logger:  logger,
		nl:      nl,
	}
}

// EnsureTunnel creates a GRE/IPIP tunnel if it does not exist, or recreates it
// if the configuration has changed. The operation is idempotent.
func (m *Manager) EnsureTunnel(ctx context.Context, config TunnelConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already managed with identical config
	if existing, ok := m.tunnels[config.Name]; ok {
		if tunnelConfigEqual(existing.config, config) {
			m.logger.Debug("tunnel already exists with identical config",
				slog.String("name", config.Name))
			return nil
		}
		// Config changed: remove old tunnel and recreate
		m.logger.Info("tunnel config changed, recreating",
			slog.String("name", config.Name))
		if err := m.removeTunnelLocked(ctx, config.Name); err != nil {
			return err
		}
	}

	// Check if the interface already exists in the kernel (not managed by us)
	if _, err := m.nl.LinkByName(config.Name); err == nil {
		// Link exists but not managed: delete it first for idempotency
		m.logger.Info("removing unmanaged tunnel before creation",
			slog.String("name", config.Name))
		dummy := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: config.Name}}
		if delErr := m.nl.LinkDel(dummy); delErr != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: delErr}
		}
	}

	if err := m.createTunnel(config); err != nil {
		return err
	}

	m.tunnels[config.Name] = &managedTunnel{config: config}

	m.logger.Info("tunnel created",
		slog.String("name", config.Name),
		slog.String("type", config.Type),
		slog.String("local", config.Local),
		slog.String("remote", config.Remote),
		slog.String("tunnel_ip", config.TunnelIP),
		slog.Int("mtu", config.effectiveMTU()),
	)

	return nil
}

// RemoveTunnel removes a managed tunnel by name. Returns ErrTunnelNotFound if
// the tunnel is not managed by this manager.
func (m *Manager) RemoveTunnel(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.removeTunnelLocked(ctx, name)
}

// Status returns the current status of a managed tunnel.
func (m *Manager) Status(ctx context.Context, name string) (*TunnelStatus, error) {
	m.mu.RLock()
	managed, ok := m.tunnels[name]
	m.mu.RUnlock()

	if !ok {
		return nil, &ErrTunnelNotFound{Name: name}
	}

	link, err := m.nl.LinkByName(name)
	if err != nil {
		return nil, &ErrTunnelStatusFailed{Name: name, Cause: err}
	}

	attrs := link.Attrs()
	state := linkOperState(attrs)

	status := &TunnelStatus{
		Name:     name,
		State:    state,
		LocalIP:  managed.config.Local,
		RemoteIP: managed.config.Remote,
		TunnelIP: managed.config.TunnelIP,
	}

	// Read stats if available
	if attrs.Statistics != nil {
		status.RxBytes = attrs.Statistics.RxBytes
		status.TxBytes = attrs.Statistics.TxBytes
		status.RxPackets = attrs.Statistics.RxPackets
		status.TxPackets = attrs.Statistics.TxPackets
	}

	return status, nil
}

// linkOperState determines the tunnel state from link attributes.
// OperState from the kernel takes priority; if it is unknown/unset, fall back
// to the administrative IFF_UP flag.
func linkOperState(attrs *vnl.LinkAttrs) TunnelState {
	switch attrs.OperState {
	case vnl.OperUp:
		return TunnelStateUp
	case vnl.OperDown:
		return TunnelStateDown
	default:
		// OperState not set or unknown: fall back to admin flag
		if attrs.Flags&net.FlagUp != 0 {
			return TunnelStateUp
		}
		return TunnelStateUnknown
	}
}

// ListTunnels returns the status of all managed tunnels.
func (m *Manager) ListTunnels(ctx context.Context) ([]*TunnelStatus, error) {
	m.mu.RLock()
	names := make([]string, 0, len(m.tunnels))
	for name := range m.tunnels {
		names = append(names, name)
	}
	m.mu.RUnlock()

	result := make([]*TunnelStatus, 0, len(names))
	for _, name := range names {
		status, err := m.Status(ctx, name)
		if err != nil {
			m.logger.Warn("failed to get tunnel status",
				slog.String("name", name),
				slog.Any("error", err))
			continue
		}
		result = append(result, status)
	}

	return result, nil
}

// Close removes all managed tunnels.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx := context.Background()
	var lastErr error
	for name := range m.tunnels {
		if err := m.removeTunnelLocked(ctx, name); err != nil {
			m.logger.Error("failed to remove tunnel during close",
				slog.String("name", name),
				slog.Any("error", err))
			lastErr = err
		}
	}

	return lastErr
}

// createTunnel performs the actual netlink operations to create the tunnel.
func (m *Manager) createTunnel(config TunnelConfig) error {
	localIP := net.ParseIP(config.Local)
	remoteIP := net.ParseIP(config.Remote)

	link, err := m.buildLink(config, localIP, remoteIP)
	if err != nil {
		return err
	}

	// Create the link
	if err := m.nl.LinkAdd(link); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}

	// Retrieve the created link for subsequent operations
	createdLink, err := m.nl.LinkByName(config.Name)
	if err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}

	// Set MTU
	if err := m.nl.LinkSetMTU(createdLink, config.effectiveMTU()); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}

	// Add IPv4 tunnel address
	if err := m.addAddress(createdLink, config.TunnelIP); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}

	// Add IPv6 tunnel address if configured
	if config.TunnelIPv6 != "" {
		if err := m.addAddress(createdLink, config.TunnelIPv6); err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
	}

	// Bring the link up
	if err := m.nl.LinkSetUp(createdLink); err != nil {
		return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
	}

	return nil
}

// buildLink constructs the appropriate netlink link type for the tunnel.
func (m *Manager) buildLink(config TunnelConfig, localIP, remoteIP net.IP) (vnl.Link, error) {
	attrs := vnl.LinkAttrs{
		Name: config.Name,
		MTU:  config.effectiveMTU(),
	}

	switch config.Type {
	case TunnelTypeGRE:
		gre := &vnl.Gretun{
			LinkAttrs: attrs,
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       uint8(config.effectiveTTL()),
		}
		if config.Key > 0 {
			gre.IKey = config.Key
			gre.OKey = config.Key
		}
		return gre, nil

	case TunnelTypeGRE6:
		gre6 := &vnl.Ip6tnl{
			LinkAttrs: attrs,
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       uint8(config.effectiveTTL()),
			Proto:     syscall.IPPROTO_GRE,
		}
		return gre6, nil

	case TunnelTypeIPIP:
		ipip := &vnl.Iptun{
			LinkAttrs: attrs,
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       uint8(config.effectiveTTL()),
		}
		return ipip, nil

	default:
		return nil, &ErrInvalidTunnelConfig{Name: config.Name, Reason: "unsupported tunnel type"}
	}
}

// addAddress parses a CIDR string and adds the address to the link.
func (m *Manager) addAddress(link vnl.Link, cidr string) error {
	addr, err := vnl.ParseAddr(cidr)
	if err != nil {
		return err
	}
	return m.nl.AddrAdd(link, addr)
}

// removeTunnelLocked removes a tunnel. Caller must hold m.mu.
func (m *Manager) removeTunnelLocked(_ context.Context, name string) error {
	if _, ok := m.tunnels[name]; !ok {
		return &ErrTunnelNotFound{Name: name}
	}

	link, err := m.nl.LinkByName(name)
	if err != nil {
		// Already gone from kernel, just remove tracking
		delete(m.tunnels, name)
		return nil
	}

	if err := m.nl.LinkDel(link); err != nil {
		return &ErrTunnelRemoveFailed{Name: name, Cause: err}
	}

	delete(m.tunnels, name)

	m.logger.Info("tunnel removed",
		slog.String("name", name))

	return nil
}

// tunnelConfigEqual returns true if two tunnel configs are functionally identical.
func tunnelConfigEqual(a, b TunnelConfig) bool {
	return a.Name == b.Name &&
		a.Type == b.Type &&
		a.Local == b.Local &&
		a.Remote == b.Remote &&
		a.TunnelIP == b.TunnelIP &&
		a.TunnelIPv6 == b.TunnelIPv6 &&
		a.effectiveMTU() == b.effectiveMTU() &&
		a.effectiveTTL() == b.effectiveTTL() &&
		a.Key == b.Key
}
