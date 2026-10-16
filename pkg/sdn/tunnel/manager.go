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
	"time"

	vnl "github.com/vishvananda/netlink"
)

// managedTunnel tracks a tunnel and its config.
type managedTunnel struct {
	config    TunnelConfig
	bound     bool      // outer endpoints pinned to an uplink table
	lastRekey time.Time // when Rekey last succeeded; zero until then
}

// Manager creates, updates, and removes tunnels via Linux netlink under a
// pluggable transport: plain GRE/GRE6/IPIP, the same carrier protected by
// ESP through XFRM (ipsec), or a kernel WireGuard interface (non-FIPS builds).
// All operations are idempotent and safe for concurrent use.
type Manager struct {
	tunnels map[string]*managedTunnel
	mu      sync.RWMutex
	logger  *slog.Logger
	nl      netlinkOps
	keys    KeyProvider
	uplinks *UplinkManager
	wg      wgOps
	clock   func() time.Time
}

// Option configures a Manager.
type Option func(*Manager)

// WithKeyProvider supplies the key store the ipsec and wireguard transports
// resolve their key references through. Without it those transports are
// refused with ErrKeyProviderRequired.
func WithKeyProvider(p KeyProvider) Option {
	return func(m *Manager) { m.keys = p }
}

// WithUplinks supplies the UplinkManager tunnels are pinned to when their
// configuration names an uplink. Without it a tunnel naming an uplink is
// refused with ErrUplinkUnknown.
func WithUplinks(u *UplinkManager) Option {
	return func(m *Manager) { m.uplinks = u }
}

// NewManager creates a new tunnel manager over the real netlink.
func NewManager(logger *slog.Logger, opts ...Option) *Manager {
	return newManagerWithOps(logger, &realNetlinkOps{}, opts...)
}

// newManagerWithOps creates a manager with a custom netlinkOps (for testing).
func newManagerWithOps(logger *slog.Logger, nl netlinkOps, opts ...Option) *Manager {
	m := &Manager{
		tunnels: make(map[string]*managedTunnel),
		logger:  logger,
		nl:      nl,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// EnsureTunnel creates a tunnel if it does not exist, or recreates it if
// the configuration has changed. The operation is idempotent. Every
// prerequisite the transport needs — a key provider, a known uplink — is
// checked before anything is programmed.
func (m *Manager) EnsureTunnel(ctx context.Context, config TunnelConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := m.checkPrerequisites(config); err != nil {
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

	// A link the manager does not track yet is either this tunnel, left in
	// place by a datapath that was killed, or something else holding the
	// name. The first is adopted, so a relaunch does not drop the traffic it
	// carries; anything else is deleted and recreated.
	adopted := false
	if link, err := m.nl.LinkByName(config.Name); err == nil {
		adopted, err = m.adoptable(link, config)
		if err != nil {
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
		if !adopted {
			m.logger.Info("removing unmanaged tunnel before creation",
				slog.String("name", config.Name))
			dummy := &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: config.Name}}
			if delErr := m.nl.LinkDel(dummy); delErr != nil {
				return &ErrTunnelCreateFailed{Name: config.Name, Cause: delErr}
			}
		}
	}

	if !adopted {
		if err := m.createTransport(ctx, config); err != nil {
			return err
		}
	}

	managed := &managedTunnel{config: config}
	if config.Uplink != "" {
		if err := m.uplinks.BindTunnel(ctx, config.Uplink, config.Name, config.Local, config.Remote); err != nil {
			m.teardownTransport(config)
			return &ErrTunnelCreateFailed{Name: config.Name, Cause: err}
		}
		managed.bound = true
	}
	m.tunnels[config.Name] = managed

	m.logger.Info("tunnel created",
		slog.String("name", config.Name),
		slog.Bool("adopted", adopted),
		slog.String("transport", config.effectiveTransport()),
		slog.String("type", config.Type),
		slog.String("uplink", config.Uplink),
		slog.String("local", config.Local),
		slog.String("remote", config.Remote),
		slog.String("tunnel_ip", config.TunnelIP),
		slog.Int("mtu", config.effectiveMTU()),
	)

	return nil
}

// checkPrerequisites refuses a configuration this manager cannot honour
// before any netlink call is made.
func (m *Manager) checkPrerequisites(config TunnelConfig) error {
	switch config.effectiveTransport() {
	case TransportIPsec, TransportWireGuard:
		if m.keys == nil {
			return &ErrKeyProviderRequired{Name: config.Name, Transport: config.effectiveTransport()}
		}
	}
	if config.Uplink != "" {
		if m.uplinks == nil || !m.uplinks.Has(config.Uplink) {
			return &ErrUplinkUnknown{Name: config.Name, Uplink: config.Uplink}
		}
	}
	return nil
}

// createTransport programs the carrier and its protection for config.
func (m *Manager) createTransport(ctx context.Context, config TunnelConfig) error {
	switch config.effectiveTransport() {
	case TransportGRE:
		return m.createTunnel(config)
	case TransportIPsec:
		// Protection first: the carrier must never carry a packet in the
		// clear, so the policies exist before the interface comes up.
		if err := m.installIPsec(ctx, config); err != nil {
			return err
		}
		if err := m.createTunnel(config); err != nil {
			_ = m.removeIPsec(config)
			return err
		}
		return nil
	case TransportWireGuard:
		return m.createWireGuard(ctx, config)
	default:
		return &ErrInvalidTunnelConfig{Name: config.Name, Reason: "unsupported transport"}
	}
}

// teardownTransport undoes createTransport after a later step failed.
func (m *Manager) teardownTransport(config TunnelConfig) {
	if link, err := m.nl.LinkByName(config.Name); err == nil {
		_ = m.nl.LinkDel(link)
	}
	if config.effectiveTransport() == TransportIPsec {
		_ = m.removeIPsec(config)
	}
}

// Rekey rotates the key material of an ipsec or wireguard tunnel in place
// by re-resolving its key references. The reconcile loop drives it on the
// tunnel's rekey interval; the peer rotates the same references in lockstep.
func (m *Manager) Rekey(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	managed, ok := m.tunnels[name]
	if !ok {
		return &ErrTunnelNotFound{Name: name}
	}
	var err error
	switch managed.config.effectiveTransport() {
	case TransportIPsec:
		err = m.rekeyIPsec(ctx, managed.config)
	case TransportWireGuard:
		err = m.rekeyWireGuard(ctx, managed.config)
	default:
		return &ErrRekeyUnsupported{Name: name, Transport: managed.config.effectiveTransport()}
	}
	if err != nil {
		return err
	}
	managed.lastRekey = m.now()
	return nil
}

// now returns the current time; tests substitute a fixed clock.
func (m *Manager) now() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
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
	entry, ok := m.tunnels[name]
	var managed managedTunnel
	if ok {
		managed = *entry
	}
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
		Name:          name,
		State:         state,
		LocalIP:       managed.config.Local,
		RemoteIP:      managed.config.Remote,
		TunnelIP:      managed.config.TunnelIP,
		Transport:     managed.config.effectiveTransport(),
		Uplink:        managed.config.Uplink,
		Bound:         managed.bound,
		RekeyInterval: managed.config.rekeyInterval(),
		LastRekey:     managed.lastRekey,
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

// Uplinks reports the policy-routing state of every uplink this manager
// pins tunnels to. It is empty when the manager was built without an
// UplinkManager, which is what a deployment that routes every tunnel
// through the main table looks like.
func (m *Manager) Uplinks() []UplinkStatus {
	if m.uplinks == nil {
		return nil
	}
	return m.uplinks.List()
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
	if m.wg != nil {
		if err := m.wg.Close(); err != nil && lastErr == nil {
			lastErr = err
		}
		m.wg = nil
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

// adoptable reports whether a link already in the kernel is exactly the
// tunnel config describes: same kind, endpoints, key, TTL and MTU, up, and
// carrying exactly the configured tunnel addresses. Only the plain GRE
// transport is adopted. An IPsec or WireGuard tunnel's keys live in kernel
// state the manager would have to read back to trust, so those links are
// recreated, as is anything that differs in a single field.
func (m *Manager) adoptable(link vnl.Link, config TunnelConfig) (bool, error) {
	if config.effectiveTransport() != TransportGRE || !linkMatches(link, config) {
		return false, nil
	}
	addrs, err := m.nl.AddrList(link, vnl.FAMILY_ALL)
	if err != nil {
		return false, err
	}
	want := []string{config.TunnelIP}
	if config.TunnelIPv6 != "" {
		want = append(want, config.TunnelIPv6)
	}
	return sameAddresses(addrs, want), nil
}

// linkMatches compares the link's kind and attributes with the link
// buildLink would create for config.
func linkMatches(link vnl.Link, config TunnelConfig) bool {
	attrs := link.Attrs()
	if attrs.MTU != config.effectiveMTU() || attrs.Flags&net.FlagUp == 0 {
		return false
	}
	local, remote := net.ParseIP(config.Local), net.ParseIP(config.Remote)
	ttl := uint8(config.effectiveTTL())
	switch tunnel := link.(type) {
	case *vnl.Gretun:
		return config.Type == TunnelTypeGRE && tunnel.Local.Equal(local) && tunnel.Remote.Equal(remote) &&
			tunnel.Ttl == ttl && tunnel.IKey == config.Key && tunnel.OKey == config.Key
	case *vnl.Ip6tnl:
		return config.Type == TunnelTypeGRE6 && tunnel.Local.Equal(local) && tunnel.Remote.Equal(remote) &&
			tunnel.Ttl == ttl && tunnel.Proto == syscall.IPPROTO_GRE
	case *vnl.Iptun:
		return config.Type == TunnelTypeIPIP && tunnel.Local.Equal(local) && tunnel.Remote.Equal(remote) &&
			tunnel.Ttl == ttl
	default:
		return false
	}
}

// sameAddresses reports whether the link's addresses, link-local ones
// aside (the kernel assigns those itself), are exactly want.
func sameAddresses(addrs []vnl.Addr, want []string) bool {
	have := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			continue
		}
		have[addr.IPNet.String()] = true
	}
	if len(have) != len(want) {
		return false
	}
	for _, cidr := range want {
		parsed, err := vnl.ParseAddr(cidr)
		if err != nil || !have[parsed.IPNet.String()] {
			return false
		}
	}
	return true
}

// removeTunnelLocked removes a tunnel: the uplink pin, the interface, then
// (for ipsec) the XFRM policies and SAs. Caller must hold m.mu.
func (m *Manager) removeTunnelLocked(ctx context.Context, name string) error {
	managed, ok := m.tunnels[name]
	if !ok {
		return &ErrTunnelNotFound{Name: name}
	}

	if managed.bound && m.uplinks != nil {
		if err := m.uplinks.UnbindTunnel(ctx, managed.config.Uplink, name); err != nil {
			return &ErrTunnelRemoveFailed{Name: name, Cause: err}
		}
		managed.bound = false
	}

	if link, err := m.nl.LinkByName(name); err == nil {
		if err := m.nl.LinkDel(link); err != nil {
			return &ErrTunnelRemoveFailed{Name: name, Cause: err}
		}
	}

	if managed.config.effectiveTransport() == TransportIPsec {
		if err := m.removeIPsec(managed.config); err != nil {
			return err
		}
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
		a.effectiveTransport() == b.effectiveTransport() &&
		a.Uplink == b.Uplink &&
		ipsecEqual(a.IPsec, b.IPsec) &&
		wireGuardEqual(a.WireGuard, b.WireGuard) &&
		a.Local == b.Local &&
		a.Remote == b.Remote &&
		a.TunnelIP == b.TunnelIP &&
		a.TunnelIPv6 == b.TunnelIPv6 &&
		a.effectiveMTU() == b.effectiveMTU() &&
		a.effectiveTTL() == b.effectiveTTL() &&
		a.Key == b.Key
}

func ipsecEqual(a, b *IPsecConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.KeyRef == b.KeyRef && a.effectivePeerKeyRef() == b.effectivePeerKeyRef() &&
		a.SPIOut == b.SPIOut && a.SPIIn == b.SPIIn &&
		a.effectiveReplayWindow() == b.effectiveReplayWindow() &&
		a.EffectiveRekeyInterval() == b.EffectiveRekeyInterval()
}

func wireGuardEqual(a, b *WireGuardConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.KeyRef == b.KeyRef && a.PeerPublicKey == b.PeerPublicKey &&
		a.ListenPort == b.ListenPort && a.RemotePort == b.RemotePort &&
		a.effectiveKeepalive() == b.effectiveKeepalive()
}
