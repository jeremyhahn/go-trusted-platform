//go:build !fips

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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"

	vnl "github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardHubConfig describes a hub interface: one server key and listen
// port, many roaming peers each programmed with the addresses it may use.
// The remote-access VPN's WireGuard data plane is a hub; site-to-site
// tunnels (TunnelConfig) are point-to-point and stay with the Manager.
type WireGuardHubConfig struct {
	// Name is the interface name (at most 15 characters).
	Name string
	// KeyRef is the reference the KeyProvider resolves to the 32-byte
	// private key; the configuration never carries the key itself.
	KeyRef string
	// ListenPort is the UDP port the hub listens on.
	ListenPort int
	// Addresses are the hub's own addresses on the interface — the gateway
	// address of the remote-access pool.
	Addresses []netip.Prefix
	// MTU is the link MTU; zero selects the WireGuard default.
	MTU int
}

func (c WireGuardHubConfig) effectiveMTU() int {
	if c.MTU <= 0 {
		return DefaultMTU
	}
	return c.MTU
}

func (c WireGuardHubConfig) validate() error {
	if c.Name == "" || len(c.Name) > maxInterfaceNameLen {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "device name must be 1-15 characters"}
	}
	if c.KeyRef == "" {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "key-ref is required"}
	}
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "listen-port must be 1-65535"}
	}
	if len(c.Addresses) == 0 {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "at least one address is required"}
	}
	for _, p := range c.Addresses {
		if !p.IsValid() {
			return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "address prefix is not valid"}
		}
	}
	if c.MTU != 0 && (c.MTU < MinMTU || c.MTU > MaxMTU) {
		return &ErrInvalidTunnelConfig{Name: c.Name, Reason: "MTU out of range"}
	}
	return nil
}

// WireGuardHub is a kernel WireGuard interface whose peers come and go at
// runtime. Up keys the device through the control socket and never writes
// the private key anywhere else; SetPeer and RemovePeer program one peer at
// a time without touching the others.
type WireGuardHub struct {
	cfg    WireGuardHubConfig
	logger *slog.Logger
	keys   KeyProvider
	nl     netlinkOps
	wg     wgOps

	mu        sync.Mutex
	up        bool
	link      vnl.Link
	publicKey wgtypes.Key
}

// NewWireGuardHub builds a hub over the real netlink and WireGuard control
// sockets. The device is created by Up.
func NewWireGuardHub(logger *slog.Logger, cfg WireGuardHubConfig, keys KeyProvider) (*WireGuardHub, error) {
	return newWireGuardHubWithOps(logger, cfg, keys, &realNetlinkOps{}, nil)
}

func newWireGuardHubWithOps(logger *slog.Logger, cfg WireGuardHubConfig, keys KeyProvider, nl netlinkOps, wg wgOps) (*WireGuardHub, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, &ErrKeyProviderRequired{Name: cfg.Name, Transport: TransportWireGuard}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WireGuardHub{cfg: cfg, logger: logger, keys: keys, nl: nl, wg: wg}, nil
}

// Up creates the interface, keys it, addresses it and brings it up. The
// private key is resolved through the KeyProvider, handed to the kernel and
// zeroized; only the derived public key is kept.
func (h *WireGuardHub) Up(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.up {
		return nil
	}
	// A predecessor that exited without Down leaves its device, and every
	// peer on it, in the kernel. Remove it before the key is resolved, so
	// a key-store failure cannot leave those peers accepting traffic.
	if err := h.removeStale(); err != nil {
		return &ErrTunnelCreateFailed{Name: h.cfg.Name, Cause: err}
	}
	key, err := fetchKey(ctx, h.keys, h.cfg.Name, h.cfg.KeyRef, wireGuardKeyLen)
	if err != nil {
		return err
	}
	defer zeroize(key)
	priv, err := wgtypes.NewKey(key)
	if err != nil {
		return &ErrKeyMaterial{Name: h.cfg.Name, KeyRef: h.cfg.KeyRef, Reason: "not a WireGuard private key", Cause: err}
	}
	if h.wg == nil {
		ops, err := newRealWGOps()
		if err != nil {
			return &ErrTunnelCreateFailed{Name: h.cfg.Name, Cause: err}
		}
		h.wg = ops
	}
	link := &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: h.cfg.Name, MTU: h.cfg.effectiveMTU()}}
	if err := h.addLink(link); err != nil {
		return &ErrTunnelCreateFailed{Name: h.cfg.Name, Cause: err}
	}
	created, err := h.nl.LinkByName(h.cfg.Name)
	if err != nil {
		_ = h.nl.LinkDel(link)
		return &ErrTunnelCreateFailed{Name: h.cfg.Name, Cause: err}
	}
	if err := h.configure(created, priv); err != nil {
		_ = h.nl.LinkDel(created)
		return &ErrTunnelCreateFailed{Name: h.cfg.Name, Cause: err}
	}
	h.link = created
	h.publicKey = priv.PublicKey()
	h.up = true
	h.logger.Info("wireguard hub up", slog.String("device", h.cfg.Name), slog.Int("listen_port", h.cfg.ListenPort))
	return nil
}

// addLink creates the hub's device. A WireGuard device of the hub's name
// that already exists is a predecessor's, left by an ungraceful stop
// (the launcher SIGKILLs a child when the supervisor dies) with its
// addresses and peers still installed: it is deleted and created afresh,
// so none of that state survives. A device of the name that is not a
// WireGuard device is not the hub's, and is refused.
// removeStale deletes a WireGuard device of the hub's name left by a
// predecessor. A device of another type is not the hub's and is left for
// addLink to refuse; a failed lookup means there is nothing to remove.
func (h *WireGuardHub) removeStale() error {
	return removeStaleWireGuardHub(h.logger, h.nl, h.cfg.Name)
}

// RemoveStaleWireGuardHub deletes a WireGuard device named name that a
// predecessor left in the kernel, with every peer on it. A datapath that
// restarts with no hub to bring up calls it, since no hub's Up will. A
// device of another type is not a hub's and is left in place; no device is
// not an error.
func RemoveStaleWireGuardHub(logger *slog.Logger, name string) error {
	return removeStaleWireGuardHub(logger, &realNetlinkOps{}, name)
}

func removeStaleWireGuardHub(logger *slog.Logger, nl netlinkOps, name string) error {
	stale, err := nl.LinkByName(name)
	if err != nil {
		// Only the typed not-found result proves the device absent; any other
		// lookup failure leaves a predecessor's hub possibly live.
		var missing vnl.LinkNotFoundError
		if errors.As(err, &missing) {
			return nil
		}
		return &ErrTunnelRemoveFailed{Name: name, Cause: fmt.Errorf("looking up a stale hub device: %w", err)}
	}
	if stale == nil || stale.Type() != (&vnl.Wireguard{}).Type() {
		return nil
	}
	if err := nl.LinkDel(stale); err != nil {
		return &ErrTunnelRemoveFailed{Name: name, Cause: fmt.Errorf("removing the stale hub device: %w", err)}
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("wireguard hub removed a stale device of its name", slog.String("device", name))
	return nil
}

func (h *WireGuardHub) addLink(link vnl.Link) error {
	err := h.nl.LinkAdd(link)
	if !errors.Is(err, syscall.EEXIST) {
		return err
	}
	stale, lerr := h.nl.LinkByName(h.cfg.Name)
	if lerr != nil {
		return errors.Join(err, lerr)
	}
	if stale.Type() != link.Type() {
		return fmt.Errorf("%w: the device is a %q device, not the hub's %q", err, stale.Type(), link.Type())
	}
	if err := h.nl.LinkDel(stale); err != nil {
		return fmt.Errorf("removing the stale hub device: %w", err)
	}
	h.logger.Warn("wireguard hub replaced a stale device of its name", slog.String("device", h.cfg.Name))
	return h.nl.LinkAdd(link)
}

func (h *WireGuardHub) configure(link vnl.Link, priv wgtypes.Key) error {
	listen := h.cfg.ListenPort
	devCfg := wgtypes.Config{PrivateKey: &priv, ListenPort: &listen, ReplacePeers: true}
	if err := h.wg.ConfigureDevice(h.cfg.Name, devCfg); err != nil {
		return err
	}
	if err := h.nl.LinkSetMTU(link, h.cfg.effectiveMTU()); err != nil {
		return err
	}
	for _, p := range h.cfg.Addresses {
		if err := h.nl.AddrAdd(link, &vnl.Addr{IPNet: prefixToIPNet(p)}); err != nil {
			return err
		}
	}
	return h.nl.LinkSetUp(link)
}

// PublicKey returns the hub's public key once Up has keyed the device, so an
// admission response can hand it to the client. Before Up it is nil.
func (h *WireGuardHub) PublicKey() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.up {
		return nil
	}
	out := make([]byte, len(h.publicKey))
	copy(out, h.publicKey[:])
	return out
}

// ListenPort returns the hub's UDP port, for the endpoint an admission
// response advertises.
func (h *WireGuardHub) ListenPort() int { return h.cfg.ListenPort }

// SetPeer adds or replaces one peer: the addresses it may source packets
// from are exactly allowed. Other peers are untouched.
func (h *WireGuardHub) SetPeer(_ context.Context, publicKey []byte, allowed []netip.Prefix) error {
	pub, err := h.peerKey(publicKey)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return &ErrPeerInvalid{Name: h.cfg.Name, Reason: "at least one allowed prefix is required"}
	}
	allowedIPs := make([]net.IPNet, 0, len(allowed))
	for _, p := range allowed {
		if !p.IsValid() {
			return &ErrPeerInvalid{Name: h.cfg.Name, Reason: "allowed prefix is not valid"}
		}
		allowedIPs = append(allowedIPs, *prefixToIPNet(p.Masked()))
	}
	peer := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true, AllowedIPs: allowedIPs}
	return h.applyPeer(peer)
}

// RemovePeer removes one peer. Removing a peer the kernel does not have is
// not an error: the end state is what was asked for.
func (h *WireGuardHub) RemovePeer(_ context.Context, publicKey []byte) error {
	pub, err := h.peerKey(publicKey)
	if err != nil {
		return err
	}
	return h.applyPeer(wgtypes.PeerConfig{PublicKey: pub, Remove: true})
}

func (h *WireGuardHub) peerKey(publicKey []byte) (wgtypes.Key, error) {
	if len(publicKey) != wireGuardKeyLen {
		return wgtypes.Key{}, &ErrPeerInvalid{Name: h.cfg.Name, Reason: "public key must be exactly " + itoa(wireGuardKeyLen) + " bytes"}
	}
	pub, err := wgtypes.NewKey(publicKey)
	if err != nil {
		return wgtypes.Key{}, &ErrPeerInvalid{Name: h.cfg.Name, Reason: "public key is not a WireGuard key"}
	}
	return pub, nil
}

func (h *WireGuardHub) applyPeer(peer wgtypes.PeerConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.up {
		return &ErrDeviceNotUp{Name: h.cfg.Name}
	}
	if err := h.wg.ConfigureDevice(h.cfg.Name, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}}); err != nil {
		return &ErrPeerConfigureFailed{Name: h.cfg.Name, Cause: err}
	}
	return nil
}

// Down removes the interface and closes the control socket. It is
// idempotent.
func (h *WireGuardHub) Down() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.up {
		return nil
	}
	h.up = false
	h.publicKey = wgtypes.Key{}
	err := h.nl.LinkDel(h.link)
	if h.wg != nil {
		if cerr := h.wg.Close(); cerr != nil && err == nil {
			err = cerr
		}
		h.wg = nil
	}
	if err != nil {
		return &ErrTunnelRemoveFailed{Name: h.cfg.Name, Cause: err}
	}
	h.logger.Info("wireguard hub down", slog.String("device", h.cfg.Name))
	return nil
}
