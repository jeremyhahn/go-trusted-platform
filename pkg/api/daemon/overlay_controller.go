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
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// ErrVTEPNotOnFabric is returned when the overlay IPsec local address is not
// configured on the fabric interface, so VXLAN could not be sourced from it.
var ErrVTEPNotOnFabric = errors.New("overlay.ipsec.local-address is not an address of overlay.ipsec.fabric-interface")

// ErrUnderlayNotFabric is returned when overlay.underlay-interface names an
// interface other than the IPsec fabric interface.
var ErrUnderlayNotFabric = errors.New("overlay.underlay-interface is not overlay.ipsec.fabric-interface")

// OverlayVTEPError refuses an overlay VTEP the IPsec fail-closed floor would
// not protect: the VTEP address and the interface it was checked against.
type OverlayVTEPError struct {
	Address   netip.Addr
	Interface string
	Err       error
}

func (e *OverlayVTEPError) Error() string {
	return "daemon: overlay VTEP " + e.Address.String() + " on " + e.Interface + ": " + e.Err.Error()
}

func (e *OverlayVTEPError) Unwrap() error {
	return e.Err
}

// The overlay keys an OverlayVTEPSettingError names.
const (
	overlayVTEPAddressKey       = "sdn.overlay.vtep-address"
	overlayUnderlayInterfaceKey = "sdn.overlay.underlay-interface"
)

// OverlayVTEPSettingError refuses an overlay VTEP (without IPsec) that the
// configuration does not determine: Setting is the key to set, and Value the
// configured value when one was given but is not a usable unicast address.
type OverlayVTEPSettingError struct {
	Setting string
	Value   string
}

func (e *OverlayVTEPSettingError) Error() string {
	if e.Value != "" {
		return "daemon: overlay VTEP: " + e.Setting + " " + strconv.Quote(e.Value) + " is not a unicast IP address"
	}
	return "daemon: overlay VTEP undetermined: set " + e.Setting
}

// overlayVTEP is the local VTEP: the address the overlay controller
// registers and sources VXLAN from, and the underlay interface it leaves by.
type overlayVTEP struct {
	addr  netip.Addr
	iface string
}

// interfaceAddrsFunc lists the addresses configured on a named interface.
type interfaceAddrsFunc func(name string) ([]netip.Addr, error)

// resolveOverlayVTEP is the one place that decides the local VTEP.
//
// With overlay.ipsec enabled the VTEP is the IPsec local endpoint
// (overlay.ipsec.local-address) on the fabric interface: the SAs and the
// fail-closed floor cover only that address on that interface, so VXLAN
// sourced anywhere else would be dropped. overlay.underlay-interface may be
// unset or name the fabric interface; the local address must be one of the
// fabric interface's addresses. Anything else is an *OverlayVTEPError.
//
// Without IPsec the VTEP address is overlay.vtep-address, else the node's
// detected publicIPv4, on overlay.underlay-interface; the interfaces are not
// read. Nothing is guessed: no address or no interface is an
// *OverlayVTEPSettingError naming the key to set. A loopback VTEP (single
// node, tests) is an explicit vtep-address: 127.0.0.1 on underlay-interface: lo.
func resolveOverlayVTEP(publicIPv4 net.IP, cfg *sdn.OverlayConfig, addrsOf interfaceAddrsFunc) (overlayVTEP, error) {
	if cfg.IPsec != nil && cfg.IPsec.Enabled {
		return ipsecVTEP(cfg, addrsOf)
	}
	addr, err := plainVTEPAddress(publicIPv4, cfg.VTEPAddress)
	if err != nil {
		return overlayVTEP{}, err
	}
	if cfg.UnderlayInterface == "" {
		return overlayVTEP{}, &OverlayVTEPSettingError{Setting: overlayUnderlayInterfaceKey}
	}
	return overlayVTEP{addr: addr, iface: cfg.UnderlayInterface}, nil
}

// plainVTEPAddress is the VTEP address of an overlay without IPsec: the
// configured vtep-address when set, otherwise the detected public address.
func plainVTEPAddress(publicIPv4 net.IP, configured string) (netip.Addr, error) {
	if configured != "" {
		addr, err := netip.ParseAddr(configured)
		if err != nil || addr.Unmap().IsUnspecified() || addr.Unmap().IsMulticast() {
			return netip.Addr{}, &OverlayVTEPSettingError{Setting: overlayVTEPAddressKey, Value: configured}
		}
		return addr.Unmap(), nil
	}
	if addr, ok := netip.AddrFromSlice(publicIPv4); ok && !addr.Unmap().IsUnspecified() {
		return addr.Unmap(), nil
	}
	return netip.Addr{}, &OverlayVTEPSettingError{Setting: overlayVTEPAddressKey}
}

// ipsecVTEP is the IPsec local endpoint on the fabric interface, refused
// when the two do not agree (see resolveOverlayVTEP).
func ipsecVTEP(cfg *sdn.OverlayConfig, addrsOf interfaceAddrsFunc) (overlayVTEP, error) {
	local, err := cfg.IPsec.Local()
	if err != nil {
		return overlayVTEP{}, err
	}
	fabric := cfg.IPsec.FabricInterface
	if cfg.UnderlayInterface != "" && cfg.UnderlayInterface != fabric {
		return overlayVTEP{}, &OverlayVTEPError{Address: local, Interface: cfg.UnderlayInterface, Err: ErrUnderlayNotFabric}
	}
	addrs, err := addrsOf(fabric)
	if err != nil {
		return overlayVTEP{}, &OverlayVTEPError{Address: local, Interface: fabric, Err: err}
	}
	if !slices.Contains(addrs, local) {
		return overlayVTEP{}, &OverlayVTEPError{Address: local, Interface: fabric, Err: ErrVTEPNotOnFabric}
	}
	return overlayVTEP{addr: local, iface: fabric}, nil
}

// interfaceAddrs lists the IP addresses of the named host interface,
// IPv4 unmapped.
func interfaceAddrs(name string) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	ifAddrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ifAddrs))
	for _, a := range ifAddrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs, nil
}

// buildOverlayController constructs and starts the overlay controller from App
// configuration and the local VTEP. The controller config is derived as follows:
//
//   - NodeID: App.Hostname (unique per node).
//   - VTEPIP and UnderlayInterface: the VTEP resolveOverlayVTEP decided.
//   - BridgeName: the overlay integration bridge br-int (overlay.DefaultBridgeName),
//     never the trunk bridge (sdn.ovs.bridge, br-fabric).
//   - Environment: the environment number of the network plan, so derived
//     VNIs are E·100000+n.
//   - OVSSocketPath: the configured path; empty if OVS is not available.
//   - VXLANPort: SDNConfig.Overlay.VXLANPort; defaults applied by ApplyDefaults.
//
// The controller is started synchronously. Start() only registers the local VTEP
// in memory and launches lightweight background goroutines, so it does not block
// daemon startup.
func buildOverlayController(ctx context.Context, a *app.App, vtep overlayVTEP, ovsSocketPath string, logger *logging.Logger) (*overlay.Controller, error) {
	cfg := &overlay.Config{
		NodeID:            a.Hostname,
		StateBackend:      overlay.DefaultStateBackend,
		VTEPIP:            vtep.addr,
		UnderlayInterface: vtep.iface,
	}

	// VXLAN port from overlay config (ApplyDefaults fills in 4789 when zero).
	cfg.VXLANPort = a.SDNConfig.Overlay.VXLANPort

	// Overlay ports live on the integration bridge (br-int, applied by
	// ApplyDefaults); the trunk bridge is never patched into it.
	if plan := a.SDNConfig.Plan(); plan != nil {
		cfg.Environment = plan.Environment().ID
	}

	// OVS socket: wired when available; controller health-checks log a warning
	// when nil but the in-memory state path remains fully operational.
	cfg.OVSSocketPath = ovsSocketPath

	// ApplyDefaults fills MTU, VXLANPort (4789), BridgeName (br-int),
	// StateBackend (memory), intervals.
	cfg.ApplyDefaults()

	ctrl, err := overlay.New(cfg)
	if err != nil {
		return nil, err
	}

	if err := ctrl.Start(ctx); err != nil {
		return nil, err
	}

	logger.Info("overlay controller started",
		"node_id", cfg.NodeID,
		"vtep_ip", cfg.VTEPIP,
		"underlay_iface", cfg.UnderlayInterface,
		"bridge", cfg.BridgeName,
		"environment", cfg.Environment,
		"vxlan_port", cfg.VXLANPort)

	return ctrl, nil
}
