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

package modes

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// evpnRouteHandler programs one EVPN route type.
type evpnRouteHandler func(h *OverlayModeHandler, ctx context.Context, route *bgp.EVPNRouteData) error

// evpnRouteHandlers dispatches EVPN route changes by type. Type-1 and
// Type-4 routes (multihoming) are not used by the VLAN-based overlay.
var evpnRouteHandlers = map[bgp.EVPNRouteType]evpnRouteHandler{
	bgp.EVPNTypeMACIPAdvertisement: (*OverlayModeHandler).handleMACIPRoute,
	bgp.EVPNTypeInclusiveMulticast: (*OverlayModeHandler).handleIMETRoute,
	bgp.EVPNTypeIPPrefix:           (*OverlayModeHandler).handlePrefixRoute,
}

// handleEVPNRoute programs a change to an imported remote route. A route
// for a VNI this VTEP does not carry, or arriving while stopped, changes
// nothing.
func (h *OverlayModeHandler) handleEVPNRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	if route == nil {
		return nil
	}
	handle, ok := evpnRouteHandlers[route.Type]
	if !ok {
		return nil
	}
	return handle(h, ctx, route)
}

// handleMACIPRoute forwards a MAC to the VTEP that advertises it. The
// EVPN manager resolves MAC Mobility first: an add names where the MAC is
// now, so one at another VTEP replaces everything known of the MAC. A
// binding to an IP a local host answers for is held back until that host
// goes; a binding claiming the anycast gateway is refused outright.
func (h *OverlayModeHandler) handleMACIPRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	entry := route.MACIP
	if entry == nil || validateOverlayMAC(entry.MAC) != nil {
		return nil
	}
	if route.IsWithdraw {
		return h.withdrawMACIP(ctx, route)
	}
	binding := irbBinding{l3vni: entry.L3VNI, routerMAC: route.RouterMAC}
	vnis := []uint32{entry.VNI}
	if routable(h.config.L3VNI, binding) {
		vnis = append(vnis, h.config.L3VNI)
	}
	epoch, err := h.admit(ctx, entry.VTEPIP, vnis...)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	segment, ok := h.segments[entry.VNI]
	if !h.running || !ok {
		return nil
	}
	if err := h.unrevoked(entry.VTEPIP, epoch); err != nil {
		return err
	}
	key := hostKey{vni: entry.VNI, mac: entry.MAC.String()}
	if owner := h.conflict(entry); owner != "" {
		h.refusedBindings++
		h.logger.Warn("remote binding refused: it claims the anycast gateway",
			slog.Uint64("vni", uint64(entry.VNI)), slog.String("mac", key.mac),
			slog.String("ip", entry.IP.String()), slog.String("vtep", entry.VTEPIP.String()),
			slog.String("owner", owner))
		return &ErrMACOperationFailed{MAC: entry.MAC, Operation: "install remote",
			Cause: &ErrBindingConflict{VNI: entry.VNI, MAC: entry.MAC, IP: entry.IP, Owner: owner}}
	}
	old := h.hosts[key]
	next := &overlayHost{
		mac:       entry.MAC,
		vtep:      entry.VTEPIP,
		ips:       make(map[netip.Addr]irbBinding),
		held:      make(map[netip.Addr]irbBinding),
		updatedAt: time.Now(),
	}
	if old != nil && old.vtep == entry.VTEPIP {
		maps.Copy(next.ips, old.ips)
		maps.Copy(next.held, old.held)
	}
	delete(next.held, entry.IP)
	next.ips[entry.IP] = binding
	h.holdBack(key, next)
	if err := h.replaceHost(ctx, key, segment, old, next); err != nil {
		return &ErrMACOperationFailed{MAC: entry.MAC, Operation: "install remote", Cause: err}
	}
	if _, held := next.held[entry.IP]; held {
		h.refusedBindings++
		h.logger.Warn("remote binding held back: a local host answers for its IP",
			slog.Uint64("vni", uint64(entry.VNI)), slog.String("mac", key.mac),
			slog.String("ip", entry.IP.String()), slog.String("vtep", entry.VTEPIP.String()),
			slog.String("owner", "local host "+h.localHolder(key, entry.IP)))
	}
	h.logger.Debug("remote MAC installed",
		slog.Uint64("vni", uint64(entry.VNI)), slog.String("mac", key.mac),
		slog.String("ip", entry.IP.String()), slog.String("vtep", entry.VTEPIP.String()))
	if old != nil && old.local() {
		return h.releaseHeld(ctx)
	}
	return nil
}

// withdrawMACIP drops one route of a remote MAC, and the MAC with its last
// route. A withdrawal from a VTEP the MAC has since left changes nothing.
func (h *OverlayModeHandler) withdrawMACIP(ctx context.Context, route *bgp.EVPNRouteData) error {
	entry := route.MACIP

	h.mu.Lock()
	defer h.mu.Unlock()
	key := hostKey{vni: entry.VNI, mac: entry.MAC.String()}
	old, ok := h.hosts[key]
	if !h.running || !ok || old.vtep != entry.VTEPIP {
		return nil
	}
	_, bound := old.ips[entry.IP]
	_, held := old.held[entry.IP]
	if !bound && !held {
		return nil
	}
	next := &overlayHost{mac: old.mac, vtep: old.vtep, ips: maps.Clone(old.ips), held: maps.Clone(old.held),
		updatedAt: time.Now()}
	delete(next.ips, entry.IP)
	delete(next.held, entry.IP)
	if len(next.ips) == 0 && len(next.held) == 0 {
		next = nil
	}
	if err := h.replaceHost(ctx, key, h.segments[entry.VNI], old, next); err != nil {
		return &ErrMACOperationFailed{MAC: entry.MAC, Operation: "withdraw remote", Cause: err}
	}
	return nil
}

// handleIMETRoute keeps a VNI's ingress-replication list, and with it the
// VTEPs whose tunnelled frames the VNI accepts.
func (h *OverlayModeHandler) handleIMETRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	entry := route.IMET
	if entry == nil {
		return nil
	}
	var epoch uint64
	if !route.IsWithdraw {
		var err error
		if epoch, err = h.admit(ctx, entry.VTEPIP, entry.VNI); err != nil {
			return err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	old, ok := h.segments[entry.VNI]
	if !h.running || !ok {
		return nil
	}
	if !route.IsWithdraw {
		if err := h.unrevoked(entry.VTEPIP, epoch); err != nil {
			return err
		}
	}
	_, listed := slices.BinarySearchFunc(old.flood, entry.VTEPIP, netip.Addr.Compare)
	if listed != route.IsWithdraw {
		return nil
	}
	next := &overlaySegment{vlan: old.vlan, flood: slices.Clone(old.flood)}
	if route.IsWithdraw {
		next.flood = slices.DeleteFunc(next.flood, func(vtep netip.Addr) bool { return vtep == entry.VTEPIP })
	} else {
		next.flood = append(next.flood, entry.VTEPIP)
		slices.SortFunc(next.flood, netip.Addr.Compare)
	}
	next.flows = h.builder.segment(entry.VNI, next)
	if err := h.apply(ctx, old.flows, next.flows); err != nil {
		return &ErrVTEPOperationFailed{VTEPIP: entry.VTEPIP, Operation: "flood list", Cause: err}
	}
	h.segments[entry.VNI] = next
	return nil
}

// handlePrefixRoute routes a Type-5 IPv4 prefix of this VTEP's IP-VRF
// through the VTEP that advertises it. IPv6 prefixes are not routed: the
// pipeline routes IPv4 only.
func (h *OverlayModeHandler) handlePrefixRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	entry := route.PrefixData
	if entry == nil || h.config.L3VNI == 0 || entry.VNI != h.config.L3VNI || !entry.Prefix.Addr().Is4() {
		return nil
	}
	var epoch uint64
	if !route.IsWithdraw {
		if len(route.RouterMAC) != 6 {
			return &ErrVTEPOperationFailed{VTEPIP: entry.VTEPIP, Operation: "route", Cause: ErrRouterMACRequired}
		}
		var err error
		if epoch, err = h.admit(ctx, entry.VTEPIP, entry.VNI); err != nil {
			return err
		}
	}
	prefix := entry.Prefix.Masked()

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running || len(h.segments) == 0 {
		return nil
	}
	if !route.IsWithdraw {
		if err := h.unrevoked(entry.VTEPIP, epoch); err != nil {
			return err
		}
	}
	old := h.prefixes[prefix]
	next := &overlayPrefix{routes: make(map[netip.Addr]*overlayPrefixRoute)}
	if old != nil {
		maps.Copy(next.routes, old.routes)
	}
	if route.IsWithdraw {
		delete(next.routes, entry.VTEPIP)
	} else {
		next.routes[entry.VTEPIP] = &overlayPrefixRoute{vtep: entry.VTEPIP, routerMAC: route.RouterMAC}
	}
	if best := next.best(); best != nil {
		next.flows = h.builder.prefix(prefix, best)
	}
	var release []*openflow.FlowMod
	if old != nil {
		release = old.flows
	}
	if err := h.apply(ctx, release, next.flows); err != nil {
		return &ErrVTEPOperationFailed{VTEPIP: entry.VTEPIP, Operation: "prefix route", Cause: err}
	}
	if len(next.routes) == 0 {
		delete(h.prefixes, prefix)
		return nil
	}
	h.prefixes[prefix] = next
	return nil
}

// RevokeVTEP withdraws every route currently installed from the VTEP using the
// same route handlers that process EVPN withdrawals. Admission revocation uses
// this path so decap authorization and overlay reachability leave through the
// normal flow-table planner instead of a second flow implementation.
//
// A revocation also refuses every route of the VTEP whose admission was in
// flight when it began (ErrVTEPRevoked). A withdrawal the switch refuses
// does not stop the others: every route is tried and the failures are
// joined, so one bad flow never leaves the rest of the VTEP installed.
func (h *OverlayModeHandler) RevokeVTEP(ctx context.Context, vtep netip.Addr) error {
	if !vtep.Is4() || vtep.IsUnspecified() {
		return &ErrVTEPOperationFailed{VTEPIP: vtep, Operation: "revoke", Cause: ErrInvalidVTEPIP}
	}

	h.mu.Lock()
	h.revocations[vtep]++
	if !h.running {
		h.mu.Unlock()
		return nil
	}
	routes := h.revocationRoutesLocked(vtep)
	h.mu.Unlock()

	var errs []error
	for _, route := range routes {
		if err := h.handleEVPNRoute(ctx, route); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *OverlayModeHandler) revocationRoutesLocked(vtep netip.Addr) []*bgp.EVPNRouteData {
	var routes []*bgp.EVPNRouteData
	for vni, segment := range h.segments {
		if _, found := slices.BinarySearchFunc(segment.flood, vtep, netip.Addr.Compare); !found {
			continue
		}
		routes = append(routes, &bgp.EVPNRouteData{
			Type:       bgp.EVPNTypeInclusiveMulticast,
			IMET:       &bgp.IMETEntry{VNI: vni, VTEPIP: vtep},
			NextHop:    vtep,
			IsWithdraw: true,
		})
	}
	for key, host := range h.hosts {
		if host == nil || host.local() || host.vtep != vtep {
			continue
		}
		seen := make(map[netip.Addr]struct{}, len(host.ips)+len(host.held))
		for ip, binding := range host.ips {
			routes = append(routes, macIPWithdrawalRoute(key.vni, vtep, host, ip, binding))
			seen[ip] = struct{}{}
		}
		for ip, binding := range host.held {
			if _, ok := seen[ip]; ok {
				continue
			}
			routes = append(routes, macIPWithdrawalRoute(key.vni, vtep, host, ip, binding))
		}
	}
	for prefix, old := range h.prefixes {
		if old == nil {
			continue
		}
		if _, ok := old.routes[vtep]; !ok {
			continue
		}
		routes = append(routes, &bgp.EVPNRouteData{
			Type:       bgp.EVPNTypeIPPrefix,
			PrefixData: &bgp.PrefixRoute{Prefix: prefix, VNI: h.config.L3VNI, VTEPIP: vtep},
			NextHop:    vtep,
			IsWithdraw: true,
		})
	}
	return routes
}

func macIPWithdrawalRoute(vni uint32, vtep netip.Addr, host *overlayHost, ip netip.Addr, binding irbBinding) *bgp.EVPNRouteData {
	return &bgp.EVPNRouteData{
		Type: bgp.EVPNTypeMACIPAdvertisement,
		MACIP: &bgp.MACIPEntry{
			MAC:    host.mac,
			IP:     ip,
			VNI:    vni,
			L3VNI:  binding.l3vni,
			VTEPIP: vtep,
		},
		NextHop:    vtep,
		RouterMAC:  binding.routerMAC,
		IsWithdraw: true,
	}
}

// routable reports whether a remote binding can be routed to over the
// IP-VRF l3vni: it names that IP-VRF and the remote router MAC.
func routable(l3vni uint32, binding irbBinding) bool {
	return l3vni != 0 && binding.l3vni == l3vni && len(binding.routerMAC) == 6
}

// admit asks the admitter whether vtep may carry each of vnis. Only IPv4
// VTEPs are admitted: the flows set and match IPv4 tunnel endpoints only.
// It returns the VTEP's revocation epoch, read before the admitter is
// asked, for the install to check with unrevoked.
func (h *OverlayModeHandler) admit(ctx context.Context, vtep netip.Addr, vnis ...uint32) (uint64, error) {
	if !vtep.Is4() || vtep.IsUnspecified() {
		return 0, &ErrVTEPOperationFailed{VTEPIP: vtep, Operation: "admit", Cause: ErrInvalidVTEPIP}
	}
	h.mu.Lock()
	epoch := h.revocations[vtep]
	h.mu.Unlock()
	for _, vni := range vnis {
		if err := h.config.Admitter.AdmitVTEP(ctx, vni, vtep); err != nil {
			return 0, &ErrVTEPOperationFailed{VTEPIP: vtep, Operation: "admit", Cause: err}
		}
	}
	return epoch, nil
}

// unrevoked refuses the install of a route admitted at epoch when vtep has
// been revoked since. Caller holds mu.
func (h *OverlayModeHandler) unrevoked(vtep netip.Addr, epoch uint64) error {
	if h.revocations[vtep] != epoch {
		return &ErrVTEPOperationFailed{VTEPIP: vtep, Operation: "admit", Cause: ErrVTEPRevoked}
	}
	return nil
}

// conflict names the anycast gateway address a remote binding claims, or
// is empty when it claims none. The gateway's ARP replies share a flow
// identity with the binding's, and bridging its MAC away would take the
// gateway's traffic, so such a binding is refused whole and never retried.
func (h *OverlayModeHandler) conflict(entry *bgp.MACIPEntry) string {
	if slices.Equal(entry.MAC, h.config.AnycastGatewayMAC) {
		return "anycast gateway MAC"
	}
	if entry.IP.IsValid() && entry.IP == h.config.AnycastGatewayIP {
		return "anycast gateway IP"
	}
	return ""
}

// localHolder is the MAC of a local host, other than key, holding ip, or
// empty when none does. The MAC's own entry is no holder: a route for a
// MAC local on its VNI is the MAC moving away, which MAC Mobility settled
// before the route arrived. Caller holds mu.
func (h *OverlayModeHandler) localHolder(key hostKey, ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	for other, host := range h.hosts {
		if _, holds := host.ips[ip]; holds && host.local() && other != key {
			return other.mac
		}
	}
	return ""
}

// holdBack sorts a remote host's bindings by whether a local host answers
// for their IP: those it does are held, the rest bound. A local host's ARP
// reply and host route share a flow identity with the binding's, so taking
// the binding would take the local host's traffic. Caller holds mu.
func (h *OverlayModeHandler) holdBack(key hostKey, host *overlayHost) {
	for ip, binding := range host.held {
		if h.localHolder(key, ip) == "" {
			host.ips[ip] = binding
			delete(host.held, ip)
		}
	}
	for ip, binding := range host.ips {
		if h.localHolder(key, ip) != "" {
			host.held[ip] = binding
			delete(host.ips, ip)
		}
	}
}

// releaseHeld binds every held remote binding whose IP no local host
// answers for any more, once a local host has gone. Caller holds mu.
func (h *OverlayModeHandler) releaseHeld(ctx context.Context) error {
	var errs []error
	for key, host := range h.hosts {
		if len(host.held) == 0 {
			continue
		}
		next := &overlayHost{mac: host.mac, vtep: host.vtep, ips: maps.Clone(host.ips), held: maps.Clone(host.held),
			updatedAt: time.Now()}
		h.holdBack(key, next)
		if len(next.held) == len(host.held) {
			continue
		}
		if err := h.replaceHost(ctx, key, h.segments[key.vni], host, next); err != nil {
			errs = append(errs, &ErrMACOperationFailed{MAC: host.mac, Operation: "release held", Cause: err})
		}
	}
	return errors.Join(errs...)
}
