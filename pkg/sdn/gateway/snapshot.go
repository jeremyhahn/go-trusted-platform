// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package gateway

import (
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// Component health values reported in Snapshot.Health.Components.
const (
	componentHealthy   = "healthy"
	componentUnhealthy = "unhealthy"
)

// Overall health status values reported in Snapshot.Health.Status.
const (
	healthStatusHealthy   = "healthy"
	healthStatusDegraded  = "degraded"
	healthStatusUnhealthy = "unhealthy"
)

// Snapshot assembles the control-plane telemetry snapshot from the
// gateway's live service state. It reports only what the node actually
// runs: per-service health from the registered handlers, BGP identity
// from the configured speaker section, and PXE/DHCP liveness from their
// handlers. Fields whose subsystems are not enabled on this node are
// left at their zero values rather than fabricated.
func (g *Gateway) Snapshot() *gwstate.Snapshot {
	snap := &gwstate.Snapshot{
		GatewayID: g.config.ID,
	}
	if hostname, err := os.Hostname(); err == nil {
		snap.Hostname = hostname
	}

	services := g.ActiveServices()
	sort.Strings(services)
	snap.Mode = strings.Join(services, ",")

	snap.Health = g.collectHealth()
	snap.BGP = g.collectBGP()
	snap.PXE.Status = serviceStatus(g.hasActiveService(ServicePXE))
	snap.DHCP.Status = serviceStatus(g.hasActiveService(ServiceDHCP))
	snap.DesiredConfig = g.DesiredConfigState()
	snap.Interfaces = collectInterfaces()
	snap.Annotations = map[string]string{
		"state":  g.GetState().String(),
		"uptime": g.Uptime().String(),
	}
	return snap
}

// collectHealth walks the registered service handlers and summarizes
// per-component and overall health.
func (g *Gateway) collectHealth() gwstate.HealthState {
	g.mu.RLock()
	handlers := make(map[string]ServiceHandler, len(g.serviceHandlers))
	for name, h := range g.serviceHandlers {
		handlers[name] = h
	}
	g.mu.RUnlock()

	health := gwstate.HealthState{
		Components: make(map[string]string, len(handlers)),
	}
	unhealthy := 0
	for name, h := range handlers {
		if err := h.Health(); err != nil {
			health.Components[name] = componentUnhealthy
			unhealthy++
			continue
		}
		health.Components[name] = componentHealthy
	}

	switch {
	case !g.IsOperational():
		health.Status = healthStatusUnhealthy
	case unhealthy > 0:
		health.Status = healthStatusDegraded
	default:
		health.Status = healthStatusHealthy
	}
	return health
}

// collectBGP reports the configured BGP speaker identity. Peer and prefix
// counters stay zero until a live speaker feeds them.
func (g *Gateway) collectBGP() gwstate.BGPState {
	var bgpState gwstate.BGPState
	if g.config.BGP == nil {
		return bgpState
	}
	bgpState.LocalASN = g.config.BGP.ASN
	if g.config.BGP.RouterID.IsValid() {
		bgpState.RouterID = g.config.BGP.RouterID.String()
	}
	return bgpState
}

// hasActiveService reports whether the named service is registered and
// currently active.
func (g *Gateway) hasActiveService(name string) bool {
	g.mu.RLock()
	h, ok := g.serviceHandlers[name]
	g.mu.RUnlock()
	return ok && h.IsActive()
}

// serviceStatus maps handler liveness onto the snapshot status vocabulary.
func serviceStatus(active bool) string {
	if active {
		return "running"
	}
	return "stopped"
}

// collectInterfaces reads the node's network interfaces for the
// control plane's NIC table. Failures yield an empty list rather than
// failing the snapshot.
func collectInterfaces() []gwstate.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]gwstate.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		entry := gwstate.Interface{
			Name:   iface.Name,
			Status: interfaceStatus(iface.Flags),
			MAC:    iface.HardwareAddr.String(),
		}
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
					entry.Addresses = append(entry.Addresses, prefix)
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// interfaceStatus maps interface flags onto the snapshot status vocabulary.
func interfaceStatus(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "up"
	}
	return "down"
}
