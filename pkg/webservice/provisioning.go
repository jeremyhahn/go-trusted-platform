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

package webservice

import (
	"fmt"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// ValidateProvisioningSurface checks a webservice whose surface is
// "provisioning" against the environment's network plan (#177).
//
// The provisioning listener serves the unauthenticated boot-time
// GET /api/v1/devices/config, so where it listens is its whole trust
// boundary. Its address is the operator's bind-host, and the only accepted
// value is a literal address inside the provisioning zone's subnet as
// sdn.environment numbers it — the same plan the provisioning-zone flows,
// DHCP and PXE are derived from. There is no second source of the zone's
// addressing. An empty bind-host would listen on every interface and is
// refused, as is a plaintext-only listener and any virtual host.
//
// Webservices on any other surface pass unchecked.
func ValidateProvisioningSurface(cfg *v1.Config, plan *netplan.Plan) error {
	if cfg == nil || cfg.Surface != v1.SurfaceProvisioning {
		return nil
	}
	if plan == nil {
		return &ErrProvisioningNetworkPlanRequired{Name: cfg.Name}
	}
	if cfg.BindHost == "" {
		return &ErrProvisioningBindHostRequired{Name: cfg.Name}
	}
	addr, err := netip.ParseAddr(cfg.BindHost)
	if err != nil || addr.IsUnspecified() {
		return &ErrProvisioningBindHostInvalid{Name: cfg.Name, BindHost: cfg.BindHost}
	}
	numbering, err := plan.MustZone(zone.ZoneProvisioning)
	if err != nil {
		return &ErrProvisioningZoneMissing{Name: cfg.Name, Cause: err}
	}
	if owner, ok := plan.ZoneForAddr(addr); !ok || owner != zone.ZoneProvisioning {
		return &ErrProvisioningBindHostOutsideZone{Name: cfg.Name, BindHost: cfg.BindHost, Zone: numbering}
	}
	if cfg.TLSPort <= 0 {
		return &ErrProvisioningTLSPortRequired{Name: cfg.Name}
	}
	if cfg.VirtualHosts != nil && len(*cfg.VirtualHosts) > 0 {
		return &ErrProvisioningVirtualHosts{Name: cfg.Name}
	}
	return nil
}

// ErrProvisioningSurfaceEmpty is the startup refusal of a provisioning
// listener with no device profile service: it would mount nothing.
type ErrProvisioningSurfaceEmpty struct{ Name string }

func (e *ErrProvisioningSurfaceEmpty) Error() string {
	return fmt.Sprintf("webservice %q: a provisioning surface with no device profile service mounts nothing", e.Name)
}

// ErrProvisioningNetworkPlanRequired refuses a provisioning listener on a
// node with no sdn.environment: without the plan there is no provisioning
// zone to bind into.
type ErrProvisioningNetworkPlanRequired struct{ Name string }

func (e *ErrProvisioningNetworkPlanRequired) Error() string {
	return fmt.Sprintf("webservice %q: a provisioning surface needs sdn.environment to number the provisioning zone", e.Name)
}

// ErrProvisioningBindHostRequired refuses a provisioning listener with no
// bind-host, which would listen on every interface.
type ErrProvisioningBindHostRequired struct{ Name string }

func (e *ErrProvisioningBindHostRequired) Error() string {
	return fmt.Sprintf("webservice %q: a provisioning surface needs a bind-host inside the provisioning zone; an empty one listens on every interface", e.Name)
}

// ErrProvisioningBindHostInvalid refuses a bind-host that is not a literal,
// specified IP address.
type ErrProvisioningBindHostInvalid struct {
	Name     string
	BindHost string
}

func (e *ErrProvisioningBindHostInvalid) Error() string {
	return fmt.Sprintf("webservice %q: provisioning bind-host %q is not a specified IP address", e.Name, e.BindHost)
}

// ErrProvisioningZoneMissing refuses a provisioning listener when the
// network plan declares no provisioning zone.
type ErrProvisioningZoneMissing struct {
	Name  string
	Cause error
}

func (e *ErrProvisioningZoneMissing) Error() string {
	return fmt.Sprintf("webservice %q: the network plan has no provisioning zone: %v", e.Name, e.Cause)
}

func (e *ErrProvisioningZoneMissing) Unwrap() error { return e.Cause }

// ErrProvisioningBindHostOutsideZone refuses a bind-host that is not an
// address of the provisioning zone.
type ErrProvisioningBindHostOutsideZone struct {
	Name     string
	BindHost string
	Zone     netplan.ZoneNumbering
}

func (e *ErrProvisioningBindHostOutsideZone) Error() string {
	subnets := e.Zone.Subnet4.String()
	if e.Zone.Subnet6.IsValid() {
		subnets += " or " + e.Zone.Subnet6.String()
	}
	return fmt.Sprintf("webservice %q: provisioning bind-host %s is outside the provisioning zone (VLAN %d, %s)",
		e.Name, e.BindHost, e.Zone.VLAN, subnets)
}

// ErrProvisioningTLSPortRequired refuses a provisioning listener with no
// TLS port: the boot client fetches its config over HTTPS.
type ErrProvisioningTLSPortRequired struct{ Name string }

func (e *ErrProvisioningTLSPortRequired) Error() string {
	return fmt.Sprintf("webservice %q: a provisioning surface needs a tls-port", e.Name)
}

// ErrProvisioningVirtualHosts refuses virtual hosts on a provisioning
// listener, which carries the config route and nothing else.
type ErrProvisioningVirtualHosts struct{ Name string }

func (e *ErrProvisioningVirtualHosts) Error() string {
	return fmt.Sprintf("webservice %q: a provisioning surface carries no virtual hosts", e.Name)
}
