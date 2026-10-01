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

package policy

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrAdmissionZone is returned when a device profile names a zone a device
// may not be admitted onto as an access port.
type ErrAdmissionZone struct {
	// Zone is the zone the profile named.
	Zone zone.Zone
	// Reason says why the zone is refused.
	Reason string
}

// Error implements the error interface.
func (e ErrAdmissionZone) Error() string {
	return fmt.Sprintf("policy: a device cannot be admitted onto zone %q: %s", e.Zone, e.Reason)
}

// Admission refusal reasons.
const (
	admissionUndeclared = "the zone is not declared"
	admissionOOB        = "it is the out-of-band zone (BMCs only)"
	admissionTransit    = "transit carries the gateway edge only"
	admissionFabric     = "fabric is the VXLAN underlay; a device joins it as a VTEP, not as an access port"
	admissionLifecycle  = "it is a lifecycle zone with its own phase (provisioning, quarantine)"
	admissionControl    = "control-plane admits a device only when the zone set opens an audited privileged path into it"
)

// ValidateAdmissionZone decides whether a device may be admitted as an access
// port onto zone z, the zone its profile names explicitly, given the resolved
// zone set. It is the one place the rule lives:
//
//   - the zone must be declared;
//   - never the out-of-band zone (management), transit or fabric;
//   - never a lifecycle zone: provisioning and quarantine are entered through
//     their own phases, not by admission;
//   - control-plane only when the zone set opens an audited privileged path
//     into it (zone.PrivilegedPaths), so naming it in a profile cannot skip
//     the privileged_access audit;
//   - any other zone (storage, backup, hypervisor, an owner-defined zone) is
//     allowed.
func ValidateAdmissionZone(zones []zone.ZoneConfig, z zone.Zone) error {
	var cfg *zone.ZoneConfig
	for i := range zones {
		if zones[i].Name == z {
			cfg = &zones[i]
			break
		}
	}
	if cfg == nil {
		return ErrAdmissionZone{Zone: z, Reason: admissionUndeclared}
	}

	refusals := []struct {
		refused bool
		reason  string
	}{
		{cfg.OOB, admissionOOB},
		{z == zone.ZoneTransit, admissionTransit},
		{z == zone.ZoneFabric, admissionFabric},
		{cfg.LifecycleRole != "", admissionLifecycle},
	}
	for _, r := range refusals {
		if r.refused {
			return ErrAdmissionZone{Zone: z, Reason: r.reason}
		}
	}

	if z == zone.ZoneControlPlane {
		for _, p := range zone.PrivilegedPaths(zones) {
			if p.To == zone.ZoneControlPlane {
				return nil
			}
		}
		return ErrAdmissionZone{Zone: z, Reason: admissionControl}
	}
	return nil
}

// ValidateAdmissionZone applies ValidateAdmissionZone to the manager's
// resolved zone set. A manager configured without a zone set uses the
// built-in zones, which open no privileged path.
func (m *ZoneFlowManager) ValidateAdmissionZone(z zone.Zone) error {
	zones := m.zones
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	return ValidateAdmissionZone(zones, z)
}
