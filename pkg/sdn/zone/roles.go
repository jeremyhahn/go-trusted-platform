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

package zone

// ZoneForRole returns the name of the zone that carries the given lifecycle
// role within zones.  It returns ErrNoZoneForRole if no zone carries that
// role.  Callers in the device lifecycle (provisioning orchestrator,
// quarantine enforcement) should always reference zones by role rather than
// by name so that operator overrides are honoured automatically.
func ZoneForRole(zones []ZoneConfig, role LifecycleRole) (Zone, error) {
	for _, z := range zones {
		if z.LifecycleRole == role {
			return z.Name, nil
		}
	}
	return "", ErrNoZoneForRole{Role: role}
}
