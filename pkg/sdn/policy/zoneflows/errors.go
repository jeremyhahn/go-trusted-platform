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

package zoneflows

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrUnknownZone is returned when a zone has no registered generator and no
// network mapping can be resolved for it.
type ErrUnknownZone struct {
	// Zone is the unrecognised zone name.
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrUnknownZone) Error() string {
	return fmt.Sprintf("zoneflows: unknown zone %q", e.Zone)
}

// ErrUnresolvableNetwork is returned when the ZoneIndex holds no network entry
// for the requested zone (no VLAN can be derived).
type ErrUnresolvableNetwork struct {
	// Zone is the zone for which no network was found.
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrUnresolvableNetwork) Error() string {
	return fmt.Sprintf("zoneflows: no network found for zone %q", e.Zone)
}
