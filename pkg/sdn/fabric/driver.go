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

package fabric

import (
	"context"
	"log/slog"
)

// Driver is the interface that switch-vendor-specific drivers must implement.
// All operations are idempotent: calling an operation that is already applied
// is a no-op.
type Driver interface {
	// Connect establishes a connection to the switch.
	Connect(ctx context.Context) error

	// Close releases the connection to the switch.
	Close() error

	// Ping verifies the connection to the switch is alive.
	Ping(ctx context.Context) error

	// EnsureVLAN creates a VLAN on the switch if it does not already exist.
	EnsureVLAN(ctx context.Context, vlan uint16, name string) error

	// EnsureVNI maps a VNI to a VLAN on the NVE interface. No-op in VLAN mode.
	EnsureVNI(ctx context.Context, vni uint32, vlan uint16) error

	// EnsureLAG configures a link aggregation group on the switch.
	EnsureLAG(ctx context.Context, lag LAGConfig) error

	// SetPortAccess configures a port in access mode with the given VLAN.
	SetPortAccess(ctx context.Context, port PortRef, vlan uint16) error

	// SetPortTrunk configures a port in trunk mode with the allowed VLANs
	// and an optional native VLAN.
	SetPortTrunk(ctx context.Context, port PortRef, allowed []uint16, native uint16) error
}

// DriverFactory creates a Driver for a given switch configuration.
type DriverFactory func(cfg SwitchConfig, logger *slog.Logger) (Driver, error)

// driverFactories maps vendor names to their driver factory functions.
// Registration is done via RegisterDriver at init time.
var driverFactories = map[string]DriverFactory{}

// RegisterDriver registers a driver factory for the given vendor name.
// This is typically called from a driver package's init() function.
func RegisterDriver(vendor string, factory DriverFactory) {
	driverFactories[vendor] = factory
}

// DriverFor returns a Driver for the given switch configuration by looking
// up the vendor in the registered factories.
func DriverFor(cfg SwitchConfig, logger *slog.Logger) (Driver, error) {
	factory, ok := driverFactories[cfg.Vendor]
	if !ok {
		return nil, ErrDriverNotFound{Vendor: cfg.Vendor}
	}
	return factory(cfg, logger)
}
