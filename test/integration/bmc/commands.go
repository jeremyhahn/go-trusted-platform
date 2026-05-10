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

//go:build integration

package bmc_integration

import (
	"context"
	"time"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// BMCCommands defines the central command set for BMC integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this
// interface. Tests are written once against this interface and run against
// all protocols.
type BMCCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Power management
	PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error)
	PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error)
	PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error)

	// Boot device control
	SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error
	GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error)

	// Virtual media
	MountISO(ctx context.Context, profileID uint64, isoURL string) error
	UnmountISO(ctx context.Context, profileID uint64) error
	VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error)

	// Sensors and system info
	GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error)
	GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error)

	// Certificate management
	GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error)

	// User management
	ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error)
}

// =============================================================================
// Test Configuration Constants
// =============================================================================

const (
	// DefaultBMCTestTimeout is the default timeout for BMC integration tests.
	DefaultBMCTestTimeout = 60 * time.Second

	// DefaultTestProfileID is the profile ID used in tests against the vBMC.
	DefaultTestProfileID uint64 = 1

	// DefaultTestISOURL is the ISO URL used for virtual media tests.
	DefaultTestISOURL = "https://images.example.com/test.iso"
)
