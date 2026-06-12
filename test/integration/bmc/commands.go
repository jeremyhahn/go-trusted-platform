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

	// Enrollment ceremony
	EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error)

	// Factory certificate restore ceremony
	RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error)
}

// =============================================================================
// Enrollment types
// =============================================================================

// EnrollOptions carries optional per-enrollment overrides. Nil pointer fields
// preserve the profile's stored enrollment config defaults, matching the
// semantics of app.BMCEnrollOptions and bmcsvc.EnrollOptions.
type EnrollOptions struct {
	// ReplaceCertificate overrides the profile's replace_certificate flag.
	ReplaceCertificate *bool
	// RotatePassword overrides the profile's rotate_password flag.
	RotatePassword *bool
	// DNSRegister overrides the profile's dns_register flag.
	DNSRegister *bool
	// DANEPublish overrides the profile's dane_publish flag.
	DANEPublish *bool
}

// EnrollStep records the outcome of a single step in the enrollment ceremony.
type EnrollStep struct {
	// Name is the step identifier (e.g. "trust", "factory_cert", "credentials").
	Name string `json:"name"`
	// OK indicates whether the step succeeded.
	OK bool `json:"ok"`
	// Detail provides optional human-readable detail, typically set on failure.
	Detail string `json:"detail,omitempty"`
}

// EnrollFactoryCertMeta holds auditable metadata captured from the BMC factory
// TLS certificate at the start of the enrollment ceremony.
type EnrollFactoryCertMeta struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// EnrollResult is the full outcome of a BMC enrollment ceremony as returned by
// every protocol adapter. The type mirrors bmcsvc.EnrollResult but is local so
// the test package has no compile-time dependency on the exact SDK version of
// that type.
type EnrollResult struct {
	// DeviceID is the platform device ID assigned to the enrolled BMC.
	DeviceID uint64 `json:"device_id,string"`
	// Endpoint is the BMC HTTPS endpoint (host:port).
	Endpoint string `json:"endpoint"`
	// Hostname is the BMC hostname.
	Hostname string `json:"hostname"`
	// DNSName is the FQDN registered in the platform DNS, if requested.
	DNSName string `json:"dns_name,omitempty"`
	// PinSPKISHA256 is the HPKP-style SHA-256 pin of the new certificate's SPKI.
	PinSPKISHA256 string `json:"pin_spki_sha256"`
	// FactoryCertMeta holds metadata from the captured factory certificate.
	FactoryCertMeta EnrollFactoryCertMeta `json:"factory_cert_meta"`
	// Steps records the per-step outcomes of the enrollment ceremony.
	Steps []EnrollStep `json:"steps"`
}

// =============================================================================
// Restore types
// =============================================================================

// RestoreFactoryCertMeta holds auditable metadata captured from the new
// self-signed factory certificate generated by the restore ceremony.
type RestoreFactoryCertMeta struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// RestoreResult is the full outcome of a BMC factory-certificate restore
// ceremony as returned by every protocol adapter.
type RestoreResult struct {
	// DeviceID is the platform device ID of the BMC whose cert was restored.
	DeviceID uint64 `json:"device_id,string"`
	// Endpoint is the BMC HTTPS endpoint (host:port).
	Endpoint string `json:"endpoint"`
	// Hostname is the BMC hostname.
	Hostname string `json:"hostname"`
	// NewCertMeta holds metadata from the newly regenerated factory certificate.
	NewCertMeta RestoreFactoryCertMeta `json:"new_cert_meta"`
	// Steps records the per-step outcomes of the restore ceremony.
	Steps []EnrollStep `json:"steps"`
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
