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

package pxe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultServiceConfig(t *testing.T) {
	cfg := testServiceConfig()

	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.IPXEConfig)
	assert.Equal(t, "", cfg.BridgeName)
	assert.Equal(t, testQuarantineVLAN, cfg.QuarantineVLAN)
	assert.Equal(t, testProvisioningVLAN, cfg.ProvisioningVLAN)
	assert.NotNil(t, cfg.Firmware)
	assert.Equal(t, "", cfg.RegistryAddr)
	assert.Equal(t, DefaultISORef, cfg.DefaultISORef)
	assert.Nil(t, cfg.ACMEServerIPs)
	assert.Nil(t, cfg.DNSServerIPs)
	assert.Equal(t, DefaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, DefaultInstallTimeout, cfg.InstallTimeout)
	assert.Equal(t, DefaultEnrollmentTimeout, cfg.EnrollmentTimeout)
	assert.True(t, cfg.EnableAutoQuarantine)
	assert.False(t, cfg.WebhookEnabled)
	assert.Equal(t, "", cfg.WebhookSecret)
}

func TestDefaultFirmwareConfig(t *testing.T) {
	cfg := DefaultFirmwareConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, FirmwareSourceEmbedded, cfg.Source)
	assert.Equal(t, DefaultUpstreamFirmwareURL, cfg.UpstreamURL)
	assert.Equal(t, "", cfg.ExpectedDigest)
	assert.Equal(t, "", cfg.CustomPath)
	assert.True(t, cfg.RequireSecureBoot)
}

func TestServiceConfig_Validate_ValidConfig(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestServiceConfig_Validate_NilIPXEConfig(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.IPXEConfig = nil

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "IPXEConfig")
}

func TestServiceConfig_Validate_EmptyBridgeName(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = ""

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "BridgeName")
}

func TestServiceConfig_Validate_InvalidQuarantineVLAN(t *testing.T) {
	tests := []struct {
		name string
		vlan uint16
	}{
		{"zero", 0},
		{"above_max", 4095},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testServiceConfig()
			cfg.BridgeName = "br-int"
			cfg.QuarantineVLAN = tt.vlan

			err := cfg.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidVLAN))
			assert.Contains(t, err.Error(), "QuarantineVLAN")
		})
	}
}

func TestServiceConfig_Validate_InvalidProvisioningVLAN(t *testing.T) {
	tests := []struct {
		name string
		vlan uint16
	}{
		{"zero", 0},
		{"above_max", 4095},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testServiceConfig()
			cfg.BridgeName = "br-int"
			cfg.ProvisioningVLAN = tt.vlan

			err := cfg.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidVLAN))
			assert.Contains(t, err.Error(), "ProvisioningVLAN")
		})
	}
}

func TestServiceConfig_Validate_SameVLANs(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.QuarantineVLAN = 100
	cfg.ProvisioningVLAN = 100

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidVLAN))
	assert.Contains(t, err.Error(), "different")
}

func TestServiceConfig_Validate_InvalidInstallTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"zero", 0},
		{"negative", -1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testServiceConfig()
			cfg.BridgeName = "br-int"
			cfg.InstallTimeout = tt.timeout

			err := cfg.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidTimeout))
			assert.Contains(t, err.Error(), "InstallTimeout")
		})
	}
}

func TestServiceConfig_Validate_InvalidEnrollmentTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"zero", 0},
		{"negative", -1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testServiceConfig()
			cfg.BridgeName = "br-int"
			cfg.EnrollmentTimeout = tt.timeout

			err := cfg.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidTimeout))
			assert.Contains(t, err.Error(), "EnrollmentTimeout")
		})
	}
}

func TestServiceConfig_Validate_NegativeMaxRetries(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.MaxRetries = -1

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "MaxRetries")
}

func TestServiceConfig_Validate_WebhookEnabledNoSecret(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.WebhookEnabled = true
	cfg.WebhookSecret = ""

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
	assert.Contains(t, err.Error(), "WebhookSecret")
}

func TestServiceConfig_Validate_WebhookEnabledWithSecret(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.WebhookEnabled = true
	cfg.WebhookSecret = "supersecret"

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestServiceConfig_Validate_NilFirmwareConfig(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.Firmware = nil

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestServiceConfig_Validate_InvalidFirmwareConfig(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.Firmware = &FirmwareConfig{
		Source: FirmwareSourceUpstream,
		// Missing ExpectedDigest which is required for upstream
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "firmware config")
}

func TestServiceConfig_Validate_ValidVLANRange(t *testing.T) {
	tests := []struct {
		name             string
		quarantineVLAN   uint16
		provisioningVLAN uint16
	}{
		{"min_values", MinVLANID, MinVLANID + 1},
		{"max_values", MaxVLANID - 1, MaxVLANID},
		{"typical_values", 100, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testServiceConfig()
			cfg.BridgeName = "br-int"
			cfg.QuarantineVLAN = tt.quarantineVLAN
			cfg.ProvisioningVLAN = tt.provisioningVLAN

			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestFirmwareConfig_Validate_EmbeddedSource(t *testing.T) {
	cfg := &FirmwareConfig{
		Source: FirmwareSourceEmbedded,
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestFirmwareConfig_Validate_UpstreamSource_Valid(t *testing.T) {
	cfg := &FirmwareConfig{
		Source:         FirmwareSourceUpstream,
		UpstreamURL:    "https://example.com/ipxe.efi",
		ExpectedDigest: "sha256:abc123",
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestFirmwareConfig_Validate_UpstreamSource_MissingDigest(t *testing.T) {
	cfg := &FirmwareConfig{
		Source:      FirmwareSourceUpstream,
		UpstreamURL: "https://example.com/ipxe.efi",
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFirmwareConfig))
	assert.Contains(t, err.Error(), "ExpectedDigest")
}

func TestFirmwareConfig_Validate_UpstreamSource_MissingURL(t *testing.T) {
	cfg := &FirmwareConfig{
		Source:         FirmwareSourceUpstream,
		ExpectedDigest: "sha256:abc123",
		UpstreamURL:    "",
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFirmwareConfig))
	assert.Contains(t, err.Error(), "UpstreamURL")
}

func TestFirmwareConfig_Validate_CustomSource_Valid(t *testing.T) {
	// Create a temporary file for custom firmware
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "ipxe.efi")
	err := os.WriteFile(customPath, []byte("firmware content"), 0644)
	require.NoError(t, err)

	cfg := &FirmwareConfig{
		Source:     FirmwareSourceCustom,
		CustomPath: customPath,
	}

	err = cfg.Validate()
	assert.NoError(t, err)
}

func TestFirmwareConfig_Validate_CustomSource_MissingPath(t *testing.T) {
	cfg := &FirmwareConfig{
		Source:     FirmwareSourceCustom,
		CustomPath: "",
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFirmwareConfig))
	assert.Contains(t, err.Error(), "CustomPath")
}

func TestFirmwareConfig_Validate_CustomSource_FileNotExists(t *testing.T) {
	cfg := &FirmwareConfig{
		Source:     FirmwareSourceCustom,
		CustomPath: "/nonexistent/path/ipxe.efi",
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFirmwareNotFound))
}

func TestFirmwareConfig_Validate_EmptySource(t *testing.T) {
	cfg := &FirmwareConfig{
		Source: "",
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFirmwareConfig))
	assert.Contains(t, err.Error(), "Source")
}

func TestFirmwareConfig_Validate_UnknownSource(t *testing.T) {
	cfg := &FirmwareConfig{
		Source: "unknown_source",
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFirmwareConfig))
	assert.Contains(t, err.Error(), "unknown firmware source")
}

func TestConstants(t *testing.T) {
	// Contracts that leave the process; no other test pins these literals.
	// The upstream firmware URL is fetched over the wire.
	assert.Equal(t, "https://boot.ipxe.org/ipxe.efi", DefaultUpstreamFirmwareURL)
	// IEEE 802.1Q bounds on the VLAN IDs written to the wire and to netplan files.
	assert.Equal(t, uint16(1), MinVLANID)
	assert.Equal(t, uint16(4094), MaxVLANID)
}

func TestServiceConfig_WithAllFieldsSet(t *testing.T) {
	cfg := &ServiceConfig{
		IPXEConfig:           ipxe.DefaultServerConfig(),
		BridgeName:           "br-custom",
		QuarantineVLAN:       10,
		ProvisioningVLAN:     20,
		Firmware:             DefaultFirmwareConfig(),
		RegistryAddr:         "registry.example.com:5000",
		DefaultISORef:        "iso/custom:v1.0",
		MaxRetries:           5,
		InstallTimeout:       45 * time.Minute,
		EnrollmentTimeout:    10 * time.Minute,
		EnableAutoQuarantine: false,
		WebhookEnabled:       true,
		WebhookSecret:        "secret123",
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestServiceConfig_WebhookSecretMessageNamesTheHMAC: the secret is now the
// key the webhook verifies every report with (#240), so the message says
// what it is for instead of warning that it protects nothing.
func TestServiceConfig_WebhookSecretMessageNamesTheHMAC(t *testing.T) {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-int"
	cfg.WebhookEnabled = true
	cfg.WebhookSecret = ""

	err := cfg.Validate()
	require.Error(t, err)

	msg := err.Error()
	assert.Contains(t, msg, "HMAC")
	assert.NotContains(t, msg, "not yet enforced")
}

// TestDaemonPXEConfigDefaultsOff pins the daemon's pxe: section (#1694): no
// section or enabled: false names no backend, a valid enabled section builds
// a ServiceConfig that passes Validate, and an invalid enabled section is a
// typed error, never a silent fallback to no backend.
func TestDaemonPXEConfigDefaultsOff(t *testing.T) {
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)

	t.Run("no section", func(t *testing.T) {
		var section *DaemonConfig
		cfg, err := section.ToServiceConfig(plan)
		require.NoError(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("zero value and enabled false", func(t *testing.T) {
		for _, section := range []*DaemonConfig{{}, {Enabled: false, BridgeName: "br-pxe"}} {
			cfg, err := section.ToServiceConfig(plan)
			require.NoError(t, err)
			assert.Nil(t, cfg)
		}
	})

	t.Run("valid enabled section", func(t *testing.T) {
		section := &DaemonConfig{
			Enabled:           true,
			BridgeName:        "br-pxe",
			DefaultISORef:     "iso/custom:1",
			MaxRetries:        5,
			InstallTimeout:    time.Hour,
			EnrollmentTimeout: 2 * time.Minute,
			WebhookEnabled:    true,
			WebhookSecret:     "s3cret",
			LocalFilesDir:     "/srv/pxe/files",
			InstallsDir:       "/srv/pxe/installs",
			FirmwareDir:       "/srv/pxe/firmware",
			FirmwareOffline:   true,
			BootEntries:       []ipxe.BootEntry{{Name: "default", Kernel: "http://example.com/kernel"}},
		}
		cfg, err := section.ToServiceConfig(plan)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.NoError(t, cfg.Validate())
		quarantine, err := plan.MustZone(zone.ZoneQuarantine)
		require.NoError(t, err)
		assert.Equal(t, quarantine.VLAN, cfg.QuarantineVLAN)
		assert.Equal(t, "br-pxe", cfg.BridgeName)
		assert.Equal(t, "iso/custom:1", cfg.DefaultISORef)
		assert.Equal(t, 5, cfg.MaxRetries)
		assert.Equal(t, time.Hour, cfg.InstallTimeout)
		assert.Equal(t, 2*time.Minute, cfg.EnrollmentTimeout)
		assert.True(t, cfg.WebhookEnabled)
		assert.Equal(t, "s3cret", cfg.WebhookSecret)
		assert.Equal(t, "/srv/pxe/files", cfg.IPXEConfig.LocalFilesDir)
		assert.Equal(t, "/srv/pxe/installs", cfg.IPXEConfig.InstallsDir)
		assert.Equal(t, "/srv/pxe/firmware", cfg.IPXEConfig.FirmwareDir)
		assert.True(t, cfg.IPXEConfig.FirmwareOffline)
		assert.Len(t, cfg.IPXEConfig.BootEntries, 1)
	})

	t.Run("enabled section keeps the defaults it does not name", func(t *testing.T) {
		cfg, err := (&DaemonConfig{Enabled: true, BridgeName: "br-pxe"}).ToServiceConfig(plan)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, DefaultISORef, cfg.DefaultISORef)
		assert.Equal(t, DefaultMaxRetries, cfg.MaxRetries)
		assert.Equal(t, DefaultInstallTimeout, cfg.InstallTimeout)
		assert.Equal(t, DefaultEnrollmentTimeout, cfg.EnrollmentTimeout)
	})

	t.Run("invalid enabled section", func(t *testing.T) {
		cfg, err := (&DaemonConfig{Enabled: true}).ToServiceConfig(plan)
		require.Error(t, err)
		assert.Nil(t, cfg)
		assert.True(t, errors.Is(err, ErrInvalidConfig), "missing bridge-name: %v", err)

		cfg, err = (&DaemonConfig{Enabled: true, BridgeName: "br-pxe", WebhookEnabled: true}).ToServiceConfig(plan)
		require.Error(t, err)
		assert.Nil(t, cfg)
		assert.True(t, errors.Is(err, ErrInvalidConfig), "webhook without a secret: %v", err)
	})

	t.Run("enabled section without a network plan", func(t *testing.T) {
		cfg, err := (&DaemonConfig{Enabled: true, BridgeName: "br-pxe"}).ToServiceConfig(nil)
		assert.Nil(t, cfg)
		var want ErrNetworkPlanRequired
		assert.True(t, errors.As(err, &want), "got %v", err)
	})
}
