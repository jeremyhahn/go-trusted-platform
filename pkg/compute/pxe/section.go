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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// Config is platformd's pxe: section. Enabled, it gives the daemon's PXE
// servicer a real backend (NewConfiguredService): the device registry and
// provisioning state machine every transport serves, and the iPXE server the
// StartService RPC starts. The quarantine and provisioning VLANs come from the
// network plan and the bridge from sdn.ovs.bridge, so the section needs an
// enabled sdn: section. Without the section, or with enabled false, every PXE
// call answers SERVICE_NOT_CONFIGURED.
type Config struct {
	// Enabled builds the PXE backend.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// BindHost is the IP address the iPXE HTTP and TFTP servers bind once
	// started. Empty binds every interface.
	BindHost string `yaml:"bind-host,omitempty" json:"bind-host,omitempty" mapstructure:"bind-host"`

	// HTTPPort is the iPXE HTTP port. Zero selects ipxe.DefaultHTTPPort.
	HTTPPort int `yaml:"http-port,omitempty" json:"http-port,omitempty" mapstructure:"http-port"`

	// TFTPPort is the iPXE TFTP port. Zero selects ipxe.DefaultTFTPPort.
	TFTPPort int `yaml:"tftp-port,omitempty" json:"tftp-port,omitempty" mapstructure:"tftp-port"`

	// LocalFilesDir is the directory the iPXE HTTP server serves local files
	// from. Empty keeps the ipxe default.
	LocalFilesDir string `yaml:"local-files-dir,omitempty" json:"local-files-dir,omitempty" mapstructure:"local-files-dir"`

	// InstallsDir is the directory install-log uploads are written under.
	// Empty keeps the ipxe default.
	InstallsDir string `yaml:"installs-dir,omitempty" json:"installs-dir,omitempty" mapstructure:"installs-dir"`

	// BootEntries are the iPXE boot menu entries. At least one is required.
	BootEntries []ipxe.BootEntry `yaml:"boot-entries" json:"boot-entries" mapstructure:"boot-entries"`
}

// NewConfiguredService builds the PXE service a pxe: section describes on the
// node's network plan and bridge, and initializes it. Initializing validates
// the whole configuration and creates the iPXE server without binding any
// port: the HTTP and TFTP listeners open only when StartService runs.
func NewConfiguredService(ctx context.Context, cfg *Config, plan *netplan.Plan, bridge string, logger *logging.Logger) (Service, error) {
	if cfg == nil {
		return nil, ErrInvalidConfiguration{Field: "pxe", Reason: "configuration is nil"}
	}
	serviceConfig, err := NewServiceConfig(plan)
	if err != nil {
		return nil, err
	}
	serviceConfig.BridgeName = bridge

	ipxeConfig := serviceConfig.IPXEConfig
	ipxeConfig.BindHost = cfg.BindHost
	if cfg.HTTPPort != 0 {
		ipxeConfig.HTTPPort = cfg.HTTPPort
	}
	if cfg.TFTPPort != 0 {
		ipxeConfig.TFTPPort = cfg.TFTPPort
	}
	if cfg.LocalFilesDir != "" {
		ipxeConfig.LocalFilesDir = cfg.LocalFilesDir
	}
	if cfg.InstallsDir != "" {
		ipxeConfig.InstallsDir = cfg.InstallsDir
	}
	ipxeConfig.BootEntries = cfg.BootEntries

	svc := NewService(WithLogger(logger))
	if err := svc.Initialize(ctx, serviceConfig); err != nil {
		return nil, err
	}
	return svc, nil
}
