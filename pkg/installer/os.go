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

package installer

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// NewOSInstaller creates an OS-specific installer
func NewOSInstaller(logger *logging.Logger, config *OSConfig) (OSInstaller, error) {
	if config == nil {
		return nil, ErrInvalidConfig("OS config is required")
	}

	switch config.OS {
	case OSAlpine:
		return newAlpineInstaller(logger, config)
	case OSDebian:
		return newDebianInstaller(logger, config)
	case OSFedora:
		return newFedoraInstaller(logger, config)
	case OSUbuntu:
		return newUbuntuInstaller(logger, config)
	default:
		return nil, ErrInvalidConfig(fmt.Sprintf("unsupported OS: %s", config.OS))
	}
}

// Debian installer stub
type debianInstaller struct {
	config *OSConfig
	logger *logging.Logger
}

func newDebianInstaller(logger *logging.Logger, config *OSConfig) (OSInstaller, error) {
	return &debianInstaller{config: config, logger: logger}, nil
}

func (di *debianInstaller) InstallBase(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Debian installation not yet implemented", nil)
}

func (di *debianInstaller) ConfigureSystem(ctx context.Context, rootPath string, diskInfo *DiskInfo) error {
	return ErrOSInstall("Debian system configuration not yet implemented", nil)
}

func (di *debianInstaller) InstallKernel(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Debian kernel installation not yet implemented", nil)
}

func (di *debianInstaller) SetRootPassword(ctx context.Context, rootPath, password string) error {
	return ErrOSInstall("Debian password setting not yet implemented", nil)
}

func (di *debianInstaller) EnableServices(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Debian service enablement not yet implemented", nil)
}

func (di *debianInstaller) InstallPackages(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Debian package installation not yet implemented", nil)
}

func (di *debianInstaller) ExecutePostInstall(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Debian post-install script execution not yet implemented", nil)
}

func (di *debianInstaller) ConfigureNetwork(ctx context.Context, rootPath string, netConfig *NetworkConfig, plan *netplan.Plan) error {
	return ErrOSInstall("Debian network configuration not yet implemented", nil)
}

func (di *debianInstaller) Name() OperatingSystem {
	return OSDebian
}

// Fedora installer stub
type fedoraInstaller struct {
	config *OSConfig
	logger *logging.Logger
}

func newFedoraInstaller(logger *logging.Logger, config *OSConfig) (OSInstaller, error) {
	return &fedoraInstaller{config: config, logger: logger}, nil
}

func (fi *fedoraInstaller) InstallBase(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Fedora installation not yet implemented", nil)
}

func (fi *fedoraInstaller) ConfigureSystem(ctx context.Context, rootPath string, diskInfo *DiskInfo) error {
	return ErrOSInstall("Fedora system configuration not yet implemented", nil)
}

func (fi *fedoraInstaller) InstallKernel(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Fedora kernel installation not yet implemented", nil)
}

func (fi *fedoraInstaller) SetRootPassword(ctx context.Context, rootPath, password string) error {
	return ErrOSInstall("Fedora password setting not yet implemented", nil)
}

func (fi *fedoraInstaller) EnableServices(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Fedora service enablement not yet implemented", nil)
}

func (fi *fedoraInstaller) InstallPackages(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Fedora package installation not yet implemented", nil)
}

func (fi *fedoraInstaller) ExecutePostInstall(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Fedora post-install script execution not yet implemented", nil)
}

func (fi *fedoraInstaller) ConfigureNetwork(ctx context.Context, rootPath string, netConfig *NetworkConfig, plan *netplan.Plan) error {
	return ErrOSInstall("Fedora network configuration not yet implemented", nil)
}

func (fi *fedoraInstaller) Name() OperatingSystem {
	return OSFedora
}

// Ubuntu installer stub
type ubuntuInstaller struct {
	config *OSConfig
	logger *logging.Logger
}

func newUbuntuInstaller(logger *logging.Logger, config *OSConfig) (OSInstaller, error) {
	return &ubuntuInstaller{config: config, logger: logger}, nil
}

func (ui *ubuntuInstaller) InstallBase(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Ubuntu installation not yet implemented", nil)
}

func (ui *ubuntuInstaller) ConfigureSystem(ctx context.Context, rootPath string, diskInfo *DiskInfo) error {
	return ErrOSInstall("Ubuntu system configuration not yet implemented", nil)
}

func (ui *ubuntuInstaller) InstallKernel(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Ubuntu kernel installation not yet implemented", nil)
}

func (ui *ubuntuInstaller) SetRootPassword(ctx context.Context, rootPath, password string) error {
	return ErrOSInstall("Ubuntu password setting not yet implemented", nil)
}

func (ui *ubuntuInstaller) EnableServices(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Ubuntu service enablement not yet implemented", nil)
}

func (ui *ubuntuInstaller) InstallPackages(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Ubuntu package installation not yet implemented", nil)
}

func (ui *ubuntuInstaller) ExecutePostInstall(ctx context.Context, rootPath string) error {
	return ErrOSInstall("Ubuntu post-install script execution not yet implemented", nil)
}

func (ui *ubuntuInstaller) ConfigureNetwork(ctx context.Context, rootPath string, netConfig *NetworkConfig, plan *netplan.Plan) error {
	return ErrOSInstall("Ubuntu network configuration not yet implemented", nil)
}

func (ui *ubuntuInstaller) Name() OperatingSystem {
	return OSUbuntu
}
