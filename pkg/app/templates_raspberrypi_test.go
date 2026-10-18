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

package app

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raspberryPiTemplate names a template `diskimage create --model <model>
// --role <role>` builds.
type raspberryPiTemplate struct{ model, role string }

func (p raspberryPiTemplate) path() string {
	return filepath.Join(templateRoot, "dedicated", "raspberrypi", p.model, p.role+".yaml")
}

// The Raspberry Pi templates, each with its board. The hardware model is the
// board name pkg/diskimage/rpi gives the image, so the quirk the installer
// resolves and the template agree.
var raspberryPiTemplates = map[raspberryPiTemplate]string{
	{"rpi4", "compute"}:       "Raspberry Pi 4 Model B",
	{"rpi5", "compute"}:       "Raspberry Pi 5",
	{"cm4", "control-plane"}:  "Raspberry Pi Compute Module 4",
	{"rpi4", "control-plane"}: "Raspberry Pi 4 Model B",
}

func TestRaspberryPiTemplates_LoadAndValidate(t *testing.T) {
	for template, board := range raspberryPiTemplates {
		t.Run(template.model+"/"+template.role, func(t *testing.T) {
			a := loadTemplate(t, template.path())

			require.NotNil(t, a.SDNConfig)
			require.NoError(t, a.SDNConfig.Validate())
			require.NotNil(t, a.NetworkConfig)
			require.NoError(t, a.NetworkConfig.Validate(a.SDNConfig.Plan()))
			require.NoError(t, a.validateHostNetwork())

			assert.Equal(t, installer.HostRole(template.role), a.NetworkConfig.Role)
			assert.Empty(t, a.NetworkConfig.Bonds, "a one-port Pi has no bond")
			require.NotNil(t, a.OSConfig)
			assert.Equal(t, "aarch64", a.OSConfig.Architecture)
			assert.Equal(t, "Raspberry Pi", a.HardwareManufacturer)
			assert.Equal(t, board, a.HardwareModel)
			require.NotNil(t, a.TPMConfig.IDevID)
			assert.Equal(t, board, a.TPMConfig.IDevID.Model)
			assert.Equal(t, []uint{0, 4, 7, 9}, a.SealPCRs, "U-Boot's TCG2 PCRs and the EFI stub's")
		})
	}
}

// A Pi control plane is a standalone one: QuicBaaS on the file backend with
// no Raft peers to join.
func TestRaspberryPiControlPlaneTemplates_Standalone(t *testing.T) {
	for template := range raspberryPiTemplates {
		if template.role != string(installer.HostRoleControlPlane) {
			continue
		}
		t.Run(template.model, func(t *testing.T) {
			a := loadTemplate(t, template.path())
			require.NotNil(t, a.QuicBaaSConfig)
			assert.Equal(t, "file", a.QuicBaaSConfig.StorageBackend)
			assert.Empty(t, a.QuicBaaSConfig.JoinAddresses)
		})
	}
}

// The Pi 5 has one Ethernet port, so the template carries no bond; a bond
// with one member is a configuration the validation refuses.
func TestRaspberryPiComputeTemplates_OneMemberBondRefused(t *testing.T) {
	a := loadTemplate(t, raspberryPiTemplate{"rpi5", "compute"}.path())
	a.NetworkConfig.Bonds = []installer.BondConfig{{Name: "bond0", Mode: "active-backup", Interfaces: []string{"eth0"}}}

	err := a.validateHostNetwork()

	var hostErr ErrHostNetworkValidation
	require.True(t, errors.As(err, &hostErr), "got %v", err)
	var cfgErr *installer.InstallerError
	require.True(t, errors.As(err, &cfgErr), "got %v", err)
	assert.Equal(t, installer.ErrorTypeInvalidConfig, cfgErr.Type)
	assert.Contains(t, cfgErr.Message, "at least two member interfaces")
}
