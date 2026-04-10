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

package ipxe

import (
	"log/slog"
	"strings"
)

// DeviceBootInfo contains the information needed to generate a device-specific boot script.
type DeviceBootInfo struct {
	// MAC is the MAC address of the device.
	MAC string

	// Role is the device role (control-plane, gateway, worker).
	Role string

	// Hostname is the hostname to assign to the device.
	Hostname string

	// KernelURL is the URL to the kernel (vmlinuz).
	KernelURL string

	// InitrdURL is the URL to the initrd (initramfs).
	InitrdURL string

	// ConfigServerURL is the URL for config delivery (platformd address).
	ConfigServerURL string

	// BootstrapStrategy is the bootstrap trust strategy (dane, noise, spki, auto).
	BootstrapStrategy string

	// ExtraKernelArgs contains additional kernel arguments.
	ExtraKernelArgs []string
}

// ScriptGenerator produces per-device iPXE boot scripts.
type ScriptGenerator struct {
	serverAddr string
	logger     *slog.Logger
}

// NewScriptGenerator creates a new ScriptGenerator for the given HTTP server address.
func NewScriptGenerator(serverAddr string, logger *slog.Logger) *ScriptGenerator {
	if logger == nil {
		logger = slog.Default()
	}
	return &ScriptGenerator{
		serverAddr: serverAddr,
		logger:     logger,
	}
}

// GenerateScript produces an iPXE boot script for a specific device.
func (g *ScriptGenerator) GenerateScript(info *DeviceBootInfo) string {
	var sb strings.Builder
	sb.WriteString("#!ipxe\n")

	// Build kernel command with platform arguments
	sb.WriteString("kernel ")
	sb.WriteString(info.KernelURL)

	if info.ConfigServerURL != "" {
		sb.WriteByte(' ')
		sb.WriteString("platform_config=")
		sb.WriteString(info.ConfigServerURL)
	}
	if info.Role != "" {
		sb.WriteByte(' ')
		sb.WriteString("platform_role=")
		sb.WriteString(info.Role)
	}
	if info.Hostname != "" {
		sb.WriteByte(' ')
		sb.WriteString("platform_hostname=")
		sb.WriteString(info.Hostname)
	}
	if info.BootstrapStrategy != "" {
		sb.WriteByte(' ')
		sb.WriteString("bootstrap_strategy=")
		sb.WriteString(info.BootstrapStrategy)
	}
	for _, arg := range info.ExtraKernelArgs {
		sb.WriteByte(' ')
		sb.WriteString(arg)
	}
	sb.WriteByte('\n')

	// Initrd
	sb.WriteString("initrd ")
	sb.WriteString(info.InitrdURL)
	sb.WriteByte('\n')

	// Boot
	sb.WriteString("boot\n")

	g.logger.Debug("generated device boot script",
		"mac", info.MAC,
		"role", info.Role,
		"hostname", info.Hostname,
	)

	return sb.String()
}

// GenerateDefaultMenu produces the fallback boot menu for unknown devices.
func (g *ScriptGenerator) GenerateDefaultMenu(entries []BootEntry) string {
	var sb strings.Builder
	sb.WriteString("#!ipxe\n\n")
	sb.WriteString("menu PXE Boot Menu - Unknown Device\n")
	sb.WriteString("item --gap -- ---------- Available Boot Options ----------\n")

	for _, entry := range entries {
		sb.WriteString("item ")
		sb.WriteString(entry.Name)
		sb.WriteString("    ")
		sb.WriteString(entry.Description)
		sb.WriteByte('\n')
	}

	sb.WriteString("item --gap -- ---------- Utilities ----------\n")
	sb.WriteString("item shell    Drop to iPXE shell\n")
	sb.WriteString("item reboot   Reboot system\n\n")

	if len(entries) > 0 {
		sb.WriteString("choose --timeout 30000 --default ")
		sb.WriteString(entries[0].Name)
		sb.WriteString(" selected || goto shell\n")
	} else {
		sb.WriteString("choose --timeout 30000 selected || goto shell\n")
	}
	sb.WriteString("goto ${selected}\n\n")

	for _, entry := range entries {
		sb.WriteString(":")
		sb.WriteString(entry.Name)
		sb.WriteByte('\n')
		if entry.Kernel != "" {
			sb.WriteString("kernel ")
			sb.WriteString(entry.Kernel)
			if entry.Args != "" {
				sb.WriteByte(' ')
				sb.WriteString(entry.Args)
			}
			sb.WriteByte('\n')
		}
		if entry.Initrd != "" {
			sb.WriteString("initrd ")
			sb.WriteString(entry.Initrd)
			sb.WriteByte('\n')
		}
		sb.WriteString("boot || goto shell\n\n")
	}

	sb.WriteString(":shell\necho Type 'exit' to return to menu\nshell\n\n")
	sb.WriteString(":reboot\nreboot\n")

	g.logger.Debug("generated default boot menu", "entries", len(entries))

	return sb.String()
}
