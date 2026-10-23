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
	"fmt"
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
	// Architecture is the client's iPXE build architecture ("x86_64",
	// "arm64"), when the lookup knows it; the kernel and initrd URLs must
	// be for it.
	Architecture string

	// BootImageURL, when set, is a signed UKI the device boots instead of
	// the kernel and initrd: an installed diskless-nbd node's, read out of
	// its export. It is booted with no arguments, so the command line
	// signed into it is the one it runs.
	BootImageURL string
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
	var args []string
	if info.ConfigServerURL != "" {
		args = append(args, "platform_config="+info.ConfigServerURL)
	}
	if info.Role != "" {
		args = append(args, "platform_role="+info.Role)
	}
	if info.Hostname != "" {
		args = append(args, "platform_hostname="+info.Hostname)
	}
	if info.BootstrapStrategy != "" {
		args = append(args, "bootstrap_strategy="+info.BootstrapStrategy)
	}
	args = append(args, info.ExtraKernelArgs...)

	description := info.Hostname
	if description == "" {
		description = info.MAC
	}
	var sb strings.Builder
	sb.WriteString("#!ipxe\n")
	sb.WriteString(architectureGuard(info.Architecture, "/menu.ipxe"))
	if info.BootImageURL != "" {
		sb.WriteString(bootBlock("", description, info.BootImageURL, "", ""))
	} else {
		sb.WriteString(bootBlock("", description, info.KernelURL, strings.Join(args, " "), info.InitrdURL))
	}

	g.logger.Debug("generated device boot script",
		"mac", info.MAC,
		"role", info.Role,
		"hostname", info.Hostname,
		"architecture", info.Architecture,
	)
	return sb.String()
}

// architectureGuard is the line that keeps a client of another
// architecture from fetching a kernel it cannot run: it chains the menu
// for its own architecture instead. Empty when the entry names none. iPXE
// knows its build architecture as ${buildarch} (x86_64, arm64, i386).
func architectureGuard(architecture, menuURL string) string {
	if architecture == "" {
		return ""
	}
	var sb strings.Builder
	for _, a := range ClientArchitectures(architecture) {
		fmt.Fprintf(&sb, "iseq ${buildarch} %s || ", a)
	}
	fmt.Fprintf(&sb, "chain %s?arch=${buildarch}\n", menuURL)
	return sb.String()
}

// bootMaxAttempts bounds the boot retry loop.
const bootMaxAttempts = 20

// bootBlock renders one boot of kernel + initrd with a bounded retry:
// some iPXE builds (X10 ATEN) intermittently drop the chained initramfs
// fetch, sometimes the kernel's, so kernel + initrd + boot are retried
// rather than dead-ending at the shell on a transient drop. label keeps
// the block's labels unique when a script carries several ("" gives
// boot_retry, boot_failed, boot_giveup).
func bootBlock(label, description, kernelURL, args, initrdURL string) string {
	l := "boot"
	if label != "" {
		l = "boot_" + label
	}
	kernel := "kernel " + kernelURL
	if args != "" {
		kernel += " " + args
	}
	// A UKI carries its own initrd, so it is fetched alone.
	initrd := ""
	if initrdURL != "" {
		initrd = fmt.Sprintf("initrd %s || goto %s_failed\n", initrdURL, l)
	}
	return fmt.Sprintf(`echo Booting %[1]s...
echo
set attempts:int32 0
:%[2]s_retry
inc attempts
echo Boot attempt ${attempts}...
%[3]s || goto %[2]s_failed
%[4]sboot || goto %[2]s_failed
:%[2]s_failed
iseq ${attempts} %[5]d && goto %[2]s_giveup ||
echo Boot fetch failed (attempt ${attempts}); retrying in 3s...
sleep 3
goto %[2]s_retry
:%[2]s_giveup
echo Giving up after ${attempts} attempts; dropping to iPXE shell
shell
`, description, l, kernel, initrd, bootMaxAttempts)
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
