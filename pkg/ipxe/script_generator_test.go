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
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestScriptGenerator(t *testing.T) *ScriptGenerator {
	t.Helper()
	return NewScriptGenerator("172.16.7.1:8080", slog.Default())
}

func TestNewScriptGenerator(t *testing.T) {
	gen := NewScriptGenerator("172.16.7.1:8080", slog.Default())
	require.NotNil(t, gen)
	assert.Equal(t, "172.16.7.1:8080", gen.serverAddr)
}

func TestNewScriptGenerator_NilLogger(t *testing.T) {
	gen := NewScriptGenerator("172.16.7.1:8080", nil)
	require.NotNil(t, gen)
	assert.NotNil(t, gen.logger)
}

func TestGenerateScript_Gateway(t *testing.T) {
	gen := newTestScriptGenerator(t)

	info := &DeviceBootInfo{
		MAC:               "52:54:00:aa:bb:cc",
		Role:              "gateway",
		Hostname:          "gw-01",
		KernelURL:         "http://172.16.7.1:8080/files/vmlinuz",
		InitrdURL:         "http://172.16.7.1:8080/files/initramfs",
		ConfigServerURL:   "https://platformd:8443",
		BootstrapStrategy: "dane",
	}

	script := gen.GenerateScript(info)

	assert.True(t, strings.HasPrefix(script, "#!ipxe\n"))
	assert.Contains(t, script, "kernel http://172.16.7.1:8080/files/vmlinuz")
	assert.Contains(t, script, "platform_config=https://platformd:8443")
	assert.Contains(t, script, "platform_role=gateway")
	assert.Contains(t, script, "platform_hostname=gw-01")
	assert.Contains(t, script, "bootstrap_strategy=dane")
	assert.Contains(t, script, "initrd http://172.16.7.1:8080/files/initramfs")
	assert.Contains(t, script, "boot")
}

func TestGenerateScript_ControlPlane(t *testing.T) {
	gen := newTestScriptGenerator(t)

	info := &DeviceBootInfo{
		MAC:               "52:54:00:11:22:33",
		Role:              "control-plane",
		Hostname:          "cp-01",
		KernelURL:         "http://172.16.7.1:8080/files/vmlinuz",
		InitrdURL:         "http://172.16.7.1:8080/files/initramfs",
		ConfigServerURL:   "https://platformd:8443",
		BootstrapStrategy: "spki",
	}

	script := gen.GenerateScript(info)

	assert.True(t, strings.HasPrefix(script, "#!ipxe\n"))
	assert.Contains(t, script, "platform_role=control-plane")
	assert.Contains(t, script, "platform_hostname=cp-01")
	assert.Contains(t, script, "bootstrap_strategy=spki")
}

func TestGenerateScript_Worker(t *testing.T) {
	gen := newTestScriptGenerator(t)

	info := &DeviceBootInfo{
		MAC:               "52:54:00:dd:ee:ff",
		Role:              "worker",
		Hostname:          "worker-01",
		KernelURL:         "http://172.16.7.1:8080/files/vmlinuz",
		InitrdURL:         "http://172.16.7.1:8080/files/initramfs",
		ConfigServerURL:   "https://platformd:8443",
		BootstrapStrategy: "auto",
	}

	script := gen.GenerateScript(info)

	assert.True(t, strings.HasPrefix(script, "#!ipxe\n"))
	assert.Contains(t, script, "platform_role=worker")
	assert.Contains(t, script, "platform_hostname=worker-01")
	assert.Contains(t, script, "bootstrap_strategy=auto")
}

func TestGenerateScript_ExtraArgs(t *testing.T) {
	gen := newTestScriptGenerator(t)

	info := &DeviceBootInfo{
		MAC:             "52:54:00:aa:bb:cc",
		Role:            "gateway",
		Hostname:        "gw-02",
		KernelURL:       "http://172.16.7.1:8080/files/vmlinuz",
		InitrdURL:       "http://172.16.7.1:8080/files/initramfs",
		ConfigServerURL: "https://platformd:8443",
		ExtraKernelArgs: []string{
			"console=ttyS0,115200",
			"debug=1",
			"quiet",
		},
	}

	script := gen.GenerateScript(info)

	assert.Contains(t, script, "console=ttyS0,115200")
	assert.Contains(t, script, "debug=1")
	assert.Contains(t, script, "quiet")

	// Verify all extra args appear on the kernel line
	lines := strings.Split(script, "\n")
	var kernelLine string
	for _, line := range lines {
		if strings.HasPrefix(line, "kernel ") {
			kernelLine = line
			break
		}
	}
	require.NotEmpty(t, kernelLine, "should have a kernel line")
	assert.Contains(t, kernelLine, "console=ttyS0,115200")
	assert.Contains(t, kernelLine, "debug=1")
	assert.Contains(t, kernelLine, "quiet")
}

func TestGenerateScript_MinimalInfo(t *testing.T) {
	gen := newTestScriptGenerator(t)

	info := &DeviceBootInfo{
		MAC:       "52:54:00:00:00:01",
		KernelURL: "http://172.16.7.1:8080/files/vmlinuz",
		InitrdURL: "http://172.16.7.1:8080/files/initramfs",
	}

	script := gen.GenerateScript(info)

	assert.True(t, strings.HasPrefix(script, "#!ipxe\n"))
	assert.Contains(t, script, "kernel http://172.16.7.1:8080/files/vmlinuz || goto boot_failed\n", "no arguments after the URL")
	assert.NotContains(t, script, "platform_config=")
	assert.NotContains(t, script, "platform_role=")
	assert.NotContains(t, script, "platform_hostname=")
	assert.NotContains(t, script, "bootstrap_strategy=")
}

func TestGenerateDefaultMenu(t *testing.T) {
	gen := newTestScriptGenerator(t)

	entries := []BootEntry{
		{
			Name:        "alpine",
			Description: "Alpine Linux 3.20",
			Kernel:      "http://172.16.7.1:8080/files/vmlinuz",
			Initrd:      "http://172.16.7.1:8080/files/initramfs",
			Args:        "alpine_start=autoinstall",
		},
		{
			Name:        "rescue",
			Description: "Rescue Shell",
			Kernel:      "http://172.16.7.1:8080/files/rescue-vmlinuz",
			Initrd:      "http://172.16.7.1:8080/files/rescue-initramfs",
		},
	}

	menu := gen.GenerateDefaultMenu(entries)

	assert.True(t, strings.HasPrefix(menu, "#!ipxe\n"))
	assert.Contains(t, menu, "menu PXE Boot Menu - Unknown Device")
	assert.Contains(t, menu, "item alpine")
	assert.Contains(t, menu, "Alpine Linux 3.20")
	assert.Contains(t, menu, "item rescue")
	assert.Contains(t, menu, "Rescue Shell")
	assert.Contains(t, menu, "--default alpine")
	assert.Contains(t, menu, ":alpine")
	assert.Contains(t, menu, ":rescue")
	assert.Contains(t, menu, "kernel http://172.16.7.1:8080/files/vmlinuz alpine_start=autoinstall")
	assert.Contains(t, menu, ":shell")
	assert.Contains(t, menu, ":reboot")
}

func TestGenerateDefaultMenu_Empty(t *testing.T) {
	gen := newTestScriptGenerator(t)

	menu := gen.GenerateDefaultMenu(nil)

	assert.True(t, strings.HasPrefix(menu, "#!ipxe\n"))
	assert.Contains(t, menu, "menu PXE Boot Menu - Unknown Device")
	assert.Contains(t, menu, ":shell")
	assert.Contains(t, menu, ":reboot")
	// No default entry since there are no entries
	assert.NotContains(t, menu, "--default")
}

func TestGenerateScript_RetriesAndGuardsItsArchitecture(t *testing.T) {
	gen := NewScriptGenerator("http://10.99.99.1:8080", logging.DefaultLogger().Slog())
	script := gen.GenerateScript(&DeviceBootInfo{
		MAC: "dc:a6:32:01:36:c2", Hostname: "pi-01", Architecture: ArchitectureARM64,
		KernelURL: "http://10.99.99.1:8080/data/media/aarch64-rpi/vmlinuz", InitrdURL: "http://10.99.99.1:8080/data/media/aarch64-rpi/initramfs",
	})
	assert.Contains(t, script, "iseq ${buildarch} arm64 || chain /menu.ipxe?arch=${buildarch}\n", "an x86 client never fetches the arm64 kernel")
	assert.Less(t, strings.Index(script, "iseq ${buildarch}"), strings.Index(script, "kernel "))
	assert.Contains(t, script, ":boot_retry", "the device script retries like /boot.ipxe does")
	assert.Contains(t, script, "iseq ${attempts} 20 && goto boot_giveup")
	assert.Contains(t, script, "echo Booting pi-01...")
}

// TestGenerateScript_BootsAnInstalledUKI: a device with a boot image boots it
// alone, with no argument and no initrd, so only its signed command line runs,
// and keeps the architecture guard and the retry loop.
func TestGenerateScript_BootsAnInstalledUKI(t *testing.T) {
	gen := NewScriptGenerator("http://10.99.99.1:8080", logging.DefaultLogger().Slog())
	script := gen.GenerateScript(&DeviceBootInfo{
		MAC: "dc:a6:32:01:36:c2", Hostname: "pi-01", Role: "worker", Architecture: ArchitectureARM64,
		KernelURL:       "http://10.99.99.1:8080/data/media/aarch64-rpi/vmlinuz",
		InitrdURL:       "http://10.99.99.1:8080/data/media/aarch64-rpi/initramfs",
		ExtraKernelArgs: []string{"alpine_start=autoinstall platform_boot_model=diskless-nbd"},
		BootImageURL:    "http://10.99.99.1:8080/boot/uki/dc:a6:32:01:36:c2.efi",
	})
	assert.Contains(t, script, "kernel http://10.99.99.1:8080/boot/uki/dc:a6:32:01:36:c2.efi || goto boot_failed\nboot || goto boot_failed\n")
	assert.NotContains(t, script, "initrd ")
	assert.NotContains(t, script, "vmlinuz")
	assert.NotContains(t, script, "platform_", "no argument reaches the UKI")
	assert.Contains(t, script, "iseq ${buildarch} arm64 || chain /menu.ipxe?arch=${buildarch}\n")
	assert.Contains(t, script, "iseq ${attempts} 20 && goto boot_giveup")
}

// TestGenerateScript_WithoutABootImageFetchesTheInitrd: the installer path is
// unchanged, the initrd fetched between the kernel and the boot.
func TestGenerateScript_WithoutABootImageFetchesTheInitrd(t *testing.T) {
	gen := NewScriptGenerator("http://10.99.99.1:8080", logging.DefaultLogger().Slog())
	script := gen.GenerateScript(&DeviceBootInfo{
		MAC: "dc:a6:32:01:36:c2", Hostname: "pi-01",
		KernelURL: "http://10.99.99.1:8080/vmlinuz", InitrdURL: "http://10.99.99.1:8080/initramfs",
	})
	assert.Contains(t, script, "kernel http://10.99.99.1:8080/vmlinuz platform_hostname=pi-01 || goto boot_failed\n"+
		"initrd http://10.99.99.1:8080/initramfs || goto boot_failed\nboot || goto boot_failed\n")
}
