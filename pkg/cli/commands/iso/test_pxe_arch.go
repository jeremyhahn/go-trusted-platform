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

package iso

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// Defaults for the aarch64 PXE test: the U-Boot the U-Boot builder emits
// for the QEMU virt machine and the Secure Boot key set it was preseeded
// with. Both are what `make image-rpi-qemu` uses, so the netboot test
// boots the same firmware as the factory image.
const (
	DefaultPXEUBoot    = "build/docker/uboot-builder/output/qemu_arm64/u-boot.bin"
	DefaultPXEIPXE     = "build/docker/ipxe-builder/output/bin-arm64-efi/snponly.efi"
	DefaultPXEKeysDir  = "~/.trusted-platform/secure-boot"
	pxeDownloadTimeout = 5 * time.Minute
)

// pxeArchitecture is what the PXE test needs that differs by guest
// architecture.
type pxeArchitecture struct {
	// qemu is the guest architecture.
	qemu qemu.Arch
	// firmware is the firmware image QEMU boots (U-Boot on aarch64; empty
	// on x86_64, which uses OVMF through the profile).
	firmware string
	// entryArch is the iPXE ${buildarch} the boot entry is restricted to.
	entryArch string
	// signer signs what a Secure Boot client verifies: the served iPXE
	// binary (through the PXE server) and the kernel (through signKernel).
	// nil on x86_64 without --secure-boot.
	signer authenticode.Authenticode
	// firmwareOverrides are the platform-built iPXE binaries served in
	// place of upstream's (ServerConfig.FirmwareOverrides). On aarch64
	// that is the whole point: upstream's arm64 iPXE naps in WFI, which
	// U-Boot's EFI never wakes, so it hangs at its own banner.
	firmwareOverrides map[string]string
}

// preparePXEArchitecture resolves the architecture-specific inputs from
// the flags. On aarch64 the client is U-Boot with the platform's db
// preseeded, so everything it loads must be signed with that db key: the
// keys directory is required, and the signer built from it is handed to
// the PXE server for iPXE and used here for the kernel.
func preparePXEArchitecture(ctx context.Context, logger *logging.Logger) (*pxeArchitecture, error) {
	switch strings.ToLower(pxeArchitectureFlag) {
	case "", "x86_64", "amd64":
		x86 := pxeArchitectureX86()
		return &x86, nil
	case "aarch64", "arm64":
		firmware := pxeUBoot
		if firmware == "" {
			firmware = DefaultPXEUBoot
		}
		if _, err := os.Stat(firmware); err != nil {
			return nil, &WrappedError{Msg: "aarch64 PXE needs the qemu_arm64 U-Boot (make uboot-build); --uboot", Err: err}
		}
		ipxeBinary := pxeIPXE
		if ipxeBinary == "" {
			ipxeBinary = DefaultPXEIPXE
		}
		if _, err := os.Stat(ipxeBinary); err != nil {
			return nil, &WrappedError{Msg: "aarch64 PXE needs the platform-built arm64 iPXE (make ipxe-build); --ipxe", Err: err}
		}
		keysDir := expandHome(pxeKeysDir)
		if keysDir == "" {
			keysDir = expandHome(DefaultPXEKeysDir)
		}
		signer, err := authenticode.NewFileSigner(ctx, filepath.Join(keysDir, "DB.key"), filepath.Join(keysDir, "DB.crt"), logger)
		if err != nil {
			return nil, &WrappedError{Msg: "aarch64 PXE needs the Secure Boot db key U-Boot was preseeded with; --keys-dir", Err: err}
		}
		return &pxeArchitecture{
			qemu:              qemu.ArchAArch64,
			firmware:          firmware,
			entryArch:         ipxe.ArchitectureARM64,
			signer:            signer,
			firmwareOverrides: map[string]string{ipxe.FirmwareSNPOnlyAArch64: ipxeBinary},
		}, nil
	default:
		return nil, &MessageError{Msg: "unsupported --architecture " + pxeArchitectureFlag + " (x86_64 or aarch64)"}
	}
}

// pxeArchitectureX86 is the x86_64 test as it has always run: OVMF
// through the QEMU profile, no signing (Secure Boot is --secure-boot with
// enrolled keys, and the kernel is trusted by the enrolled db).
func pxeArchitectureX86() pxeArchitecture {
	return pxeArchitecture{qemu: qemu.ArchX86_64, entryArch: ipxe.ArchitectureX86_64}
}

// expandHome replaces a leading ~ with the home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// localizeKernel makes a boot entry's kernel a local, signed PE image for a
// Secure Boot client. A kernel URL is downloaded first; a gzip-compressed
// vmlinuz (Alpine's aarch64 kernels) is decompressed, because the
// firmware verifies and executes the PE image inside; the result is
// Authenticode-signed with the db key and the entry's kernel becomes that
// file. Without a signer the entry is returned as it was.
func (a *pxeArchitecture) localizeKernel(ctx context.Context, logger *logging.Logger, entry ipxe.BootEntry, workDir string) (ipxe.BootEntry, error) {
	entry.Architecture = a.entryArch
	if a.signer == nil {
		return entry, nil
	}
	src := strings.TrimPrefix(entry.Kernel, "file://")
	if strings.HasPrefix(entry.Kernel, "http://") || strings.HasPrefix(entry.Kernel, "https://") {
		downloaded := filepath.Join(workDir, "kernel.download")
		logger.Info("Downloading the kernel so it can be signed", "url", entry.Kernel)
		if err := fetchToFile(ctx, entry.Kernel, downloaded); err != nil {
			return entry, &WrappedError{Msg: "downloading the kernel", Err: err}
		}
		src = downloaded
	}

	signed := filepath.Join(workDir, "kernel.signed.efi")
	if err := uki.SignKernel(src, signed, a.signer); err != nil {
		return entry, &WrappedError{Msg: "signing the kernel for the Secure Boot client", Err: err}
	}
	logger.Info("Kernel signed for the Secure Boot client", "kernel", signed)
	entry.Kernel = "file://" + signed
	return entry, nil
}

// fetchToFile downloads url to path.
func fetchToFile(ctx context.Context, url, path string) error {
	ctx, cancel := context.WithTimeout(ctx, pxeDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &MessageError{Msg: fmt.Sprintf("GET %s: %s", url, resp.Status)}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
