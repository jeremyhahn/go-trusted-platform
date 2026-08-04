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

package uki

import (
	"fmt"
	"io"
	"os"
)

// UKI represents a Unified Kernel Image
// A UKI is a single EFI PE/COFF executable containing:
// - Linux kernel (vmlinuz)
// - Initial ramdisk (initramfs)
// - Kernel command line
// - OS release information
// - EFI stub loader
type UKI struct {
	// Kernel is the Linux kernel image (vmlinuz)
	Kernel io.Reader

	// Initramfs is the initial ramdisk
	Initramfs io.Reader

	// Cmdline is the kernel command line
	Cmdline string

	// OSRelease is the os-release information
	OSRelease string

	// Stub is the EFI stub binary (systemd-boot stub or similar)
	// If nil, the default stub will be used from /usr/lib/systemd/boot/efi/linuxx64.efi.stub
	Stub io.Reader

	// Microcode is optional CPU microcode (intel-ucode.img or amd-ucode.img)
	Microcode io.Reader

	// Splash is optional splash screen image
	Splash io.Reader

	// DeviceTree is optional device tree blob for ARM systems
	DeviceTree io.Reader

	// SBAT is optional UEFI Secure Boot Advanced Targeting metadata
	SBAT string
}

// Section represents a PE/COFF section in the UKI
type Section struct {
	Name string
	Data []byte
}

// UKIBuilder builds Unified Kernel Images
type UKIBuilder interface {
	// Build constructs a UKI and writes it to the output
	Build(uki *UKI, output io.Writer) error

	// BuildFile constructs a UKI and writes it to a file
	BuildFile(uki *UKI, outputPath string) error

	// AddSection adds a custom section to the UKI
	AddSection(name string, data []byte) error

	// SetArchitecture sets the target architecture (x86_64, aarch64, etc.)
	SetArchitecture(arch string) error
}

// UKIParser parses existing Unified Kernel Images
type UKIParser interface {
	// Parse reads a UKI and extracts its components
	Parse(reader io.Reader) (*UKI, error)

	// ParseFile reads a UKI from a file
	ParseFile(path string) (*UKI, error)

	// ExtractSection extracts a specific section by name
	ExtractSection(reader io.Reader, sectionName string) ([]byte, error)

	// ListSections returns all section names in the UKI
	ListSections(reader io.Reader) ([]string, error)
}

// DefaultStubPath is the default location for the systemd-boot EFI stub
const DefaultStubPath = "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"

// Architecture represents CPU architectures supported for UKI
type Architecture string

const (
	ArchX86_64  Architecture = "x86_64"
	ArchAArch64 Architecture = "aarch64"
	ArchARM     Architecture = "arm"
	ArchRISCV64 Architecture = "riscv64"
)

// Validate checks if the UKI configuration is valid
func (u *UKI) Validate() error {
	if u.Kernel == nil {
		return &MessageError{Msg: "kernel is required"}
	}

	if u.Initramfs == nil {
		return &MessageError{Msg: "initramfs is required"}
	}

	if u.Cmdline == "" {
		return &MessageError{Msg: "kernel command line is required"}
	}

	return nil
}

// ReadFile is a helper to create a UKI from file paths
func FromFiles(kernelPath, initramfsPath, cmdline string) (*UKI, error) {
	kernel, err := os.Open(kernelPath)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open kernel", Err: err}
	}

	initramfs, err := os.Open(initramfsPath)
	if err != nil {
		_ = kernel.Close()
		return nil, &WrappedError{Msg: "failed to open initramfs", Err: err}
	}

	return &UKI{
		Kernel:    kernel,
		Initramfs: initramfs,
		Cmdline:   cmdline,
	}, nil
}

// Close closes all open file handles in the UKI
func (u *UKI) Close() error {
	var errs []error

	if closer, ok := u.Kernel.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, &WrappedError{Msg: "failed to close kernel", Err: err})
		}
	}

	if closer, ok := u.Initramfs.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, &WrappedError{Msg: "failed to close initramfs", Err: err})
		}
	}

	if closer, ok := u.Stub.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, &WrappedError{Msg: "failed to close stub", Err: err})
		}
	}

	if closer, ok := u.Microcode.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, &WrappedError{Msg: "failed to close microcode", Err: err})
		}
	}

	if len(errs) > 0 {
		return &MessageError{Msg: fmt.Sprintf("errors closing UKI resources: %v", errs)}
	}

	return nil
}
