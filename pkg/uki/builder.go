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
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// builder implements the UKIBuilder interface
type builder struct {
	arch           Architecture
	sections       []Section
	logger         *logging.Logger
	stubPath       string
	alignmentBytes int
}

// NewBuilder creates a new UKI builder
func NewBuilder(logger *logging.Logger) UKIBuilder {
	arch := HostArchitecture()
	stubPath, err := StubPath(arch)
	if err != nil {
		// HostArchitecture only yields architectures StubPath knows.
		stubPath = DefaultStubPath
	}
	return &builder{
		arch:           arch,
		logger:         logger,
		stubPath:       stubPath,
		alignmentBytes: 4096, // Standard PE section alignment
		sections:       make([]Section, 0),
	}
}

// SetArchitecture sets the target architecture
func (b *builder) SetArchitecture(arch string) error {
	archType := Architecture(arch)

	switch archType {
	case ArchX86_64, ArchAArch64, ArchARM, ArchRISCV64:
		b.arch = archType
		return nil
	default:
		return &MessageError{Msg: fmt.Sprintf("unsupported architecture: %s", arch)}
	}
}

// AddSection adds a custom section to the UKI
func (b *builder) AddSection(name string, data []byte) error {
	if len(name) > 8 {
		return &MessageError{Msg: fmt.Sprintf("section name too long (max 8 chars): %s", name)}
	}

	b.sections = append(b.sections, Section{
		Name: name,
		Data: data,
	})

	return nil
}

// Build constructs a UKI and writes it to the output
func (b *builder) Build(uki *UKI, output io.Writer) error {
	b.logger.Info("[UKI] Building Unified Kernel Image")

	// Validate UKI configuration
	if err := uki.Validate(); err != nil {
		return &WrappedError{Msg: "invalid UKI configuration", Err: err}
	}

	// Load EFI stub (use kernel as base since it has built-in EFI stub)
	stub, err := b.loadStub(uki)
	if err != nil {
		return &WrappedError{Msg: "failed to load EFI stub", Err: err}
	}
	b.logger.Info("[UKI] Kernel loaded as base PE", "size", len(stub))

	// Parse the stub as PE file
	peFile, err := pe.NewFile(bytes.NewReader(stub))
	if err != nil {
		return &WrappedError{Msg: "failed to parse kernel as PE", Err: err}
	}
	defer func() { _ = peFile.Close() }()

	// Read all required components
	sections := make(map[string][]byte)

	// Read the kernel — systemd-stub uses the .linux section to locate and
	// boot the kernel image. The stub is the base PE, not the kernel.
	kernelData, err := io.ReadAll(uki.Kernel)
	if err != nil {
		return &WrappedError{Msg: "failed to read kernel", Err: err}
	}
	sections[".linux"] = kernelData
	b.logger.Info("[UKI] Kernel loaded", "size", len(kernelData))

	// Read initramfs
	initramfsData, err := io.ReadAll(uki.Initramfs)
	if err != nil {
		return &WrappedError{Msg: "failed to read initramfs", Err: err}
	}
	sections[".initrd"] = initramfsData
	b.logger.Info("[UKI] Initramfs loaded", "size", len(initramfsData))

	// Kernel command line
	cmdlineData := []byte(uki.Cmdline + "\x00")
	sections[".cmdline"] = cmdlineData
	b.logger.Info("[UKI] Command line", "cmdline", uki.Cmdline)

	// OS release
	if uki.OSRelease != "" {
		sections[".osrel"] = []byte(uki.OSRelease)
		b.logger.Info("[UKI] OS release included")
	}

	// Optional microcode
	if uki.Microcode != nil {
		microcodeData, err := io.ReadAll(uki.Microcode)
		if err != nil {
			return &WrappedError{Msg: "failed to read microcode", Err: err}
		}
		sections[".ucode"] = microcodeData
		b.logger.Info("[UKI] Microcode loaded", "size", len(microcodeData))
	}

	// Optional splash
	if uki.Splash != nil {
		splashData, err := io.ReadAll(uki.Splash)
		if err != nil {
			return &WrappedError{Msg: "failed to read splash", Err: err}
		}
		sections[".splash"] = splashData
		b.logger.Info("[UKI] Splash image loaded", "size", len(splashData))
	}

	// Optional device tree
	if uki.DeviceTree != nil {
		dtbData, err := io.ReadAll(uki.DeviceTree)
		if err != nil {
			return &WrappedError{Msg: "failed to read device tree", Err: err}
		}
		sections[".dtb"] = dtbData
		b.logger.Info("[UKI] Device tree loaded", "size", len(dtbData))
	}

	// Optional SBAT
	if uki.SBAT != "" {
		sections[".sbat"] = []byte(uki.SBAT)
		b.logger.Info("[UKI] SBAT metadata included")
	}

	// Add custom sections
	for _, section := range b.sections {
		sections[section.Name] = section.Data
		b.logger.Info("[UKI] Custom section added", "name", section.Name, "size", len(section.Data))
	}

	// Build the UKI by appending sections to stub
	if err := b.buildPE(stub, sections, output); err != nil {
		return &WrappedError{Msg: "failed to build PE", Err: err}
	}

	b.logger.Info("[UKI] UKI built successfully")
	return nil
}

// BuildFile constructs a UKI and writes it to a file
func (b *builder) BuildFile(uki *UKI, outputPath string) error {
	b.logger.Info("[UKI] Building UKI to file", "output", outputPath)

	file, err := os.Create(outputPath)
	if err != nil {
		return &WrappedError{Msg: "failed to create output file", Err: err}
	}

	if err := b.Build(uki, file); err != nil {
		file.Close()
		_ = os.Remove(outputPath)
		return err
	}

	// CRITICAL: fsync the UKI file to ensure all data is flushed to disk.
	// FAT32 on real SATA SSDs can lose data without explicit fsync.
	if err := file.Sync(); err != nil {
		file.Close()
		return &WrappedError{Msg: "failed to sync UKI file to disk", Err: err}
	}
	file.Close()

	// Make executable
	if err := os.Chmod(outputPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	b.logger.Info("[UKI] UKI written to file", "path", outputPath)
	return nil
}

// loadStub loads the EFI stub binary (systemd-stub).
// systemd-stub is the PE base that reads .cmdline, .linux, and .initrd
// sections and passes them to the kernel. The Linux kernel's own EFI stub
// (CONFIG_EFI_STUB) does NOT read PE sections — it only reads LoadOptions
// from EFI_LOADED_IMAGE_PROTOCOL. Without systemd-stub, the kernel boots
// with no command line and no initrd, causing a silent hang.
func (b *builder) loadStub(uki *UKI) ([]byte, error) {
	if uki.Stub != nil {
		return io.ReadAll(uki.Stub)
	}

	// Load systemd-stub from the default path
	stubData, err := os.ReadFile(b.stubPath)
	if err != nil {
		return nil, &CommandOutputError{Msg: fmt.Sprintf("failed to read EFI stub at %s", b.stubPath), Err: err, Detail: " (install systemd-efistub package)"}
	}
	return stubData, nil
}

// buildPE constructs the PE file by properly adding sections with header updates
func (b *builder) buildPE(stub []byte, sections map[string][]byte, output io.Writer) error {
	// Parse the PE file from the stub
	b.logger.Debug("[UKI] Parsing EFI stub PE file")
	patcher, err := newPEPatcher(stub)
	if err != nil {
		return &WrappedError{Msg: "failed to parse PE stub", Err: err}
	}

	b.logger.Debug("[UKI] EFI stub parsed",
		"existing_sections", patcher.numberOfSections,
		"size_of_image", patcher.sizeOfImage)

	// Section order matters for UKI
	sectionOrder := []string{
		".osrel",   // OS release
		".cmdline", // Kernel command line
		".ucode",   // CPU microcode
		".splash",  // Splash screen
		".linux",   // Kernel
		".initrd",  // Initramfs
		".dtb",     // Device tree
		".sbat",    // SBAT metadata
	}

	// Section characteristics for UKI data sections (.cmdline, .initrd, etc.)
	// IMAGE_SCN_CNT_INITIALIZED_DATA (0x00000040) | IMAGE_SCN_MEM_READ (0x40000000)
	// Note: IMAGE_SCN_ALIGN_1BYTES (0x00100000) is for object files only, not PE
	// executables. Including it causes some UEFI PE loaders to reject the image.
	const sectionCharacteristics = 0x40000040

	// Add sections in order
	addedCount := 0
	for _, name := range sectionOrder {
		data, exists := sections[name]
		if !exists {
			continue
		}

		b.logger.Debug("[UKI] Adding section", "name", name, "size", len(data))

		if err := patcher.addSection(name, data, sectionCharacteristics); err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to add section %s", name), Err: err}
		}

		addedCount++
	}

	// Add any remaining custom sections
	for name, data := range sections {
		found := false
		for _, n := range sectionOrder {
			if n == name {
				found = true
				break
			}
		}
		if found {
			continue
		}

		b.logger.Debug("[UKI] Adding custom section", "name", name, "size", len(data))

		if err := patcher.addSection(name, data, sectionCharacteristics); err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to add custom section %s", name), Err: err}
		}

		addedCount++
	}

	// Write the patched PE file
	b.logger.Debug("[UKI] Writing PE file with updated headers",
		"total_sections", patcher.numberOfSections,
		"size_of_image", patcher.sizeOfImage)

	ukiData := patcher.bytes()

	if _, err := output.Write(ukiData); err != nil {
		return &WrappedError{Msg: "failed to write UKI", Err: err}
	}

	b.logger.Info("[UKI] PE construction complete",
		"total_size", len(ukiData),
		"sections_added", addedCount,
		"total_sections", patcher.numberOfSections)

	return nil
}
