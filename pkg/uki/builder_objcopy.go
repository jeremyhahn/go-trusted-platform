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
	"os/exec"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// objcopyBuilder uses objcopy to build UKIs (proven approach)
type objcopyBuilder struct {
	arch           Architecture
	sections       []Section
	logger         *logging.Logger
	alignmentBytes int
	objcopyPath    string
}

// NewObjcopyBuilder creates a new objcopy-based UKI builder
func NewObjcopyBuilder(logger *logging.Logger) UKIBuilder {
	// Try to find objcopy in PATH (prefer llvm-objcopy, fall back to objcopy)
	objcopyPath := "llvm-objcopy"
	if _, err := exec.LookPath(objcopyPath); err != nil {
		objcopyPath = "objcopy"
		if _, err := exec.LookPath(objcopyPath); err != nil {
			// Try absolute paths as fallback (for initramfs environment)
			absolutePaths := []string{
				"/usr/bin/llvm-objcopy",
				"/usr/bin/objcopy",
			}
			found := false
			for _, absPath := range absolutePaths {
				if _, err := os.Stat(absPath); err == nil {
					objcopyPath = absPath
					found = true
					logger.Debug("[UKI] Using objcopy from absolute path", "path", absPath)
					break
				}
			}
			if !found {
				logger.Warn("[UKI] objcopy not found in PATH or absolute paths, UKI building will fail")
			}
		}
	}

	return &objcopyBuilder{
		arch:           ArchX86_64,
		logger:         logger,
		alignmentBytes: 4096,
		sections:       make([]Section, 0),
		objcopyPath:    objcopyPath,
	}
}

// SetArchitecture sets the target architecture
func (b *objcopyBuilder) SetArchitecture(arch string) error {
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
func (b *objcopyBuilder) AddSection(name string, data []byte) error {
	if len(name) > 8 {
		return &MessageError{Msg: fmt.Sprintf("section name too long (max 8 chars): %s", name)}
	}

	b.sections = append(b.sections, Section{
		Name: name,
		Data: data,
	})

	return nil
}

// Build constructs a UKI using objcopy and writes it to the output
func (b *objcopyBuilder) Build(uki *UKI, output io.Writer) error {
	b.logger.Info("[UKI] Building Unified Kernel Image with objcopy")

	// Validate UKI configuration
	if err := uki.Validate(); err != nil {
		return &WrappedError{Msg: "invalid UKI configuration", Err: err}
	}

	// Create temporary directory for intermediate files
	tmpDir, err := os.MkdirTemp("", "uki-build-*")
	if err != nil {
		return &WrappedError{Msg: "failed to create temp dir", Err: err}
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	b.logger.Debug("[UKI] Using temp directory", "path", tmpDir)

	// Write kernel to temp file
	kernelPath := filepath.Join(tmpDir, "kernel.efi")
	kernelData, err := io.ReadAll(uki.Kernel)
	if err != nil {
		return &WrappedError{Msg: "failed to read kernel", Err: err}
	}
	if err := os.WriteFile(kernelPath, kernelData, 0644); err != nil {
		return &WrappedError{Msg: "failed to write kernel", Err: err}
	}
	b.logger.Debug("[UKI] Kernel written", "size", len(kernelData))

	// Write initramfs to temp file
	initramfsPath := filepath.Join(tmpDir, "initramfs.img")
	initramfsData, err := io.ReadAll(uki.Initramfs)
	if err != nil {
		return &WrappedError{Msg: "failed to read initramfs", Err: err}
	}
	if err := os.WriteFile(initramfsPath, initramfsData, 0644); err != nil {
		return &WrappedError{Msg: "failed to write initramfs", Err: err}
	}
	b.logger.Debug("[UKI] Initramfs written", "size", len(initramfsData))

	// Write cmdline to temp file
	cmdlinePath := filepath.Join(tmpDir, "cmdline.txt")
	cmdlineData := []byte(uki.Cmdline + "\x00")
	if err := os.WriteFile(cmdlinePath, cmdlineData, 0644); err != nil {
		return &WrappedError{Msg: "failed to write cmdline", Err: err}
	}
	b.logger.Debug("[UKI] Cmdline", "cmdline", uki.Cmdline)

	// Write optional os-release
	var osrelPath string
	if uki.OSRelease != "" {
		osrelPath = filepath.Join(tmpDir, "osrel.txt")
		if err := os.WriteFile(osrelPath, []byte(uki.OSRelease), 0644); err != nil {
			return &WrappedError{Msg: "failed to write os-release", Err: err}
		}
		b.logger.Debug("[UKI] OS release included")
	}

	// Write optional microcode
	var microcodePath string
	if uki.Microcode != nil {
		microcodePath = filepath.Join(tmpDir, "microcode.img")
		microcodeData, err := io.ReadAll(uki.Microcode)
		if err != nil {
			return &WrappedError{Msg: "failed to read microcode", Err: err}
		}
		if err := os.WriteFile(microcodePath, microcodeData, 0644); err != nil {
			return &WrappedError{Msg: "failed to write microcode", Err: err}
		}
		b.logger.Debug("[UKI] Microcode written", "size", len(microcodeData))
	}

	// Write optional splash
	var splashPath string
	if uki.Splash != nil {
		splashPath = filepath.Join(tmpDir, "splash.bmp")
		splashData, err := io.ReadAll(uki.Splash)
		if err != nil {
			return &WrappedError{Msg: "failed to read splash", Err: err}
		}
		if err := os.WriteFile(splashPath, splashData, 0644); err != nil {
			return &WrappedError{Msg: "failed to write splash", Err: err}
		}
		b.logger.Debug("[UKI] Splash written", "size", len(splashData))
	}

	// Write optional device tree
	var dtbPath string
	if uki.DeviceTree != nil {
		dtbPath = filepath.Join(tmpDir, "devicetree.dtb")
		dtbData, err := io.ReadAll(uki.DeviceTree)
		if err != nil {
			return &WrappedError{Msg: "failed to read device tree", Err: err}
		}
		if err := os.WriteFile(dtbPath, dtbData, 0644); err != nil {
			return &WrappedError{Msg: "failed to write device tree", Err: err}
		}
		b.logger.Debug("[UKI] Device tree written", "size", len(dtbData))
	}

	// Write optional SBAT
	var sbatPath string
	if uki.SBAT != "" {
		sbatPath = filepath.Join(tmpDir, "sbat.txt")
		if err := os.WriteFile(sbatPath, []byte(uki.SBAT), 0644); err != nil {
			return &WrappedError{Msg: "failed to write SBAT", Err: err}
		}
		b.logger.Debug("[UKI] SBAT included")
	}

	// Build objcopy command
	// Key insight from LLVM analysis: VirtualAddress=0 for data sections!
	// This is critical for the kernel's EFI stub to find the sections
	outputPath := filepath.Join(tmpDir, "output.efi")
	args := []string{}

	// Add sections in UKI order (order matters!)
	if osrelPath != "" {
		args = append(args,
			"--add-section", fmt.Sprintf(".osrel=%s", osrelPath),
			"--change-section-vma", ".osrel=0", // VirtualAddress = 0!
		)
	}

	// Cmdline section
	args = append(args,
		"--add-section", fmt.Sprintf(".cmdline=%s", cmdlinePath),
		"--change-section-vma", ".cmdline=0", // VirtualAddress = 0!
	)

	if microcodePath != "" {
		args = append(args,
			"--add-section", fmt.Sprintf(".ucode=%s", microcodePath),
			"--change-section-vma", ".ucode=0",
		)
	}

	if splashPath != "" {
		args = append(args,
			"--add-section", fmt.Sprintf(".splash=%s", splashPath),
			"--change-section-vma", ".splash=0",
		)
	}

	// Initramfs section
	args = append(args,
		"--add-section", fmt.Sprintf(".initrd=%s", initramfsPath),
		"--change-section-vma", ".initrd=0", // VirtualAddress = 0!
	)

	if dtbPath != "" {
		args = append(args,
			"--add-section", fmt.Sprintf(".dtb=%s", dtbPath),
			"--change-section-vma", ".dtb=0",
		)
	}

	if sbatPath != "" {
		args = append(args,
			"--add-section", fmt.Sprintf(".sbat=%s", sbatPath),
			"--change-section-vma", ".sbat=0",
		)
	}

	// Add custom sections
	for _, section := range b.sections {
		sectionPath := filepath.Join(tmpDir, fmt.Sprintf("custom_%s.bin", section.Name))
		if err := os.WriteFile(sectionPath, section.Data, 0644); err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to write custom section %s", section.Name), Err: err}
		}
		args = append(args,
			"--add-section", fmt.Sprintf("%s=%s", section.Name, sectionPath),
			"--change-section-vma", fmt.Sprintf("%s=0", section.Name),
		)
		b.logger.Debug("[UKI] Custom section added", "name", section.Name, "size", len(section.Data))
	}

	// Add input and output files
	args = append(args, kernelPath, outputPath)

	// Run objcopy
	b.logger.Info("[UKI] Running objcopy", "command", b.objcopyPath, "args", fmt.Sprintf("%v", args))
	cmd := exec.Command(b.objcopyPath, args...)
	if cmdOut, err := cmd.CombinedOutput(); err != nil {
		b.logger.Errorf("[UKI] objcopy failed: %s\nOutput: %s", err, string(cmdOut))
		return &CommandOutputError{Msg: "objcopy failed", Err: err, Detail: "\nOutput: " + string(cmdOut)}
	}

	// Read the output UKI
	ukiData, err := os.ReadFile(outputPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read output UKI", Err: err}
	}

	// Write to output
	if _, err := output.Write(ukiData); err != nil {
		return &WrappedError{Msg: "failed to write UKI", Err: err}
	}

	b.logger.Info("[UKI] UKI built successfully with objcopy",
		"size", len(ukiData),
		"sections_added", len(args)/3)

	return nil
}

// BuildFile constructs a UKI and writes it to a file
func (b *objcopyBuilder) BuildFile(uki *UKI, outputPath string) error {
	b.logger.Info("[UKI] Building UKI to file with objcopy", "output", outputPath)

	file, err := os.Create(outputPath)
	if err != nil {
		return &WrappedError{Msg: "failed to create output file", Err: err}
	}
	defer func() { _ = file.Close() }()

	if err := b.Build(uki, file); err != nil {
		_ = os.Remove(outputPath)
		return err
	}

	// Make executable
	if err := os.Chmod(outputPath, 0755); err != nil {
		return &WrappedError{Msg: "failed to set executable permissions", Err: err}
	}

	b.logger.Info("[UKI] UKI written to file", "path", outputPath)
	return nil
}
