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

// parser implements the UKIParser interface
type parser struct {
	logger *logging.Logger
}

// NewParser creates a new UKI parser
func NewParser(logger *logging.Logger) UKIParser {
	return &parser{
		logger: logger,
	}
}

// Parse reads a UKI and extracts its components
func (p *parser) Parse(reader io.Reader) (*UKI, error) {
	p.logger.Info("[UKI-PARSER] Parsing Unified Kernel Image")

	// Read entire UKI into memory
	ukiData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read UKI: %w", err)
	}

	// Parse as PE file
	peFile, err := pe.NewFile(bytes.NewReader(ukiData))
	if err != nil {
		return nil, fmt.Errorf("invalid PE file: %w", err)
	}
	defer func() { _ = peFile.Close() }()

	uki := &UKI{}

	// Extract sections
	for _, section := range peFile.Sections {
		sectionName := trimNullBytes(section.Name)
		p.logger.Debug("[UKI-PARSER] Found section", "name", sectionName, "size", section.Size)

		data, err := section.Data()
		if err != nil {
			p.logger.Warn("Failed to read section", "name", sectionName, "error", err)
			continue
		}

		switch sectionName {
		case ".linux":
			uki.Kernel = bytes.NewReader(data)
			p.logger.Info("[UKI-PARSER] Kernel extracted", "size", len(data))

		case ".initrd":
			uki.Initramfs = bytes.NewReader(data)
			p.logger.Info("[UKI-PARSER] Initramfs extracted", "size", len(data))

		case ".cmdline":
			// Remove null terminator
			cmdline := string(bytes.TrimRight(data, "\x00"))
			uki.Cmdline = cmdline
			p.logger.Info("[UKI-PARSER] Cmdline extracted", "cmdline", cmdline)

		case ".osrel":
			uki.OSRelease = string(data)
			p.logger.Info("[UKI-PARSER] OS release extracted")

		case ".ucode":
			uki.Microcode = bytes.NewReader(data)
			p.logger.Info("[UKI-PARSER] Microcode extracted", "size", len(data))

		case ".splash":
			uki.Splash = bytes.NewReader(data)
			p.logger.Info("[UKI-PARSER] Splash image extracted", "size", len(data))

		case ".dtb":
			uki.DeviceTree = bytes.NewReader(data)
			p.logger.Info("[UKI-PARSER] Device tree extracted", "size", len(data))

		case ".sbat":
			uki.SBAT = string(data)
			p.logger.Info("[UKI-PARSER] SBAT metadata extracted")

		default:
			p.logger.Debug("[UKI-PARSER] Unknown section", "name", sectionName)
		}
	}

	// Validate extracted UKI
	if uki.Kernel == nil {
		return nil, fmt.Errorf("UKI missing required .linux section")
	}
	if uki.Initramfs == nil {
		return nil, fmt.Errorf("UKI missing required .initrd section")
	}
	if uki.Cmdline == "" {
		return nil, fmt.Errorf("UKI missing required .cmdline section")
	}

	p.logger.Info("[UKI-PARSER] UKI parsed successfully")
	return uki, nil
}

// ParseFile reads a UKI from a file
func (p *parser) ParseFile(path string) (*UKI, error) {
	p.logger.Info("[UKI-PARSER] Parsing UKI from file", "path", path)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	return p.Parse(file)
}

// ExtractSection extracts a specific section by name
func (p *parser) ExtractSection(reader io.Reader, sectionName string) ([]byte, error) {
	p.logger.Info("[UKI-PARSER] Extracting section", "name", sectionName)

	// Read entire UKI into memory
	ukiData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read UKI: %w", err)
	}

	// Parse as PE file
	peFile, err := pe.NewFile(bytes.NewReader(ukiData))
	if err != nil {
		return nil, fmt.Errorf("invalid PE file: %w", err)
	}
	defer func() { _ = peFile.Close() }()

	// Find and extract section
	for _, section := range peFile.Sections {
		name := trimNullBytes(section.Name)
		if name == sectionName {
			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("failed to read section: %w", err)
			}
			p.logger.Info("[UKI-PARSER] Section extracted", "name", sectionName, "size", len(data))
			return data, nil
		}
	}

	return nil, fmt.Errorf("section not found: %s", sectionName)
}

// ListSections returns all section names in the UKI
func (p *parser) ListSections(reader io.Reader) ([]string, error) {
	p.logger.Info("[UKI-PARSER] Listing sections")

	// Read entire UKI into memory
	ukiData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read UKI: %w", err)
	}

	// Parse as PE file
	peFile, err := pe.NewFile(bytes.NewReader(ukiData))
	if err != nil {
		return nil, fmt.Errorf("invalid PE file: %w", err)
	}
	defer func() { _ = peFile.Close() }()

	// Extract section names
	sections := make([]string, 0, len(peFile.Sections))
	for _, section := range peFile.Sections {
		name := trimNullBytes(section.Name)
		sections = append(sections, name)
		p.logger.Debug("[UKI-PARSER] Section", "name", name, "size", section.Size)
	}

	p.logger.Info("[UKI-PARSER] Section listing complete", "count", len(sections))
	return sections, nil
}

// trimNullBytes removes null bytes from strings
func trimNullBytes(s string) string {
	return string(bytes.TrimRight([]byte(s), "\x00"))
}
