// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

// PXEPluginName is the name used in CoreDHCP configuration.
const PXEPluginName = "platform-pxe"

// PXE client architecture codes (IANA assigned).
const (
	// PXEArchIntelX86 is Intel x86 BIOS.
	PXEArchIntelX86 uint16 = 0
	// PXEArchNECPC98 is NEC/PC98.
	PXEArchNECPC98 uint16 = 1
	// PXEArchEFIItanium is EFI Itanium.
	PXEArchEFIItanium uint16 = 2
	// PXEArchDECAlpha is DEC Alpha.
	PXEArchDECAlpha uint16 = 3
	// PXEArchArcX86 is Arc x86.
	PXEArchArcX86 uint16 = 4
	// PXEArchIntelLeanClient is Intel Lean Client.
	PXEArchIntelLeanClient uint16 = 5
	// PXEArchEFIIA32 is EFI IA32.
	PXEArchEFIIA32 uint16 = 6
	// PXEArchEFIX8664 is EFI x86-64 (UEFI).
	PXEArchEFIX8664 uint16 = 7
	// PXEArchEFIXscale is EFI Xscale.
	PXEArchEFIXscale uint16 = 8
	// PXEArchEFIBC is EFI BC (EFI Byte Code).
	PXEArchEFIBC uint16 = 9
	// PXEArchARMUEFI32 is ARM 32-bit UEFI.
	PXEArchARMUEFI32 uint16 = 10
	// PXEArchARMUEFI64 is ARM 64-bit UEFI.
	PXEArchARMUEFI64 uint16 = 11
	// PXEArchPowerPCOpenFirmware is PowerPC Open Firmware.
	PXEArchPowerPCOpenFirmware uint16 = 12
	// PXEArchPowerPCePAPR is PowerPC ePAPR.
	PXEArchPowerPCePAPR uint16 = 13
	// PXEArchPowerPCOPAL is POWER OPAL v3.
	PXEArchPowerPCOPAL uint16 = 14
	// PXEArchX8664HTTP is x86-64 UEFI HTTP.
	PXEArchX8664HTTP uint16 = 15
	// PXEArchX8632HTTP is x86 UEFI HTTP.
	PXEArchX8632HTTP uint16 = 16
	// PXEArchRISCVUEFI32 is RISC-V 32-bit UEFI.
	PXEArchRISCVUEFI32 uint16 = 25
	// PXEArchRISCVUEFI64 is RISC-V 64-bit UEFI.
	PXEArchRISCVUEFI64 uint16 = 27
	// PXEArchRISCVUEFI128 is RISC-V 128-bit UEFI.
	PXEArchRISCVUEFI128 uint16 = 29
)

// PXE vendor class identifiers.
const (
	// PXEVendorClassPXEClient is the standard PXE client identifier.
	PXEVendorClassPXEClient = "PXEClient"
)

// PXEPlugin adds PXE boot support to DHCP responses.
type PXEPlugin struct {
	nextServer   net.IP
	bootFileName string
	tftpRoot     string
	archFilters  map[uint16]string
	logger       *slog.Logger
	mu           sync.RWMutex
	closed       atomic.Bool
}

// PXEPluginOption configures a PXEPlugin.
type PXEPluginOption func(*PXEPlugin)

// WithPXELogger sets the logger for the PXE plugin.
func WithPXELogger(logger *slog.Logger) PXEPluginOption {
	return func(p *PXEPlugin) {
		p.logger = logger
	}
}

// WithTFTPRoot sets the TFTP root directory.
func WithTFTPRoot(root string) PXEPluginOption {
	return func(p *PXEPlugin) {
		p.tftpRoot = root
	}
}

// WithArchitectureFilters sets architecture-specific boot files.
func WithArchitectureFilters(filters map[uint16]string) PXEPluginOption {
	return func(p *PXEPlugin) {
		p.archFilters = filters
	}
}

// NewPXEPlugin creates a new PXE plugin.
func NewPXEPlugin(nextServer net.IP, bootFile string, opts ...PXEPluginOption) (*PXEPlugin, error) {
	if nextServer == nil || nextServer.IsUnspecified() {
		return nil, ErrInvalidNextServer
	}
	if bootFile == "" {
		return nil, ErrInvalidBootFile
	}

	p := &PXEPlugin{
		nextServer:   nextServer,
		bootFileName: bootFile,
		archFilters:  make(map[uint16]string),
		logger:       slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// Handler4 returns the DHCPv4 handler that adds PXE options.
func (p *PXEPlugin) Handler4() handler.Handler4 {
	return func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
		if p.closed.Load() {
			return resp, false
		}

		// Only process if this is a PXE client
		if !p.isPXEClient(req) {
			return resp, false
		}

		mac := req.ClientHWAddr
		p.logger.Debug("processing PXE request",
			slog.String("mac", mac.String()))

		// Get client architecture
		arch := p.getClientArchitecture(req)

		// Determine boot file based on architecture
		bootFile := p.getBootFileForArch(arch)

		// Add PXE options to response
		p.mu.RLock()
		resp.ServerIPAddr = p.nextServer
		resp.BootFileName = bootFile
		p.mu.RUnlock()

		// Add TFTP server name option (option 66)
		resp.UpdateOption(dhcpv4.OptTFTPServerName(p.nextServer.String()))

		// Add boot file name option (option 67)
		resp.UpdateOption(dhcpv4.OptBootFileName(bootFile))

		p.logger.Info("added PXE options",
			slog.String("mac", mac.String()),
			slog.Uint64("arch", uint64(arch)),
			slog.String("boot_file", bootFile),
			slog.String("next_server", p.nextServer.String()))

		return resp, false // Continue chain to allow other plugins to process
	}
}

// isPXEClient checks if the request is from a PXE client.
func (p *PXEPlugin) isPXEClient(req *dhcpv4.DHCPv4) bool {
	// Check vendor class identifier (option 60)
	vendorClass := req.Options.Get(dhcpv4.OptionClassIdentifier)
	if vendorClass != nil {
		vcString := string(vendorClass)
		// PXE clients typically start with "PXEClient"
		if len(vcString) >= len(PXEVendorClassPXEClient) &&
			vcString[:len(PXEVendorClassPXEClient)] == PXEVendorClassPXEClient {
			return true
		}
	}

	// Check for client system architecture (option 93)
	archOpt := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
	return len(archOpt) >= 2
}

// getClientArchitecture extracts the client architecture from the request.
func (p *PXEPlugin) getClientArchitecture(req *dhcpv4.DHCPv4) uint16 {
	// Option 93: Client System Architecture Type
	archOpt := req.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
	if len(archOpt) >= 2 {
		return binary.BigEndian.Uint16(archOpt[:2])
	}

	// Default to x86 BIOS if not specified
	return PXEArchIntelX86
}

// getBootFileForArch returns the appropriate boot file for the architecture.
func (p *PXEPlugin) getBootFileForArch(arch uint16) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.archFilters != nil {
		if bootFile, ok := p.archFilters[arch]; ok {
			return bootFile
		}
	}

	return p.bootFileName
}

// GetNextServer returns the TFTP server address.
func (p *PXEPlugin) GetNextServer() net.IP {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make(net.IP, len(p.nextServer))
	copy(result, p.nextServer)
	return result
}

// SetNextServer updates the TFTP server address.
func (p *PXEPlugin) SetNextServer(server net.IP) error {
	if server == nil || server.IsUnspecified() {
		return ErrInvalidNextServer
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextServer = make(net.IP, len(server))
	copy(p.nextServer, server)
	return nil
}

// GetBootFileName returns the default boot file name.
func (p *PXEPlugin) GetBootFileName() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.bootFileName
}

// SetBootFileName updates the default boot file name.
func (p *PXEPlugin) SetBootFileName(bootFile string) error {
	if bootFile == "" {
		return ErrInvalidBootFile
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bootFileName = bootFile
	return nil
}

// GetArchitectureFilters returns a copy of the architecture filters.
func (p *PXEPlugin) GetArchitectureFilters() map[uint16]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make(map[uint16]string, len(p.archFilters))
	for k, v := range p.archFilters {
		result[k] = v
	}
	return result
}

// SetArchitectureFilter sets the boot file for a specific architecture.
func (p *PXEPlugin) SetArchitectureFilter(arch uint16, bootFile string) error {
	if bootFile == "" {
		return ErrInvalidBootFile
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.archFilters == nil {
		p.archFilters = make(map[uint16]string)
	}
	p.archFilters[arch] = bootFile
	return nil
}

// RemoveArchitectureFilter removes the boot file mapping for an architecture.
func (p *PXEPlugin) RemoveArchitectureFilter(arch uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.archFilters, arch)
}

// GetTFTPRoot returns the TFTP root directory.
func (p *PXEPlugin) GetTFTPRoot() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tftpRoot
}

// SetTFTPRoot updates the TFTP root directory.
func (p *PXEPlugin) SetTFTPRoot(root string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tftpRoot = root
}

// Close closes the PXE plugin.
func (p *PXEPlugin) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return ErrPluginClosed
}
