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

package dhcp

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPXEPlugin_SetArchitectureFilter_CreatesMap tests that SetArchitectureFilter creates the map if nil.
func TestPXEPlugin_SetArchitectureFilter_CreatesMap(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	// Initially the archFilters is an empty map (created in NewPXEPlugin)
	// Manually set it to nil to test the nil check in SetArchitectureFilter
	plugin.mu.Lock()
	plugin.archFilters = nil
	plugin.mu.Unlock()

	err = plugin.SetArchitectureFilter(PXEArchEFIX8664, "grubx64.efi")
	require.NoError(t, err)

	filters := plugin.GetArchitectureFilters()
	assert.Equal(t, "grubx64.efi", filters[PXEArchEFIX8664])
}

// TestPXEPlugin_GetClientArchitecture_DefaultValue tests default architecture when not specified.
func TestPXEPlugin_GetClientArchitecture_DefaultValue(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("defaults to Intel x86 when architecture not provided", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// Add PXE vendor class but no architecture option
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00000"))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Should use default boot file (for Intel x86 BIOS)
		assert.Equal(t, bootFile, result.BootFileName)
	})

	t.Run("uses architecture from option 93", func(t *testing.T) {
		archFilters := map[uint16]string{
			PXEArchEFIX8664: "grubx64.efi",
		}
		filteredPlugin, _ := NewPXEPlugin(nextServer, bootFile, WithArchitectureFilters(archFilters))
		defer filteredPlugin.Close()

		filteredHandler := filteredPlugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))

		// Add architecture type option 93
		archBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(archBytes, PXEArchEFIX8664)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archBytes))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := filteredHandler(req, resp)
		require.NotNil(t, result)

		// Should use filtered boot file
		assert.Equal(t, "grubx64.efi", result.BootFileName)
	})
}

// TestPXEPlugin_ShortArchitectureOption tests handling of short architecture option.
func TestPXEPlugin_ShortArchitectureOption(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles short architecture option gracefully", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// Add PXE vendor class to make it a PXE client
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))

		// Add short architecture option (less than 2 bytes)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x07}))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Should use default boot file
		assert.Equal(t, bootFile, result.BootFileName)
	})
}

// TestPXEPlugin_IsPXEClient_EdgeCases tests edge cases in PXE client detection.
func TestPXEPlugin_IsPXEClient_EdgeCases(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("detects PXE client by architecture option only", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// No vendor class, but has architecture option
		archBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(archBytes, PXEArchEFIX8664)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archBytes))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Should detect as PXE client and add options
		assert.Equal(t, nextServer.String(), result.ServerIPAddr.String())
	})

	t.Run("short vendor class string is not PXE", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// Vendor class too short to be "PXEClient"
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXE"))

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		originalServerIP := resp.ServerIPAddr

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Should NOT detect as PXE client
		assert.Equal(t, originalServerIP.String(), result.ServerIPAddr.String())
	})
}

// TestPXEPlugin_GetBootFileForArch_NilFilters tests boot file retrieval with nil filters.
func TestPXEPlugin_GetBootFileForArch_NilFilters(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	// Manually set archFilters to nil
	plugin.mu.Lock()
	plugin.archFilters = nil
	plugin.mu.Unlock()

	handler := plugin.Handler4()

	t.Run("returns default boot file when filters are nil", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))

		archBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(archBytes, PXEArchEFIX8664)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archBytes))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Should use default boot file since filters are nil
		assert.Equal(t, bootFile, result.BootFileName)
	})
}
