// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPXEPlugin(t *testing.T) {
	t.Run("creates plugin with valid parameters", func(t *testing.T) {
		nextServer := net.ParseIP("192.168.1.10")
		bootFile := "pxelinux.0"

		plugin, err := NewPXEPlugin(nextServer, bootFile)
		require.NoError(t, err)
		require.NotNil(t, plugin)
		defer plugin.Close()

		assert.Equal(t, nextServer.String(), plugin.GetNextServer().String())
		assert.Equal(t, bootFile, plugin.GetBootFileName())
	})

	t.Run("returns error for nil next server", func(t *testing.T) {
		plugin, err := NewPXEPlugin(nil, "pxelinux.0")
		assert.ErrorIs(t, err, ErrInvalidNextServer)
		assert.Nil(t, plugin)
	})

	t.Run("returns error for unspecified next server", func(t *testing.T) {
		plugin, err := NewPXEPlugin(net.IPv4zero, "pxelinux.0")
		assert.ErrorIs(t, err, ErrInvalidNextServer)
		assert.Nil(t, plugin)
	})

	t.Run("returns error for empty boot file", func(t *testing.T) {
		nextServer := net.ParseIP("192.168.1.10")
		plugin, err := NewPXEPlugin(nextServer, "")
		assert.ErrorIs(t, err, ErrInvalidBootFile)
		assert.Nil(t, plugin)
	})

	t.Run("applies functional options", func(t *testing.T) {
		nextServer := net.ParseIP("192.168.1.10")
		bootFile := "pxelinux.0"
		customLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		archFilters := map[uint16]string{
			PXEArchEFIX8664: "grubx64.efi",
		}

		plugin, err := NewPXEPlugin(
			nextServer,
			bootFile,
			WithPXELogger(customLogger),
			WithTFTPRoot("/tftpboot"),
			WithArchitectureFilters(archFilters),
		)
		require.NoError(t, err)
		defer plugin.Close()

		assert.Equal(t, "/tftpboot", plugin.GetTFTPRoot())
		assert.Equal(t, "grubx64.efi", plugin.GetArchitectureFilters()[PXEArchEFIX8664])
	})
}

func TestPXEPlugin_Handler4(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()
	require.NotNil(t, handler)

	t.Run("adds PXE options for PXE client", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// Add PXE vendor class
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00000:UNDI:002001"))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop) // Should continue chain

		// Verify PXE options were added
		assert.Equal(t, nextServer.String(), result.ServerIPAddr.String())
		assert.Equal(t, bootFile, result.BootFileName)
	})

	t.Run("ignores non-PXE client", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// No PXE vendor class

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		originalServerIP := resp.ServerIPAddr

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)

		// Verify PXE options were NOT added
		assert.Equal(t, originalServerIP.String(), result.ServerIPAddr.String())
	})

	t.Run("detects PXE client by architecture option", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		// Add client system architecture type (option 93)
		archBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(archBytes, PXEArchEFIX8664)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archBytes))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.False(t, stop)

		// Verify PXE options were added
		assert.Equal(t, nextServer.String(), result.ServerIPAddr.String())
	})
}

func TestPXEPlugin_ArchitectureFilters(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	defaultBootFile := "pxelinux.0"
	archFilters := map[uint16]string{
		PXEArchEFIX8664:  "grubx64.efi",
		PXEArchEFIIA32:   "grubia32.efi",
		PXEArchARMUEFI64: "grubaa64.efi",
	}

	plugin, err := NewPXEPlugin(
		nextServer,
		defaultBootFile,
		WithArchitectureFilters(archFilters),
	)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("returns architecture-specific boot file", func(t *testing.T) {
		tests := []struct {
			name     string
			arch     uint16
			expected string
		}{
			{"UEFI x86-64", PXEArchEFIX8664, "grubx64.efi"},
			{"UEFI IA32", PXEArchEFIIA32, "grubia32.efi"},
			{"ARM UEFI 64", PXEArchARMUEFI64, "grubaa64.efi"},
			{"Legacy BIOS (default)", PXEArchIntelX86, defaultBootFile},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mac, _ := net.ParseMAC("00:11:22:33:44:55")
				req, _ := dhcpv4.New(
					dhcpv4.WithHwAddr(mac),
					dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				)
				req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))

				// Add architecture type
				archBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(archBytes, tt.arch)
				req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archBytes))

				resp, _ := dhcpv4.NewReplyFromRequest(req)

				result, _ := handler(req, resp)
				require.NotNil(t, result)

				assert.Equal(t, tt.expected, result.BootFileName)
			})
		}
	})
}

func TestPXEPlugin_GettersSetters(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	t.Run("GetNextServer returns copy", func(t *testing.T) {
		server := plugin.GetNextServer()
		assert.Equal(t, nextServer.String(), server.String())

		// Modify returned value
		server[0] = 0xFF

		// Original should be unchanged
		assert.Equal(t, nextServer.String(), plugin.GetNextServer().String())
	})

	t.Run("SetNextServer updates server", func(t *testing.T) {
		newServer := net.ParseIP("192.168.1.20")
		err := plugin.SetNextServer(newServer)
		require.NoError(t, err)

		assert.Equal(t, newServer.String(), plugin.GetNextServer().String())
	})

	t.Run("SetNextServer rejects nil", func(t *testing.T) {
		err := plugin.SetNextServer(nil)
		assert.ErrorIs(t, err, ErrInvalidNextServer)
	})

	t.Run("SetNextServer rejects unspecified", func(t *testing.T) {
		err := plugin.SetNextServer(net.IPv4zero)
		assert.ErrorIs(t, err, ErrInvalidNextServer)
	})

	t.Run("GetBootFileName returns boot file", func(t *testing.T) {
		assert.Equal(t, bootFile, plugin.GetBootFileName())
	})

	t.Run("SetBootFileName updates boot file", func(t *testing.T) {
		err := plugin.SetBootFileName("newboot.0")
		require.NoError(t, err)

		assert.Equal(t, "newboot.0", plugin.GetBootFileName())
	})

	t.Run("SetBootFileName rejects empty", func(t *testing.T) {
		err := plugin.SetBootFileName("")
		assert.ErrorIs(t, err, ErrInvalidBootFile)
	})

	t.Run("GetArchitectureFilters returns copy", func(t *testing.T) {
		filters := plugin.GetArchitectureFilters()
		filters[PXEArchEFIX8664] = "test.efi"

		// Original should be unchanged
		_, exists := plugin.GetArchitectureFilters()[PXEArchEFIX8664]
		assert.False(t, exists)
	})

	t.Run("SetArchitectureFilter adds filter", func(t *testing.T) {
		err := plugin.SetArchitectureFilter(PXEArchEFIX8664, "grubx64.efi")
		require.NoError(t, err)

		filters := plugin.GetArchitectureFilters()
		assert.Equal(t, "grubx64.efi", filters[PXEArchEFIX8664])
	})

	t.Run("SetArchitectureFilter rejects empty boot file", func(t *testing.T) {
		err := plugin.SetArchitectureFilter(PXEArchEFIX8664, "")
		assert.ErrorIs(t, err, ErrInvalidBootFile)
	})

	t.Run("RemoveArchitectureFilter removes filter", func(t *testing.T) {
		plugin.SetArchitectureFilter(PXEArchEFIIA32, "grubia32.efi")
		plugin.RemoveArchitectureFilter(PXEArchEFIIA32)

		filters := plugin.GetArchitectureFilters()
		_, exists := filters[PXEArchEFIIA32]
		assert.False(t, exists)
	})

	t.Run("GetTFTPRoot returns root", func(t *testing.T) {
		assert.Empty(t, plugin.GetTFTPRoot())
	})

	t.Run("SetTFTPRoot updates root", func(t *testing.T) {
		plugin.SetTFTPRoot("/var/lib/tftpboot")
		assert.Equal(t, "/var/lib/tftpboot", plugin.GetTFTPRoot())
	})
}

func TestPXEPlugin_Close(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	t.Run("closes plugin", func(t *testing.T) {
		plugin, err := NewPXEPlugin(nextServer, bootFile)
		require.NoError(t, err)

		err = plugin.Close()
		require.NoError(t, err)

		// Handler should pass through after close
		handler := plugin.Handler4()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		// Should pass through without adding PXE options
		assert.NotNil(t, result)
		assert.False(t, stop)
	})

	t.Run("double close returns error", func(t *testing.T) {
		plugin, err := NewPXEPlugin(nextServer, bootFile)
		require.NoError(t, err)

		err = plugin.Close()
		require.NoError(t, err)

		err = plugin.Close()
		assert.ErrorIs(t, err, ErrPluginClosed)
	})
}

func TestPXEArchitectureConstants(t *testing.T) {
	t.Run("architecture constants are defined", func(t *testing.T) {
		constants := []struct {
			name  string
			value uint16
		}{
			{"PXEArchIntelX86", PXEArchIntelX86},
			{"PXEArchNECPC98", PXEArchNECPC98},
			{"PXEArchEFIItanium", PXEArchEFIItanium},
			{"PXEArchDECAlpha", PXEArchDECAlpha},
			{"PXEArchArcX86", PXEArchArcX86},
			{"PXEArchIntelLeanClient", PXEArchIntelLeanClient},
			{"PXEArchEFIIA32", PXEArchEFIIA32},
			{"PXEArchEFIX8664", PXEArchEFIX8664},
			{"PXEArchEFIXscale", PXEArchEFIXscale},
			{"PXEArchEFIBC", PXEArchEFIBC},
			{"PXEArchARMUEFI32", PXEArchARMUEFI32},
			{"PXEArchARMUEFI64", PXEArchARMUEFI64},
			{"PXEArchPowerPCOpenFirmware", PXEArchPowerPCOpenFirmware},
			{"PXEArchPowerPCePAPR", PXEArchPowerPCePAPR},
			{"PXEArchPowerPCOPAL", PXEArchPowerPCOPAL},
			{"PXEArchX8664HTTP", PXEArchX8664HTTP},
			{"PXEArchX8632HTTP", PXEArchX8632HTTP},
			{"PXEArchRISCVUEFI32", PXEArchRISCVUEFI32},
			{"PXEArchRISCVUEFI64", PXEArchRISCVUEFI64},
			{"PXEArchRISCVUEFI128", PXEArchRISCVUEFI128},
		}

		for _, c := range constants {
			t.Run(c.name, func(t *testing.T) {
				// Just verify the constant exists
				assert.IsType(t, uint16(0), c.value)
			})
		}
	})

	t.Run("common architectures have expected values", func(t *testing.T) {
		assert.Equal(t, uint16(0), PXEArchIntelX86)
		assert.Equal(t, uint16(7), PXEArchEFIX8664)
		assert.Equal(t, uint16(6), PXEArchEFIIA32)
	})
}

func TestPXEPlugin_VendorClassDetection(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("detects PXEClient vendor class", func(t *testing.T) {
		vendorClasses := []string{
			"PXEClient",
			"PXEClient:Arch:00000",
			"PXEClient:Arch:00000:UNDI:002001",
			"PXEClient:Arch:00007:UNDI:003000",
		}

		for _, vc := range vendorClasses {
			t.Run(vc, func(t *testing.T) {
				mac, _ := net.ParseMAC("00:11:22:33:44:55")
				req, _ := dhcpv4.New(
					dhcpv4.WithHwAddr(mac),
					dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				)
				req.UpdateOption(dhcpv4.OptClassIdentifier(vc))

				resp, _ := dhcpv4.NewReplyFromRequest(req)

				result, _ := handler(req, resp)
				require.NotNil(t, result)

				// Verify PXE options were added
				assert.Equal(t, nextServer.String(), result.ServerIPAddr.String())
			})
		}
	})

	t.Run("ignores non-PXE vendor classes", func(t *testing.T) {
		vendorClasses := []string{
			"MSFT 5.0",
			"Linux",
			"",
			"PXE", // Not "PXEClient"
		}

		for _, vc := range vendorClasses {
			t.Run(vc, func(t *testing.T) {
				mac, _ := net.ParseMAC("00:11:22:33:44:55")
				req, _ := dhcpv4.New(
					dhcpv4.WithHwAddr(mac),
					dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
				)
				if vc != "" {
					req.UpdateOption(dhcpv4.OptClassIdentifier(vc))
				}

				resp, _ := dhcpv4.NewReplyFromRequest(req)
				originalServerIP := resp.ServerIPAddr

				result, _ := handler(req, resp)
				require.NotNil(t, result)

				// Verify PXE options were NOT added
				assert.Equal(t, originalServerIP.String(), result.ServerIPAddr.String())
			})
		}
	})
}

func TestPXEPlugin_TFTPOptions(t *testing.T) {
	nextServer := net.ParseIP("192.168.1.10")
	bootFile := "pxelinux.0"

	plugin, err := NewPXEPlugin(nextServer, bootFile)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("adds TFTP server name option", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Verify option 66 (TFTP server name)
		tftpServerOpt := result.Options.Get(dhcpv4.OptionTFTPServerName)
		assert.NotNil(t, tftpServerOpt)
		assert.Equal(t, nextServer.String(), string(tftpServerOpt))
	})

	t.Run("adds boot file name option", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		req.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Verify option 67 (boot file name)
		bootFileOpt := result.Options.Get(dhcpv4.OptionBootfileName)
		assert.NotNil(t, bootFileOpt)
		assert.Equal(t, bootFile, string(bootFileOpt))
	})
}
