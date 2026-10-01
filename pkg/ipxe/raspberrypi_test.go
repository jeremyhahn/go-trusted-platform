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
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

// piDiscover builds the DISCOVER a Raspberry Pi 4 bootloader sends.
func piDiscover(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	mac, err := net.ParseMAC("dc:a6:32:01:36:c2")
	require.NoError(t, err)
	id := rpinetboot.Identity{Serial: 0x9ffefdef, MAC: mac, Revision: 0x00c03111}
	model, err := rpinetboot.LookupModel("rpi4")
	require.NoError(t, err)
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier(rpinetboot.VendorClass)),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x00})),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, id.Option97(model))),
	)
	require.NoError(t, err)
	return req
}

func TestDHCPServer_RaspberryPi_Offer(t *testing.T) {
	server := createTestDHCPServer(t)
	conn := &mockPacketConn{}
	req := piDiscover(t)

	server.handleDiscover(conn, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, req)

	require.NotNil(t, conn.writtenData, "a Pi is a PXE client and gets an offer")
	offer, err := dhcpv4.FromBytes(conn.writtenData)
	require.NoError(t, err)
	assert.Equal(t, dhcpv4.MessageTypeOffer, offer.MessageType())
	assert.True(t, offer.YourIPAddr.Equal(net.ParseIP("192.168.1.100")), "a lease, as a full DHCP server")
	assert.True(t, offer.ServerIPAddr.Equal(net.ParseIP("192.168.1.1")), "siaddr is the TFTP server")
	assert.Equal(t, "pxeserver", offer.ServerHostName)
	assert.Equal(t, "pxeserver", offer.TFTPServerName())
	assert.Empty(t, offer.BootFileName, "the bootloader fetches its files by name; no bootfile is offered")
	assert.Equal(t, "PXEClient", string(offer.Options.Get(dhcpv4.OptionClassIdentifier)))
	assert.Equal(t, req.Options.Get(dhcpv4.OptionClientMachineIdentifier), offer.Options.Get(dhcpv4.OptionClientMachineIdentifier), "option 97 echoed")
	opt43 := offer.Options.Get(dhcpv4.OptionVendorSpecificInformation)
	assert.True(t, rpinetboot.Option43Matches(opt43, rpinetboot.Option43Match), "option 43 carries the match string: %x", opt43)
	assert.Equal(t, rpinetboot.Option43(rpinetboot.Option43Match), opt43)
}

func TestDHCPServer_RaspberryPi_Option43Override(t *testing.T) {
	server := createTestDHCPServer(t)
	server.config.RaspberryPiOption43 = rpinetboot.Option43MatchLegacy
	conn := &mockPacketConn{}

	server.handleDiscover(conn, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, piDiscover(t))

	offer, err := dhcpv4.FromBytes(conn.writtenData)
	require.NoError(t, err)
	assert.Equal(t, rpinetboot.Option43(rpinetboot.Option43MatchLegacy), offer.Options.Get(dhcpv4.OptionVendorSpecificInformation))
}

func TestDHCPServer_LegacyX86ROMIsNotAPi(t *testing.T) {
	// The same vendor class from a legacy BIOS PXE ROM (a random GUID, a
	// non-Pi MAC) keeps the x86 path: undionly.kpxe and the PXE option 43.
	server := createTestDHCPServer(t)
	server.config.BootFilenameByArch = DefaultBootFilenameByArch()
	conn := &mockPacketConn{}
	mac, _ := net.ParseMAC("00:25:90:aa:bb:cc")
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier(rpinetboot.VendorClass)),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x00})),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, append([]byte{0}, []byte("0123456789abcdef")...))),
	)
	require.NoError(t, err)

	server.handleDiscover(conn, &net.UDPAddr{IP: net.IPv4zero, Port: 68}, req)

	offer, err := dhcpv4.FromBytes(conn.writtenData)
	require.NoError(t, err)
	assert.Equal(t, "undionly.kpxe", offer.BootFileName)
	assert.Equal(t, []byte{0x06, 0x01, 0x08, 0xff}, offer.Options.Get(dhcpv4.OptionVendorSpecificInformation))
}

func TestDHCPServer_ProxyOnly(t *testing.T) {
	server := createTestDHCPServer(t)
	server.config.ProxyOnly = true
	server.config.BootFilenameByArch = DefaultBootFilenameByArch()
	peer := &net.UDPAddr{IP: net.IPv4zero, Port: 68}

	t.Run("a Pi gets boot options and no address", func(t *testing.T) {
		conn := &mockPacketConn{}
		server.handleDiscover(conn, peer, piDiscover(t))
		require.NotNil(t, conn.writtenData)
		offer, err := dhcpv4.FromBytes(conn.writtenData)
		require.NoError(t, err)
		assert.Equal(t, dhcpv4.MessageTypeOffer, offer.MessageType())
		assert.True(t, offer.YourIPAddr.IsUnspecified(), "no lease from a proxy")
		assert.Nil(t, offer.Options.Get(dhcpv4.OptionSubnetMask), "no lease options either")
		assert.Nil(t, offer.Options.Get(dhcpv4.OptionIPAddressLeaseTime))
		assert.True(t, offer.ServerIPAddr.Equal(net.ParseIP("192.168.1.1")))
		assert.True(t, rpinetboot.Option43Matches(offer.Options.Get(dhcpv4.OptionVendorSpecificInformation), rpinetboot.Option43Match))
		assert.Len(t, server.leases, 0, "nothing allocated")
	})

	t.Run("an EFI client gets its bootfile and no address", func(t *testing.T) {
		conn := &mockPacketConn{}
		server.handleDiscover(conn, peer, createPXEDiscoverRequest(t))
		offer, err := dhcpv4.FromBytes(conn.writtenData)
		require.NoError(t, err)
		assert.True(t, offer.YourIPAddr.IsUnspecified())
		assert.Equal(t, "ipxe.efi", offer.BootFileName)
	})

	t.Run("a non-PXE client is ignored even with RespondToAll", func(t *testing.T) {
		server.config.RespondToAll = true
		defer func() { server.config.RespondToAll = false }()
		conn := &mockPacketConn{}
		server.handleDiscover(conn, peer, createBaseDHCPRequest(t))
		assert.Nil(t, conn.writtenData, "a proxy has no address to give an ordinary client")
	})

	t.Run("a REQUEST is left to the network's DHCP server", func(t *testing.T) {
		conn := &mockPacketConn{}
		server.handleRequest(conn, peer, createPXERequestRequest(t, net.ParseIP("192.168.1.100")))
		assert.Nil(t, conn.writtenData)
	})
}

func TestTFTPServer_ServesTheTree(t *testing.T) {
	tree := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "9ffefdef", "overlays"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "start4.elf"), []byte("ELF4"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "9ffefdef", "config.txt"), []byte("kernel=kernel8.img\n"), 0o644))
	cfg := DefaultServerConfig()
	cfg.TFTPDir = tree
	server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())
	server.firmwareMu.Lock()
	server.firmware["ipxe.efi"] = []byte("MZ")
	server.firmwareMu.Unlock()

	read := func(name string) (*mockReaderFrom, error) {
		rf := &mockReaderFrom{remoteAddr: net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5000}}
		return rf, server.readHandler(name, rf)
	}

	rf, err := read("start4.elf")
	require.NoError(t, err)
	assert.Equal(t, []byte("ELF4"), rf.data)
	assert.Equal(t, int64(4), rf.size, "tsize is set from the file")

	rf, err = read("9ffefdef/config.txt")
	require.NoError(t, err, "a per-device directory")
	assert.Equal(t, "kernel=kernel8.img\n", string(rf.data))

	rf, err = read("ipxe.efi")
	require.NoError(t, err)
	assert.Equal(t, []byte("MZ"), rf.data, "the firmware set still answers first")

	_, err = read("9ffefdef/start4.elf")
	var pathErr *TFTPPathError
	require.ErrorAs(t, err, &pathErr, "absent in the device directory: the bootloader then asks the root")
	assert.ErrorIs(t, err, os.ErrNotExist)

	_, err = read("../etc/passwd")
	require.ErrorAs(t, err, &pathErr)
	assert.ErrorIs(t, err, os.ErrNotExist, "an escape is refused as not found")
	_, err = read("9ffefdef")
	require.ErrorAs(t, err, &pathErr)
	assert.ErrorIs(t, err, os.ErrNotExist, "a directory is not a file")
	_, err = read("/start4.elf")
	require.NoError(t, err, "a leading slash is root-relative")
}

func TestTFTPServer_NoTreeKeepsTheFirmwareOnlyBehaviour(t *testing.T) {
	server := NewTFTPServer(DefaultServerConfig(), net.ParseIP("192.168.1.1"), logging.DefaultLogger())
	err := server.readHandler("start4.elf", &mockReaderFrom{})
	assert.ErrorIs(t, err, ErrFirmwareNotFound)
}

func TestTestEnv_RaspberryPiSettingsPassThrough(t *testing.T) {
	cfg := DefaultTestEnvConfig()
	cfg.TFTPDir = "/srv/tftp"
	cfg.ProxyDHCP = true
	env, err := NewTestEnv(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Equal(t, "/srv/tftp", env.ServerConfig().TFTPDir)
	assert.True(t, env.ServerConfig().DHCPProxyOnly)
	assert.True(t, env.dhcpConfig().ProxyOnly)
}
