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

package rpinetboot

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pi4() Identity {
	mac, _ := net.ParseMAC("dc:a6:32:01:36:c2")
	return Identity{Serial: 0x9ffefdef, MAC: mac, Revision: 0x00c03111}
}

func TestOption97_RoundTrip(t *testing.T) {
	id := pi4()
	m, err := LookupModel("rpi4")
	require.NoError(t, err)

	opt := id.Option97(m)
	require.Len(t, opt, Option97Len)
	assert.Equal(t, byte(0), opt[0], "the type byte")
	assert.Equal(t, "RPi4", string(opt[1:5]), "the FourCC opens the GUID")
	assert.Equal(t, []byte{0x00, 0xc0, 0x31, 0x11}, opt[5:9], "the board revision")
	assert.Equal(t, []byte{0x32, 0x01, 0x36, 0xc2}, opt[9:13], "the low four MAC bytes")
	assert.Equal(t, []byte{0x9f, 0xfe, 0xfd, 0xef}, opt[13:17], "the serial")

	parsed, ok := ParseOption97(opt)
	require.True(t, ok)
	assert.Equal(t, ParsedOption97{FourCC: "RPi4", Serial: 0x9ffefdef, Revision: 0x00c03111}, parsed)

	pi5, err := LookupModel("rpi5")
	require.NoError(t, err)
	parsed, ok = ParseOption97(id.Option97(pi5))
	require.True(t, ok)
	assert.Equal(t, "RPi5", parsed.FourCC)
}

func TestOption97_LegacyFormatIsTheSerialFourTimes(t *testing.T) {
	id := pi4()
	m, err := LookupModel("rpi3b+")
	require.NoError(t, err)

	opt := id.Option97(m)
	require.Len(t, opt, Option97Len)
	for i := 1; i < Option97Len; i += 4 {
		assert.Equal(t, []byte{0x9f, 0xfe, 0xfd, 0xef}, opt[i:i+4])
	}
	parsed, ok := ParseOption97(opt)
	require.True(t, ok)
	assert.Equal(t, ParsedOption97{Serial: 0x9ffefdef}, parsed)
}

func TestParseOption97_RejectsWhatIsNotAPi(t *testing.T) {
	random := append([]byte{0}, []byte("0123456789abcdef")...)
	_, ok := ParseOption97(random)
	assert.False(t, ok, "a PXE ROM's GUID")
	_, ok = ParseOption97(nil)
	assert.False(t, ok, "no option")
	_, ok = ParseOption97(pi4().Option97(models["rpi4"])[:10])
	assert.False(t, ok, "a short option")
	wrongType := pi4().Option97(models["rpi4"])
	wrongType[0] = 1
	_, ok = ParseOption97(wrongType)
	assert.False(t, ok, "a non-zero type byte")
}

func TestIsBootloaderRequest(t *testing.T) {
	id := pi4()
	x86, _ := net.ParseMAC("00:11:22:33:44:55")
	assert.True(t, IsBootloaderRequest(VendorClass, id.Option97(models["rpi4"]), x86), "a Pi option 97 decides")
	assert.True(t, IsBootloaderRequest(VendorClass, nil, id.MAC), "a Pi MAC decides when option 97 is absent")
	assert.False(t, IsBootloaderRequest(VendorClass, append([]byte{0}, []byte("0123456789abcdef")...), x86), "a legacy x86 PXE ROM sends the same vendor class")
	assert.False(t, IsBootloaderRequest("PXEClient:Arch:00007:UNDI:003001", id.Option97(models["rpi4"]), id.MAC), "the vendor class must be the bootloader's")
	assert.False(t, IsBootloaderRequest("", nil, id.MAC))
}

func TestIsPiMAC(t *testing.T) {
	for _, s := range []string{"b8:27:eb:00:00:01", "dc:a6:32:01:36:c2", "e4:5f:01:aa:bb:cc", "d8:3a:dd:00:00:00", "2c:cf:67:12:34:56", "28:cd:c1:00:00:00"} {
		mac, err := net.ParseMAC(s)
		require.NoError(t, err)
		assert.True(t, IsPiMAC(mac), s)
	}
	mac, _ := net.ParseMAC("52:54:00:12:34:56")
	assert.False(t, IsPiMAC(mac))
	assert.False(t, IsPiMAC(net.HardwareAddr{0xb8}))
}

func TestOption43_IsWhatDnsmasqEmitsAndMatches(t *testing.T) {
	opt := Option43(Option43Match)
	want := append([]byte{0x06, 0x01, 0x03, 0x0a, 0x04, 0x00, 'P', 'X', 'E', 0x09, 0x14, 0x00, 0x00, 0x11}, []byte("Raspberry Pi Boot")...)
	want = append(want, 0xff)
	assert.Equal(t, want, opt)
	assert.True(t, Option43Matches(opt, Option43Match))
	assert.False(t, Option43Matches(opt, Option43MatchLegacy), "the three-space form is a different string")
	assert.True(t, Option43Matches(Option43(Option43MatchLegacy), Option43Match), "the legacy form still contains the plain one")
	assert.False(t, Option43Matches([]byte{0x06, 0x01, 0x08, 0xff}, Option43Match), "the x86 PXE reply")
}

func TestPrefix(t *testing.T) {
	id := pi4()
	p, err := id.Prefix(PrefixSerial, "")
	require.NoError(t, err)
	assert.Equal(t, "9ffefdef/", p)

	p, err = id.Prefix(PrefixMAC, "")
	require.NoError(t, err)
	assert.Equal(t, "dc-a6-32-01-36-c2/", p)

	p, err = id.Prefix(PrefixString, "tftp_test/")
	require.NoError(t, err)
	assert.Equal(t, "tftp_test/", p)
	p, err = id.Prefix(PrefixString, "lab")
	require.NoError(t, err)
	assert.Equal(t, "lab/", p, "the slash is added when missing")

	small := Identity{Serial: 0x1234}
	p, err = small.Prefix(PrefixSerial, "")
	require.NoError(t, err)
	assert.Equal(t, "00001234/", p, "eight digits, zero-padded")

	_, err = small.Prefix(PrefixMAC, "")
	var invalid *InvalidIdentityError
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "MAC", invalid.Field)
	_, err = id.Prefix(PrefixString, "")
	require.ErrorAs(t, err, &invalid)
	_, err = id.Prefix(PrefixMode(7), "")
	require.ErrorAs(t, err, &invalid)
}

func TestLookupModel(t *testing.T) {
	assert.Equal(t, []string{"cm4", "rpi3b+", "rpi4", "rpi400", "rpi5"}, Models())
	m, err := LookupModel("rpi5")
	require.NoError(t, err)
	assert.Empty(t, m.FirstStage, "the Pi 5 EEPROM is the firmware")
	assert.Empty(t, m.Fixup)
	m, err = LookupModel("rpi3b+")
	require.NoError(t, err)
	assert.Equal(t, []string{"bootcode.bin", "start.elf"}, m.FirstStage)

	_, err = LookupModel("rpi2")
	var unknown *UnknownModelError
	require.ErrorAs(t, err, &unknown)
	assert.Contains(t, err.Error(), "rpi4")
}

func TestParseBootConfigAndFirmwareFiles(t *testing.T) {
	cfg := ParseBootConfig([]byte("# comment\narm_64bit=1\ndtoverlay=disable-bt\ndtoverlay=tpm-soft-spi,cs=1\n dtoverlay= \nkernel=kernel8.img\n"))
	assert.Equal(t, BootConfig{Kernel: "kernel8.img", Overlays: []string{"disable-bt", "tpm-soft-spi"}}, cfg)
	assert.Equal(t, DefaultKernel, ParseBootConfig(nil).Kernel, "no kernel= means kernel8.img")
	assert.Equal(t, "u-boot.bin", ParseBootConfig([]byte("kernel=u-boot.bin")).Kernel)

	files := models["rpi4"].FirmwareFiles(cfg)
	assert.Equal(t, []FileSpec{
		{Name: "fixup4.dat"},
		{Name: "bcm2711-rpi-4-b.dtb"},
		{Name: "overlays/disable-bt.dtbo"},
		{Name: "overlays/tpm-soft-spi.dtbo"},
		{Name: "cmdline.txt", Optional: true},
		{Name: "kernel8.img"},
	}, files)

	pi5 := models["rpi5"].FirmwareFiles(BootConfig{Kernel: DefaultKernel})
	assert.Equal(t, []FileSpec{{Name: "bcm2712-rpi-5-b.dtb"}, {Name: "cmdline.txt", Optional: true}, {Name: "kernel8.img"}}, pi5)
}
