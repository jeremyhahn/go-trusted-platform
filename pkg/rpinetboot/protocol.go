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

// Package rpinetboot is the Raspberry Pi bootloader's network boot
// protocol — what the EEPROM (Pi 4, 400, CM4, 5) or the boot ROM (3B+)
// sends, what it accepts in reply, the files it then fetches over TFTP and
// where it looks for them — and a client that speaks it faithfully.
//
// The PXE server in pkg/ipxe uses the protocol half to recognise a Pi and
// answer it; the integration suite and `platformctl bootstrap probe rpi`
// use the client half to prove a boot server from the Pi's side of the
// wire without a Pi. Nothing here emulates the Pi itself: what it fetches
// is served to a real Pi unchanged.
//
// Every constant is from the Raspberry Pi bootloader configuration
// documentation (properties DHCP_OPTION97, PXE_OPTION43, TFTP_PREFIX,
// DHCP_TIMEOUT, DHCP_REQ_TIMEOUT, TFTP_FILE_TIMEOUT) and the network boot
// documentation of the 3B+ era ("Raspberry Pi Boot" with three trailing
// spaces; five TFTP retries five seconds apart).
package rpinetboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// VendorClass is the DHCP option 60 the bootloader sends. It is the same
// string a legacy x86 PXE ROM sends, which is why a Pi is recognised by
// option 97 or its MAC prefix as well.
const VendorClass = "PXEClient:Arch:00000:UNDI:002001"

// ClientArch is the bootloader's DHCP option 93 value.
const ClientArch uint16 = 0

// Option43Match is the string the bootloader looks for in the DHCP reply's
// option 43 (the PXE_OPTION43 default). The 2B v1.2 and original 3B boot
// ROMs matched it with three trailing spaces; Option43MatchLegacy is that
// form.
const (
	Option43Match       = "Raspberry Pi Boot"
	Option43MatchLegacy = "Raspberry Pi Boot   "
)

// Bootloader timing, as configured by default in the EEPROM.
const (
	// DHCPTimeout bounds the whole DHCP exchange (DHCP_TIMEOUT).
	DHCPTimeout = 45 * time.Second
	// DHCPRequestTimeout is the interval between DISCOVER or REQUEST
	// retries (DHCP_REQ_TIMEOUT).
	DHCPRequestTimeout = 4 * time.Second
	// TFTPFileTimeout bounds one file download (TFTP_FILE_TIMEOUT).
	TFTPFileTimeout = 30 * time.Second
	// TFTPRetries and TFTPRetryInterval: the bootloader retries a TFTP
	// request five times, five seconds apart.
	TFTPRetries       = 5
	TFTPRetryInterval = 5 * time.Second
)

// FourCC values that open the new-format client GUID (option 97): "RPi4"
// (0x34695052) and "RPi5" (0x35695052) read as little-endian words.
const (
	FourCCPi4 = "RPi4"
	FourCCPi5 = "RPi5"
)

// Option97Len is the length of option 97 as the bootloader sends it: the
// type byte (0) and a 16-byte GUID.
const Option97Len = 17

// Identity is what distinguishes one Pi from another on the wire.
type Identity struct {
	// Serial is the 32-bit board serial number (the low word of the
	// 64-bit serial in /proc/cpuinfo).
	Serial uint32
	// MAC is the Ethernet address.
	MAC net.HardwareAddr
	// Revision is the board revision code (for example 0x00c03111).
	Revision uint32
}

// Option97 encodes the client machine identifier the bootloader sends:
// the type byte, then the model's FourCC, the board revision, the low four
// bytes of the MAC and the serial number (DHCP_OPTION97's default format).
// A model without a FourCC (the 3B+ boot ROM) sends the earlier format,
// the serial number repeated four times.
func (id Identity) Option97(m Model) []byte {
	guid := make([]byte, 0, 16)
	if m.FourCC == "" {
		for i := 0; i < 4; i++ {
			guid = binary.BigEndian.AppendUint32(guid, id.Serial)
		}
	} else {
		guid = append(guid, m.FourCC...)
		guid = binary.BigEndian.AppendUint32(guid, id.Revision)
		mac := id.MAC
		if len(mac) >= 4 {
			guid = append(guid, mac[len(mac)-4:]...)
		} else {
			guid = append(guid, 0, 0, 0, 0)
		}
		guid = binary.BigEndian.AppendUint32(guid, id.Serial)
	}
	return append([]byte{0}, guid...)
}

// ParsedOption97 is what a bootloader's option 97 says about it.
type ParsedOption97 struct {
	// FourCC is "RPi4" or "RPi5", or empty for the earlier format.
	FourCC string
	// Serial is the board serial number.
	Serial uint32
	// Revision is the board revision (new format only).
	Revision uint32
}

// ParseOption97 reports whether opt is a Raspberry Pi client machine
// identifier, in either format, and what it carries. Anything else — a
// PXE ROM's random GUID, a short or absent option — is not a Pi.
func ParseOption97(opt []byte) (ParsedOption97, bool) {
	if len(opt) != Option97Len || opt[0] != 0 {
		return ParsedOption97{}, false
	}
	guid := opt[1:]
	switch string(guid[:4]) {
	case FourCCPi4, FourCCPi5:
		return ParsedOption97{
			FourCC:   string(guid[:4]),
			Revision: binary.BigEndian.Uint32(guid[4:8]),
			Serial:   binary.BigEndian.Uint32(guid[12:16]),
		}, true
	}
	// The earlier format: one word repeated four times. A random GUID
	// never has that shape.
	w := guid[:4]
	if bytes.Equal(w, guid[4:8]) && bytes.Equal(w, guid[8:12]) && bytes.Equal(w, guid[12:16]) {
		return ParsedOption97{Serial: binary.BigEndian.Uint32(w)}, true
	}
	return ParsedOption97{}, false
}

// piOUIs are the IEEE OUIs assigned to Raspberry Pi (Trading) Ltd.
var piOUIs = [][3]byte{
	{0xb8, 0x27, 0xeb},
	{0xdc, 0xa6, 0x32},
	{0xe4, 0x5f, 0x01},
	{0xd8, 0x3a, 0xdd},
	{0x2c, 0xcf, 0x67},
	{0x28, 0xcd, 0xc1},
}

// IsPiMAC reports whether mac carries a Raspberry Pi OUI.
func IsPiMAC(mac net.HardwareAddr) bool {
	if len(mac) < 3 {
		return false
	}
	for _, oui := range piOUIs {
		if mac[0] == oui[0] && mac[1] == oui[1] && mac[2] == oui[2] {
			return true
		}
	}
	return false
}

// IsBootloaderRequest reports whether a DHCP request is the Raspberry Pi
// bootloader's: its vendor class, and either a Pi-shaped option 97 or a
// Pi MAC. The vendor class alone is a legacy x86 PXE ROM's too.
func IsBootloaderRequest(vendorClass string, option97 []byte, mac net.HardwareAddr) bool {
	if vendorClass != VendorClass {
		return false
	}
	if _, ok := ParseOption97(option97); ok {
		return true
	}
	return IsPiMAC(mac)
}

// PXE vendor-specific (option 43) sub-options, as the bootloader's
// documented dnsmasq configuration (pxe-service=0,"Raspberry Pi Boot")
// emits them.
const (
	pxeDiscoveryControl = 0x06
	pxeBootServers      = 0x08
	pxeBootMenu         = 0x09
	pxeMenuPrompt       = 0x0a
	pxeEnd              = 0xff
)

// Option43 builds the option 43 a Pi accepts: a PXE boot menu whose one
// item's description is match (Option43Match unless a fleet of 2B v1.2 /
// original 3B boards needs Option43MatchLegacy), laid out exactly as
// dnsmasq lays out `pxe-service=0,"<match>"`: discovery control 3, a
// zero-timeout "PXE" prompt, the menu item of type 0, then END.
func Option43(match string) []byte {
	item := append([]byte{0, 0, byte(len(match))}, match...)
	opt := []byte{pxeDiscoveryControl, 1, 0x03}
	opt = append(opt, pxeMenuPrompt, 4, 0, 'P', 'X', 'E')
	opt = append(opt, pxeBootMenu, byte(len(item)))
	opt = append(opt, item...)
	return append(opt, pxeEnd)
}

// Option43Matches reports whether a reply's option 43 satisfies the
// bootloader, which looks for its match string in the option.
func Option43Matches(option43 []byte, match string) bool {
	return bytes.Contains(option43, []byte(match))
}

// PrefixMode is the TFTP_PREFIX setting: the per-device directory the
// bootloader prefixes every filename with before falling back to the
// root.
type PrefixMode int

const (
	// PrefixSerial is TFTP_PREFIX=0, the serial number ("9ffefdef/").
	PrefixSerial PrefixMode = 0
	// PrefixString is TFTP_PREFIX=1, the TFTP_PREFIX_STR string.
	PrefixString PrefixMode = 1
	// PrefixMAC is TFTP_PREFIX=2, the MAC ("dc-a6-32-01-36-c2/").
	PrefixMAC PrefixMode = 2
)

// Prefix returns the per-device directory for mode: the serial number as
// eight lower-case hex digits, the MAC with dashes, or custom (given with
// or without its trailing slash). The result ends in a slash.
func (id Identity) Prefix(mode PrefixMode, custom string) (string, error) {
	switch mode {
	case PrefixSerial:
		return fmt.Sprintf("%08x/", id.Serial), nil
	case PrefixMAC:
		if len(id.MAC) != 6 {
			return "", &InvalidIdentityError{Field: "MAC", Value: id.MAC.String()}
		}
		return strings.ReplaceAll(id.MAC.String(), ":", "-") + "/", nil
	case PrefixString:
		if custom == "" {
			return "", &InvalidIdentityError{Field: "TFTP_PREFIX_STR", Value: ""}
		}
		return strings.TrimSuffix(custom, "/") + "/", nil
	default:
		return "", &InvalidIdentityError{Field: "TFTP_PREFIX", Value: fmt.Sprint(int(mode))}
	}
}

// Model is how one board family boots over the network.
type Model struct {
	// Name is the platform's --model name (rpi4, rpi400, cm4, rpi3b+, rpi5). lab-string-ok: Raspberry Pi model name, not a lab host
	Name string
	// FourCC opens the option 97 GUID; empty for the boot ROM models,
	// which send the serial repeated.
	FourCC string
	// FirstStage are the files the bootloader itself fetches before the
	// firmware takes over, in order: the Pi 4 family's EEPROM fetches
	// start4.elf; the 3B+ boot ROM fetches bootcode.bin then start.elf.
	// The Pi 5's EEPROM is the firmware and fetches config.txt first.
	FirstStage []string
	// Fixup is the firmware's fixup file, or empty (Pi 5).
	Fixup string
	// DTB is the board's device tree.
	DTB string
}

// models is the supported board table, matching pkg/diskimage/rpi.
var models = map[string]Model{
	"rpi4":   {Name: "rpi4", FourCC: FourCCPi4, FirstStage: []string{"start4.elf"}, Fixup: "fixup4.dat", DTB: "bcm2711-rpi-4-b.dtb"},
	"rpi400": {Name: "rpi400", FourCC: FourCCPi4, FirstStage: []string{"start4.elf"}, Fixup: "fixup4.dat", DTB: "bcm2711-rpi-400.dtb"}, // lab-string-ok: Raspberry Pi model name, not a lab host
	"cm4":    {Name: "cm4", FourCC: FourCCPi4, FirstStage: []string{"start4.elf"}, Fixup: "fixup4.dat", DTB: "bcm2711-rpi-cm4.dtb"},
	"rpi3b+": {Name: "rpi3b+", FirstStage: []string{"bootcode.bin", "start.elf"}, Fixup: "fixup.dat", DTB: "bcm2710-rpi-3-b-plus.dtb"},
	"rpi5":   {Name: "rpi5", FourCC: FourCCPi5, DTB: "bcm2712-rpi-5-b.dtb"},
}

// LookupModel resolves a model name.
func LookupModel(name string) (Model, error) {
	m, ok := models[name]
	if !ok {
		return Model{}, &UnknownModelError{Model: name, Models: Models()}
	}
	return m, nil
}

// Models lists the supported model names, sorted.
func Models() []string {
	names := make([]string, 0, len(models))
	for name := range models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BootConfig is what the firmware reads from config.txt that decides
// which further files it fetches.
type BootConfig struct {
	// Kernel is the kernel= file (kernel8.img when unset).
	Kernel string
	// Overlays are the dtoverlay= names, in order, as overlays/<name>.dtbo.
	Overlays []string
}

// DefaultKernel is the 64-bit kernel file the firmware loads when
// config.txt names none.
const DefaultKernel = "kernel8.img"

// ParseBootConfig reads the kernel and overlay lines of a config.txt. A
// dtoverlay line's parameters (after the first comma) are not part of the
// file name.
func ParseBootConfig(configTxt []byte) BootConfig {
	cfg := BootConfig{Kernel: DefaultKernel}
	for _, line := range strings.Split(string(configTxt), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "kernel="):
			if k := strings.TrimSpace(strings.TrimPrefix(line, "kernel=")); k != "" {
				cfg.Kernel = k
			}
		case strings.HasPrefix(line, "dtoverlay="):
			name := strings.TrimPrefix(line, "dtoverlay=")
			if i := strings.IndexByte(name, ','); i >= 0 {
				name = name[:i]
			}
			if name = strings.TrimSpace(name); name != "" {
				cfg.Overlays = append(cfg.Overlays, name)
			}
		}
	}
	return cfg
}

// FirmwareFiles lists what the firmware fetches after config.txt, in
// order: the fixup file, the board's device tree, every overlay named in
// config.txt, cmdline.txt (which may be absent) and the kernel.
func (m Model) FirmwareFiles(cfg BootConfig) []FileSpec {
	var files []FileSpec
	if m.Fixup != "" {
		files = append(files, FileSpec{Name: m.Fixup})
	}
	files = append(files, FileSpec{Name: m.DTB})
	for _, overlay := range cfg.Overlays {
		files = append(files, FileSpec{Name: "overlays/" + overlay + ".dtbo"})
	}
	files = append(files, FileSpec{Name: "cmdline.txt", Optional: true})
	files = append(files, FileSpec{Name: cfg.Kernel})
	return files
}

// FileSpec is one file in the boot sequence.
type FileSpec struct {
	// Name is the path the bootloader asks for, before the prefix.
	Name string
	// Optional files may be absent; the bootloader continues without
	// them.
	Optional bool
}
