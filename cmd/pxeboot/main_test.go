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

package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

func TestFirmwareOverrides(t *testing.T) {
	f := firmwareOverrides{}
	fs := flag.NewFlagSet("pxeboot", flag.ContinueOnError)
	fs.Var(f, "firmware-override", "")
	require.NoError(t, fs.Parse([]string{
		"--firmware-override", "snponly-aarch64.efi=/data/firmware/snponly-aarch64.efi",
		"--firmware-override", "ipxe.efi=/data/firmware/ipxe.efi",
	}))
	assert.Equal(t, firmwareOverrides{"snponly-aarch64.efi": "/data/firmware/snponly-aarch64.efi", "ipxe.efi": "/data/firmware/ipxe.efi"}, f)
	assert.Equal(t, "ipxe.efi=/data/firmware/ipxe.efi,snponly-aarch64.efi=/data/firmware/snponly-aarch64.efi", f.String(), "sorted")

	for _, bad := range []string{"no-equals", "=path", "name=", "ipxe.efi=/again"} {
		assert.Error(t, f.Set(bad), bad)
	}
}

func TestValidateRequiredFlags(t *testing.T) {
	require.NoError(t, validateRequiredFlags("m", "/data/media", "1.1.1.1", "1.1.1.2", "1.1.1.3"))
	err := validateRequiredFlags("", "", "1.1.1.1", "", "1.1.1.3")
	var msg *MessageError
	require.ErrorAs(t, err, &msg)
	assert.Equal(t, "required flags not set: --dhcp-range-start, --manifest, --media-dir", msg.Error(), "every missing flag, in a stable order")
}

func TestParseDHCPOptionFlags(t *testing.T) {
	gateway, dns, err := parseDHCPOptionFlags("192.0.2.1", "192.0.2.1, 1.1.1.1,9.9.9.9")
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", gateway)
	assert.Equal(t, []string{"192.0.2.1", "1.1.1.1", "9.9.9.9"}, dns, "every server, in order, trimmed")

	gateway, dns, err = parseDHCPOptionFlags("", "")
	require.NoError(t, err, "no gateway is no router (BOOTSTRAP_NO_ROUTER)")
	assert.Empty(t, gateway)
	assert.Nil(t, dns)
}

func TestParseDHCPOptionFlags_Refused(t *testing.T) {
	for _, tt := range []struct {
		name, gateway, dns, flag, value string
	}{
		{name: "gateway not an address", gateway: "router", flag: "dhcp-gateway", value: "router"},
		{name: "IPv6 gateway", gateway: "fd00::1", flag: "dhcp-gateway", value: "fd00::1"},
		{name: "bad server in a list", dns: "192.0.2.1,dns.example.com", flag: "dhcp-dns", value: "dns.example.com"},
		{name: "IPv6 server", dns: "fd00::53", flag: "dhcp-dns", value: "fd00::53"},
		{name: "empty entry", dns: "192.0.2.1,,1.1.1.1", flag: "dhcp-dns", value: ""},
		{name: "trailing comma", dns: "192.0.2.1,", flag: "dhcp-dns", value: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseDHCPOptionFlags(tt.gateway, tt.dns)
			var flagErr *FlagError
			require.ErrorAs(t, err, &flagErr)
			assert.Equal(t, tt.flag, flagErr.Flag)
			var addrErr *ipxe.DHCPAddressError
			require.ErrorAs(t, err, &addrErr)
			assert.Equal(t, tt.value, addrErr.Value)
		})
	}
}
