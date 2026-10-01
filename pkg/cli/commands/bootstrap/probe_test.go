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

package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

func TestProbeOptions(t *testing.T) {
	logger := logging.DefaultLogger()
	good := func() *probeRPiFlags {
		return &probeRPiFlags{iface: "eth1", serial: "9ffefdef", mac: "dc:a6:32:01:36:c2", revision: "0xc03111", model: "rpi4", prefix: "serial"}
	}

	t.Run("a Pi 4 with the serial prefix", func(t *testing.T) {
		opts, err := probeOptions(good(), logger)
		require.NoError(t, err)
		assert.Equal(t, "eth1", opts.Interface)
		assert.Equal(t, uint32(0x9ffefdef), opts.Identity.Serial)
		assert.Equal(t, uint32(0x00c03111), opts.Identity.Revision)
		assert.Equal(t, "dc:a6:32:01:36:c2", opts.Identity.MAC.String())
		assert.Equal(t, "rpi4", opts.Model.Name)
		assert.Equal(t, rpinetboot.PrefixSerial, opts.Prefix)
		assert.Same(t, logger, opts.Logger)
	})

	t.Run("mac and string prefixes", func(t *testing.T) {
		f := good()
		f.prefix = "mac"
		opts, err := probeOptions(f, logger)
		require.NoError(t, err)
		assert.Equal(t, rpinetboot.PrefixMAC, opts.Prefix)

		f.prefix, f.prefixStr = "string", "lab/"
		opts, err = probeOptions(f, logger)
		require.NoError(t, err)
		assert.Equal(t, rpinetboot.PrefixString, opts.Prefix)
		assert.Equal(t, "lab/", opts.PrefixString)
	})

	for name, mutate := range map[string]func(*probeRPiFlags){
		"no interface":       func(f *probeRPiFlags) { f.iface = "" },
		"bad serial":         func(f *probeRPiFlags) { f.serial = "xyz" },
		"serial too long":    func(f *probeRPiFlags) { f.serial = "123456789" },
		"empty serial":       func(f *probeRPiFlags) { f.serial = "" },
		"bad mac":            func(f *probeRPiFlags) { f.mac = "not-a-mac" },
		"bad revision":       func(f *probeRPiFlags) { f.revision = "zz" },
		"unknown model":      func(f *probeRPiFlags) { f.model = "rpi2" },
		"unknown prefix":     func(f *probeRPiFlags) { f.prefix = "uuid" },
		"string without str": func(f *probeRPiFlags) { f.prefix = "string" },
	} {
		t.Run(name, func(t *testing.T) {
			f := good()
			mutate(f)
			_, err := probeOptions(f, logger)
			var invalid *ErrProbeInvalidFlag
			require.ErrorAs(t, err, &invalid, name)
			assert.NotEmpty(t, invalid.Error())
		})
	}
}

func TestParseHex32(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint32
	}{
		{"9ffefdef", 0x9ffefdef},
		{"0x1234", 0x1234},
		{" ABCD ", 0xabcd}, // surrounding space and upper case are accepted
		{"0", 0},
	} {
		v, err := parseHex32(tc.in)
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, v, tc.in)
	}
	for _, in := range []string{"", "0x", "g", "100000000"} {
		_, err := parseHex32(in)
		assert.Error(t, err, in)
	}
}

func sampleReport() *rpinetboot.Report {
	mac, _ := net.ParseMAC("dc:a6:32:01:36:c2")
	_ = mac
	return &rpinetboot.Report{
		Offer:  rpinetboot.OfferReport{Server: net.ParseIP("10.99.99.1"), TFTPServer: net.ParseIP("10.99.99.1"), Proxy: false, Option43: rpinetboot.Option43(rpinetboot.Option43Match)},
		Lease:  &rpinetboot.LeaseReport{IP: net.ParseIP("10.99.99.100"), Mask: net.CIDRMask(24, 32), Router: net.ParseIP("10.99.99.1")},
		Prefix: "9ffefdef/",
		Files: []rpinetboot.FileReport{
			{Name: "start4.elf", Path: "9ffefdef/start4.elf", Bytes: 3, SHA256: "abc"},
			{Name: "cmdline.txt", Path: "cmdline.txt", Optional: true, Missing: true},
			{Name: "kernel8.img", Path: "kernel8.img"},
		},
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	f()
	require.NoError(t, w.Close())
	os.Stdout = orig
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func TestPrintProbeReport_JSON(t *testing.T) {
	out := captureStdout(t, func() {
		printProbeReport(sampleReport(), &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON})
	})
	var view probeReportView
	require.NoError(t, json.Unmarshal([]byte(out), &view), out)
	assert.Equal(t, "10.99.99.1", view.Offer.TFTPServer)
	assert.False(t, view.Offer.Proxy)
	require.NotNil(t, view.Lease)
	assert.Equal(t, "10.99.99.100", view.Lease.IP)
	assert.Equal(t, "255.255.255.0", view.Lease.Mask)
	assert.Equal(t, "9ffefdef/", view.Prefix)
	require.Len(t, view.Files, 3)
	assert.Equal(t, "9ffefdef/start4.elf", view.Files[0].Path)
	assert.True(t, view.Files[1].Missing)
}

func TestPrintProbeReport_Table(t *testing.T) {
	out := captureStdout(t, func() {
		printProbeReport(sampleReport(), &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true})
	})
	assert.Contains(t, out, "9ffefdef/start4.elf")
	assert.Contains(t, out, "absent (optional)")
	assert.Contains(t, out, "failed", "a file with nothing received is a failure")
	assert.Contains(t, out, "10.99.99.100/255.255.255.0")

	assert.NotPanics(t, func() { printProbeReport(nil, nil) }, "nothing to print before the DHCP exchange began")
	proxy := sampleReport()
	proxy.Lease = nil
	proxy.Offer.Proxy = true
	out = captureStdout(t, func() { printProbeReport(proxy, nil) })
	assert.Contains(t, out, "true")
}

func TestNewProbeCommand(t *testing.T) {
	cmd := newProbeCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	rpi, _, err := cmd.Find([]string{"rpi"})
	require.NoError(t, err)
	assert.Equal(t, "rpi", rpi.Name())
	for _, flag := range []string{"interface", "serial", "mac", "revision", "model", "prefix", "prefix-str", "option43", "timeout"} {
		assert.NotNil(t, rpi.Flags().Lookup(flag), flag)
	}
	assert.Equal(t, rpinetboot.Option43Match, rpi.Flags().Lookup("option43").DefValue)

	// Bad flags fail before any socket is opened.
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"rpi", "--interface", "", "--serial", "1", "--mac", "dc:a6:32:01:36:c2"})
	err = cmd.Execute()
	var invalid *ErrProbeInvalidFlag
	assert.ErrorAs(t, err, &invalid)
}
