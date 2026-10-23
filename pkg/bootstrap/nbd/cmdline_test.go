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

package nbd

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

const nbdModel = disklessroot.ParamBootModel + "=" + BootModel

func TestParseServerAddr(t *testing.T) {
	tests := []struct {
		value string
		want  ServerAddr
	}{
		{"192.0.2.1:10809", ServerAddr{Host: "192.0.2.1", Port: 10809}},
		{"[fd00:405::1]:10809", ServerAddr{Host: "fd00:405::1", Port: 10809}},
		{"boot-01.prov.example:65535", ServerAddr{Host: "boot-01.prov.example", Port: 65535}},
	}
	for _, tc := range tests {
		got, err := ParseServerAddr(tc.value)
		if err != nil {
			t.Fatalf("ParseServerAddr(%q): %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("ParseServerAddr(%q) = %+v, want %+v", tc.value, got, tc.want)
		}
		if got.String() != tc.value {
			t.Fatalf("String() = %q, want the value it parsed, %q", got.String(), tc.value)
		}
	}
}

func TestParseServerAddr_Malformed(t *testing.T) {
	for _, value := range []string{
		"",
		"192.0.2.1",              // no default port
		"192.0.2.1:",             // empty port
		"192.0.2.1:0",            // port zero
		"192.0.2.1:65536",        // out of range
		"192.0.2.1:nbd",          // a service name is not a port
		":10809",                // no host
		"fd00::1:10809",         // IPv6 without brackets
		"[fe80::1%eth0]:10809",  // a zone names no server
		"-boot.example:10809",   // label begins with a hyphen
		"boot..example:10809",   // empty label
		"boot_01.example:10809", // underscore
		"boot/01:10809",         // not a host
		strings.Repeat("a", 64) + ".example:10809", // label too long
	} {
		_, err := ParseServerAddr(value)
		var cmdErr ErrCmdline
		if !errors.As(err, &cmdErr) || cmdErr.Param != ParamServer {
			t.Errorf("ParseServerAddr(%q) = %v, want ErrCmdline on %s", value, err, ParamServer)
		}
	}
}

func TestServerAddr_Validate(t *testing.T) {
	if err := (ServerAddr{Host: "192.0.2.1", Port: 10809}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, addr := range []ServerAddr{{Host: "192.0.2.1"}, {Port: 10809}, {Host: strings.Repeat("a.", 127) + "a", Port: 1}} {
		var cmdErr ErrCmdline
		if err := addr.Validate(); !errors.As(err, &cmdErr) {
			t.Errorf("Validate(%+v) = %v, want ErrCmdline", addr, err)
		}
	}
}

func TestServerAddr_Arg(t *testing.T) {
	addr := ServerAddr{Host: "192.0.2.1", Port: 10809}
	if got, want := addr.Arg(), "platform_nbd_server=192.0.2.1:10809"; got != want {
		t.Fatalf("Arg() = %q, want %q", got, want)
	}
	parsed, ok, err := ServerFromCmdline(nbdModel + " " + addr.Arg())
	if err != nil || !ok || parsed != addr {
		t.Fatalf("ServerFromCmdline(Arg()) = %+v, %v, %v; want the address back", parsed, ok, err)
	}
}

func TestServerFromCmdline(t *testing.T) {
	cmdline := "BOOT_IMAGE=/vmlinuz ro " + nbdModel + " " + ParamServer + "=192.0.2.1:10809 console=ttyAMA0"
	addr, ok, err := ServerFromCmdline(cmdline)
	if err != nil || !ok {
		t.Fatalf("ServerFromCmdline = %v, %v; want the address", ok, err)
	}
	if want := (ServerAddr{Host: "192.0.2.1", Port: 10809}); addr != want {
		t.Fatalf("addr = %+v, want %+v", addr, want)
	}
}

func TestServerFromCmdline_OtherBootModelsAreNotRead(t *testing.T) {
	for _, cmdline := range []string{
		"ro console=ttyAMA0",
		ParamServer + "=192.0.2.1:10809",                  // no selector
		ParamServer + "=bogus " + ParamServer + "=twice", // not read, so not refused
		disklessroot.ParamBootModel + "=diskless " + ParamServer + "=192.0.2.1:10809",
		disklessroot.ParamBootModel + "=diskless-nbd-extra " + ParamServer + "=192.0.2.1:10809",
	} {
		addr, ok, err := ServerFromCmdline(cmdline)
		if err != nil || ok || addr != (ServerAddr{}) {
			t.Errorf("ServerFromCmdline(%q) = %+v, %v, %v; want nothing read", cmdline, addr, ok, err)
		}
	}
}

func TestServerFromCmdline_Refused(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		param   string
		ok      bool
	}{
		{"missing address", nbdModel, ParamServer, true},
		{"empty address", nbdModel + " " + ParamServer + "=", ParamServer, true},
		{"bare key", nbdModel + " " + ParamServer, ParamServer, true},
		{"address twice", nbdModel + " " + ParamServer + "=192.0.2.1:10809 " + ParamServer + "=192.0.2.2:10809", ParamServer, true},
		{"no port", nbdModel + " " + ParamServer + "=192.0.2.1", ParamServer, true},
		{"boot model twice", nbdModel + " " + nbdModel + " " + ParamServer + "=192.0.2.1:10809", disklessroot.ParamBootModel, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok, err := ServerFromCmdline(tc.cmdline)
			var cmdErr ErrCmdline
			if !errors.As(err, &cmdErr) || cmdErr.Param != tc.param {
				t.Fatalf("err = %v, want ErrCmdline on %s", err, tc.param)
			}
			if ok != tc.ok || addr != (ServerAddr{}) {
				t.Fatalf("ServerFromCmdline = %+v, %v; want no address and ok %v", addr, ok, tc.ok)
			}
		})
	}
}
