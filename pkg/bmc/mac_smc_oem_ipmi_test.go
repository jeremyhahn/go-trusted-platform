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

package bmc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
)

// --- parseSmcOEMHostMAC ---------------------------------------------------

func TestParseSmcOEMHostMAC(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      string
		wantErr   bool
		wantBytes int
	}{
		{
			name: "6-byte response parses directly",
			data: []byte{0x00, 0x25, 0x90, 0x00, 0x02, 0xAA},
			want: "00:25:90:00:02:aa",
		},
		{
			name: "7-byte response with leading reserved byte",
			data: []byte{0x00, 0x00, 0x25, 0x90, 0x00, 0x02, 0xAA},
			want: "00:25:90:00:02:aa",
		},
		{
			name: "7-byte response with trailing byte falls back to leading 6",
			// The preferred candidate [1:7] starts with 0x25, whose
			// multicast bit is set, so it is rejected as implausible and
			// the parser falls back to the leading 6 bytes [0:6].
			data: []byte{0x00, 0x25, 0x90, 0x00, 0x02, 0xAA, 0x01},
			want: "00:25:90:00:02:aa",
		},
		{
			name: "10-byte X10 ATEN response: 4-byte OEM header then MAC",
			// The exact shape returned by a real X10 ATEN BMC 4.0
			// (verified live 2026-08-16 against a chassis whose MAC
			// ac:1f:6b:00:01:02 was independently known): 3-byte IANA
			// enterprise number + reserved byte, then the host MAC.
			data: []byte{0x7C, 0x2A, 0x00, 0x00, 0xAC, 0x1F, 0x6B, 0x00, 0x01, 0x02},
			want: "ac:1f:6b:00:01:02",
		},
		{
			name: "10-byte response with MAC in leading bytes falls back",
			// Preferred trailing window [4:10] starts with 0x01
			// (multicast) → rejected; leading 6 bytes parse.
			data: []byte{0x00, 0x25, 0x90, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x00},
			want: "00:25:90:00:01:aa",
		},
		{
			name:      "10-byte response with no plausible candidate fails",
			data:      []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr:   true,
			wantBytes: 10,
		},
		{
			name:      "short response returns ErrOEMMACParse with byte count",
			data:      []byte{0x00, 0x25, 0x90},
			wantErr:   true,
			wantBytes: 3,
		},
		{
			name:      "empty response returns ErrOEMMACParse",
			data:      nil,
			wantErr:   true,
			wantBytes: 0,
		},
		{
			name:      "oversized garbage returns ErrOEMMACParse",
			data:      []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33},
			wantErr:   true,
			wantBytes: 8,
		},
		{
			name:      "all-zero MAC is rejected as implausible",
			data:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr:   true,
			wantBytes: 6,
		},
		{
			name:      "broadcast MAC is rejected as implausible",
			data:      []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr:   true,
			wantBytes: 6,
		},
		{
			name:      "multicast MAC is rejected as implausible",
			data:      []byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01},
			wantErr:   true,
			wantBytes: 6,
		},
		{
			name:      "7-byte response with no plausible candidate fails",
			data:      []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr:   true,
			wantBytes: 7,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSmcOEMHostMAC(tc.data)
			if tc.wantErr {
				var parseErr ErrOEMMACParse
				if !errors.As(err, &parseErr) {
					t.Fatalf("expected ErrOEMMACParse, got %T: %v", err, err)
				}
				if parseErr.Bytes != tc.wantBytes {
					t.Errorf("ErrOEMMACParse.Bytes = %d, want %d", parseErr.Bytes, tc.wantBytes)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseSmcOEMHostMAC = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- sendSmcOEMHostMAC ----------------------------------------------------

func TestSendSmcOEMHostMAC(t *testing.T) {
	t.Run("issues 0x30/0x21 with no payload and returns the MAC", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(smcOEMNetFn, smcOEMCmdHostMAC)] = []byte{0x00, 0x25, 0x90, 0x00, 0x02, 0xAA}

		mac, err := sendSmcOEMHostMAC(fake, slog.Default())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac != "00:25:90:00:02:aa" {
			t.Errorf("mac = %q, want %q", mac, "00:25:90:00:02:aa")
		}
		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdHostMAC)
		if !ok {
			t.Fatal("expected an OEM 0x30/0x21 send")
		}
		if len(sent.data) != 0 {
			t.Errorf("OEM 0x21 payload = % x, want empty", sent.data)
		}
	})

	t.Run("wire error is wrapped as ErrOEMMACCommand", func(t *testing.T) {
		fake := newFakeIPMISession()
		wire := ErrCompletionCode{Code: 0xC1, Command: smcOEMCmdHostMAC}
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdHostMAC)] = wire

		_, err := sendSmcOEMHostMAC(fake, slog.Default())
		var cmdErr ErrOEMMACCommand
		if !errors.As(err, &cmdErr) {
			t.Fatalf("expected ErrOEMMACCommand, got %T: %v", err, err)
		}
		if !errors.Is(err, wire) {
			t.Errorf("expected wrapped wire error, got %v", err)
		}
	})

	t.Run("malformed response surfaces ErrOEMMACParse", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(smcOEMNetFn, smcOEMCmdHostMAC)] = []byte{0x01, 0x02}

		_, err := sendSmcOEMHostMAC(fake, slog.Default())
		var parseErr ErrOEMMACParse
		if !errors.As(err, &parseErr) {
			t.Fatalf("expected ErrOEMMACParse, got %T: %v", err, err)
		}
		if parseErr.Bytes != 2 {
			t.Errorf("ErrOEMMACParse.Bytes = %d, want 2", parseErr.Bytes)
		}
	})
}

// --- ipmiClient.HostMACAddress -------------------------------------------

func TestIPMIClient_HostMACAddress(t *testing.T) {
	t.Run("Supermicro vendor returns host MAC via OEM command", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.responses[ipmiKey(smcOEMNetFn, smcOEMCmdHostMAC)] = []byte{0x00, 0x25, 0x90, 0x00, 0x02, 0xAA}
		c := oemTestClient(fake)

		mac, err := c.HostMACAddress(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac != "00:25:90:00:02:aa" {
			t.Errorf("mac = %q, want %q", mac, "00:25:90:00:02:aa")
		}
	})

	t.Run("7-byte firmware response is handled", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.responses[ipmiKey(smcOEMNetFn, smcOEMCmdHostMAC)] = []byte{0x00, 0x0C, 0xC4, 0x7A, 0x12, 0x34, 0x56}
		c := oemTestClient(fake)

		mac, err := c.HostMACAddress(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac != "0c:c4:7a:12:34:56" {
			t.Errorf("mac = %q, want %q", mac, "0c:c4:7a:12:34:56")
		}
	})

	t.Run("non-Supermicro vendor returns ErrMACDiscoveryUnsupported without 0x21 send", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(674) // Dell IANA
		c := oemTestClient(fake)

		_, err := c.HostMACAddress(context.Background())
		var unsupported ErrMACDiscoveryUnsupported
		if !errors.As(err, &unsupported) {
			t.Fatalf("expected ErrMACDiscoveryUnsupported, got %T: %v", err, err)
		}
		if unsupported.Protocol != ProtocolIPMI {
			t.Errorf("Protocol = %q, want %q", unsupported.Protocol, ProtocolIPMI)
		}
		if n := fake.countSends(smcOEMNetFn, smcOEMCmdHostMAC); n != 0 {
			t.Errorf("expected no OEM 0x21 sends for non-Supermicro vendor, got %d", n)
		}
	})

	t.Run("malformed OEM response surfaces ErrOEMMACParse", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.responses[ipmiKey(smcOEMNetFn, smcOEMCmdHostMAC)] = []byte{0xAB}
		c := oemTestClient(fake)

		_, err := c.HostMACAddress(context.Background())
		var parseErr ErrOEMMACParse
		if !errors.As(err, &parseErr) {
			t.Fatalf("expected ErrOEMMACParse, got %T: %v", err, err)
		}
		if parseErr.Bytes != 1 {
			t.Errorf("ErrOEMMACParse.Bytes = %d, want 1", parseErr.Bytes)
		}
	})

	t.Run("closed client returns ErrClientClosed", func(t *testing.T) {
		fake := newFakeIPMISession()
		c := oemTestClient(fake)
		if err := c.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		_, err := c.HostMACAddress(context.Background())
		var closed ErrClientClosed
		if !errors.As(err, &closed) {
			t.Fatalf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})
}

// --- DiscoverMACs IPMI OEM dispatch --------------------------------------

func TestDiscoverMACs_IPMIOEM(t *testing.T) {
	t.Run("OEM success returns the MAC without a Redfish probe", func(t *testing.T) {
		var gotConfig *Config
		stubIPMIOEMHostMAC(t, func(_ context.Context, config *Config, _ *slog.Logger) (string, error) {
			gotConfig = config
			return "00:25:90:00:02:aa", nil
		})

		config := &Config{
			Address:  "192.0.2.1",
			Port:     623,
			Protocol: ProtocolIPMI,
		}
		macs, err := DiscoverMACs(context.Background(), config, newTestLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(macs) != 1 || macs[0] != "00:25:90:00:02:aa" {
			t.Errorf("macs = %v, want [00:25:90:00:02:aa]", macs)
		}
		if gotConfig != config {
			t.Error("expected the OEM path to receive the caller's config")
		}
	})

	t.Run("OEM failure degrades to ErrMACDiscoveryUnsupported when Redfish is unreachable", func(t *testing.T) {
		stubIPMIOEMHostMAC(t, func(context.Context, *Config, *slog.Logger) (string, error) {
			return "", ErrOEMMACParse{Bytes: 3}
		})

		// Point the Redfish probe at a loopback port that is guaranteed
		// closed (bind, read the port, release it) so the fallthrough
		// fails with an immediate connection refusal instead of a
		// multi-second dial timeout against an unroutable address.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to reserve loopback port: %v", err)
		}
		closedPort := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		originalProbePort := redfishProbePort
		redfishProbePort = closedPort
		t.Cleanup(func() { redfishProbePort = originalProbePort })

		config := &Config{
			Address:  "127.0.0.1",
			Port:     623,
			Protocol: ProtocolIPMI,
		}
		_, discoverErr := DiscoverMACs(context.Background(), config, newTestLogger())
		var unsupported ErrMACDiscoveryUnsupported
		if !errors.As(discoverErr, &unsupported) {
			t.Fatalf("expected ErrMACDiscoveryUnsupported, got %T: %v", discoverErr, discoverErr)
		}
	})
}

// --- error strings --------------------------------------------------------

func TestOEMMACErrors_ErrorStrings(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrOEMMACParse carries byte count",
			err:  ErrOEMMACParse{Bytes: 3},
			want: "bmc: OEM host MAC response unparsable (3 bytes)",
		},
		{
			name: "ErrOEMMACCommand carries cause",
			err:  ErrOEMMACCommand{Cause: errors.New("timeout")},
			want: "bmc: OEM host MAC command failed: timeout",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}
