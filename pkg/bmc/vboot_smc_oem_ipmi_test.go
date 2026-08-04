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
	"testing"
)

// --- test session double ------------------------------------------------

// fakeIPMISession is an in-process ipmiSession that records every Send and
// answers from a per-(netfn,cmd) response/error table. It lets tests drive
// ipmiClient down the OEM dispatch path with no network, RMCP+ handshake,
// or TLS.
type fakeIPMISession struct {
	responses map[uint16][]byte
	errs      map[uint16]error
	sent      []sentIPMICmd
	closed    bool
}

type sentIPMICmd struct {
	netfn byte
	cmd   byte
	data  []byte
}

func newFakeIPMISession() *fakeIPMISession {
	return &fakeIPMISession{
		responses: make(map[uint16][]byte),
		errs:      make(map[uint16]error),
	}
}

func ipmiKey(netfn, cmd byte) uint16 { return uint16(netfn)<<8 | uint16(cmd) }

func (f *fakeIPMISession) Send(netfn, cmd byte, data []byte) ([]byte, error) {
	f.sent = append(f.sent, sentIPMICmd{netfn: netfn, cmd: cmd, data: append([]byte(nil), data...)})
	k := ipmiKey(netfn, cmd)
	if err := f.errs[k]; err != nil {
		return nil, err
	}
	return f.responses[k], nil
}

func (f *fakeIPMISession) ActivateSOL(_ context.Context, _ byte) (*SOLSession, error) {
	return nil, ErrUnsupportedOperation{Operation: "console"}
}

func (f *fakeIPMISession) Close() error {
	f.closed = true
	return nil
}

// countSends returns how many recorded sends matched the given netfn/cmd.
func (f *fakeIPMISession) countSends(netfn, cmd byte) int {
	n := 0
	for _, s := range f.sent {
		if s.netfn == netfn && s.cmd == cmd {
			n++
		}
	}
	return n
}

// lastSend returns the most recent recorded send for the given netfn/cmd.
func (f *fakeIPMISession) lastSend(netfn, cmd byte) (sentIPMICmd, bool) {
	for i := len(f.sent) - 1; i >= 0; i-- {
		if f.sent[i].netfn == netfn && f.sent[i].cmd == cmd {
			return f.sent[i], true
		}
	}
	return sentIPMICmd{}, false
}

// deviceIDResponse builds a Get Device ID response whose 3-byte
// manufacturer IANA field (bytes 6..8) encodes iana little-endian. The
// response is padded to 12 bytes so Info()'s len>=12 gate also accepts it.
func deviceIDResponse(iana uint32) []byte {
	resp := make([]byte, 12)
	resp[6] = byte(iana)
	resp[7] = byte(iana >> 8)
	resp[8] = byte(iana >> 16)
	return resp
}

func oemTestClient(session ipmiSession) *ipmiClient {
	return &ipmiClient{
		config: &Config{
			Address:  "127.0.0.1",
			Port:     623,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolIPMI,
		},
		logger:  slog.Default(),
		session: session,
	}
}

// --- sendSmcOEMBootOverride ---------------------------------------------

func TestSendSmcOEMBootOverride(t *testing.T) {
	t.Run("PXE builds 0x30/0x70 payload and succeeds", func(t *testing.T) {
		fake := newFakeIPMISession()
		if err := sendSmcOEMBootOverride(fake, slog.Default(), BootDevicePXE, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected an OEM 0x30/0x70 send")
		}
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootPXE}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
	})

	t.Run("None maps to disable code", func(t *testing.T) {
		fake := newFakeIPMISession()
		if err := sendSmcOEMBootOverride(fake, slog.Default(), BootDeviceNone, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sent, _ := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootDisable}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
	})

	t.Run("non-PXE device returns ErrBootOverrideUnsupported without a send", func(t *testing.T) {
		fake := newFakeIPMISession()
		err := sendSmcOEMBootOverride(fake, slog.Default(), BootDeviceDisk, false)
		var target ErrBootOverrideUnsupported
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootOverrideUnsupported, got %T: %v", err, err)
		}
		if len(fake.sent) != 0 {
			t.Errorf("expected no OEM send for unsupported device, got %d sends", len(fake.sent))
		}
	})

	t.Run("wire error is wrapped as ErrBootDevice", func(t *testing.T) {
		fake := newFakeIPMISession()
		wire := errors.New("completion code 0x80")
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = wire
		err := sendSmcOEMBootOverride(fake, slog.Default(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if !errors.Is(err, wire) {
			t.Errorf("expected wrapped wire error, got %v", err)
		}
	})
}

// --- manufacturerName (IANA -> vendor) ----------------------------------

func TestIPMIClient_ManufacturerName(t *testing.T) {
	t.Run("Supermicro IANA maps to supermicro", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		if got := c.manufacturerName(context.Background()); got != "supermicro" {
			t.Errorf("manufacturerName = %q, want %q", got, "supermicro")
		}
	})

	t.Run("unknown IANA maps to empty", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(999)
		c := oemTestClient(fake)
		if got := c.manufacturerName(context.Background()); got != "" {
			t.Errorf("manufacturerName = %q, want empty", got)
		}
	})

	t.Run("malformed (short) response maps to empty", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = []byte{0x01, 0x02}
		c := oemTestClient(fake)
		if got := c.manufacturerName(context.Background()); got != "" {
			t.Errorf("manufacturerName = %q, want empty", got)
		}
	})

	t.Run("result is cached after first resolution", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)
		_ = c.manufacturerName(context.Background())
		_ = c.manufacturerName(context.Background())
		if n := fake.countSends(netFnApp, cmdGetDeviceID); n != 1 {
			t.Errorf("expected Get Device ID issued once (cached), got %d", n)
		}
	})
}

// --- SetBootDevice OEM dispatch -----------------------------------------

func TestIPMIClient_SetBootDevice_OEMPath(t *testing.T) {
	t.Run("Supermicro PXE takes OEM path and returns nil without Redfish", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		c := oemTestClient(fake)

		if err := c.SetBootDevice(context.Background(), BootDevicePXE, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sent, ok := fake.lastSend(smcOEMNetFn, smcOEMCmdBootOption)
		if !ok {
			t.Fatal("expected the OEM 0x30/0x70 command to be issued")
		}
		want := []byte{smcOEMSubBootOverride, smcOEMBootSet, smcOEMBootPXE}
		if !bytesEqual(sent.data, want) {
			t.Errorf("OEM payload = % x, want % x", sent.data, want)
		}
		// The OEM override is authoritative: SetBootDevice must short-circuit
		// before lazily creating a Redfish client.
		if c.redfishClient != nil {
			t.Error("expected no Redfish client to be created on the OEM success path")
		}
	})

	t.Run("OEM wire error surfaces as ErrBootDevice", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.errs[ipmiKey(smcOEMNetFn, smcOEMCmdBootOption)] = errors.New("completion code 0x80")
		c := oemTestClient(fake)

		err := c.SetBootDevice(context.Background(), BootDevicePXE, false)
		var target ErrBootDevice
		if !errors.As(err, &target) {
			t.Fatalf("expected ErrBootDevice, got %T: %v", err, err)
		}
		if c.redfishClient != nil {
			t.Error("expected no Redfish client to be created on the OEM error path")
		}
	})
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
