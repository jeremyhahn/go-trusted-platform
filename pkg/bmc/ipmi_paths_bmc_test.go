package bmc

import (
	"context"
	"errors"
	"testing"
)

// errIPMIPathsTransport is the transport failure the fake session hands
// back for a command under test.
var errIPMIPathsTransport = errors.New("rmcp exchange timed out")

func TestIPMIPaths_PowerCommandSendErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		operation string
		call      func(*ipmiClient) error
	}{
		{"on", func(c *ipmiClient) error { return c.PowerOn(ctx) }},
		{"off", func(c *ipmiClient) error { return c.PowerOff(ctx) }},
		{"reset", func(c *ipmiClient) error { return c.PowerReset(ctx) }},
		{"cycle", func(c *ipmiClient) error { return c.PowerCycle(ctx) }},
	}
	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			fake := newFakeIPMISession()
			fake.errs[ipmiKey(netFnChassis, cmdChassisControl)] = errIPMIPathsTransport
			err := tt.call(oemTestClient(fake))

			var powerErr ErrPowerOperation
			if !errors.As(err, &powerErr) || powerErr.Operation != tt.operation {
				t.Fatalf("error = %v, want ErrPowerOperation{Operation: %q}", err, tt.operation)
			}
			if !errors.Is(err, errIPMIPathsTransport) {
				t.Errorf("error = %v, want the transport cause kept", err)
			}
		})
	}
}

func TestIPMIPaths_PowerStatus(t *testing.T) {
	ctx := context.Background()
	t.Run("power bit set is on", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnChassis, cmdChassisStatus)] = []byte{0x01, 0x00, 0x00}
		if got, err := oemTestClient(fake).PowerStatus(ctx); err != nil || got != PowerStateOn {
			t.Fatalf("PowerStatus = %v, %v; want on", got, err)
		}
	})
	t.Run("power bit clear is off", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnChassis, cmdChassisStatus)] = []byte{0x60, 0x00, 0x00}
		if got, err := oemTestClient(fake).PowerStatus(ctx); err != nil || got != PowerStateOff {
			t.Fatalf("PowerStatus = %v, %v; want off", got, err)
		}
	})
	t.Run("empty response is too short", func(t *testing.T) {
		got, err := oemTestClient(newFakeIPMISession()).PowerStatus(ctx)
		var short ErrPacketTooShort
		if !errors.As(err, &short) || short.Expected != 1 || short.Actual != 0 {
			t.Fatalf("error = %v, want ErrPacketTooShort{1, 0}", err)
		}
		if got != PowerStateUnknown {
			t.Errorf("state = %v, want unknown", got)
		}
	})
	t.Run("transport error", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.errs[ipmiKey(netFnChassis, cmdChassisStatus)] = errIPMIPathsTransport
		_, err := oemTestClient(fake).PowerStatus(ctx)
		var powerErr ErrPowerOperation
		if !errors.As(err, &powerErr) || powerErr.Operation != "status" || !errors.Is(err, errIPMIPathsTransport) {
			t.Fatalf("error = %v, want ErrPowerOperation{status} wrapping the transport error", err)
		}
	})
}

func TestIPMIPaths_GetBootDevice(t *testing.T) {
	const unknownSelector = 0x3C
	if _, ok := ipmiBootDeviceFromBits[unknownSelector]; ok {
		t.Fatalf("selector %#x must be unmapped for this test", unknownSelector)
	}
	tests := []struct {
		name string
		resp []byte
		want BootDevice
	}{
		{"valid PXE override", []byte{0x01, 0x05, 0x80, bootDevicePXEBits, 0x00}, BootDevicePXE},
		{"valid disk override", []byte{0x01, 0x05, 0xE0, bootDeviceDiskBits, 0x00}, BootDeviceDisk},
		{"valid bit clear", []byte{0x01, 0x05, 0x00, bootDevicePXEBits, 0x00}, BootDeviceNone},
		{"unmapped selector", []byte{0x01, 0x05, 0x80, unknownSelector, 0x00}, BootDeviceNone},
		{"short response", []byte{0x01, 0x05, 0x80, bootDevicePXEBits}, BootDeviceNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeIPMISession()
			fake.responses[ipmiKey(netFnChassis, cmdGetSystemBootOptions)] = tt.resp
			got, err := oemTestClient(fake).GetBootDevice(context.Background())
			if err != nil || got != tt.want {
				t.Fatalf("GetBootDevice = %q, %v; want %q", got, err, tt.want)
			}
		})
	}

	t.Run("transport error", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.errs[ipmiKey(netFnChassis, cmdGetSystemBootOptions)] = errIPMIPathsTransport
		got, err := oemTestClient(fake).GetBootDevice(context.Background())
		var bootErr ErrBootDevice
		if !errors.As(err, &bootErr) || !errors.Is(err, errIPMIPathsTransport) {
			t.Fatalf("error = %v, want ErrBootDevice wrapping the transport error", err)
		}
		if got != BootDeviceNone {
			t.Errorf("device = %q, want none", got)
		}
	})
}

// noRedfishIPMIClient returns an IPMI client whose lazy Redfish fallback
// can never be built: an empty address fails Redfish config validation.
func noRedfishIPMIClient(fake *fakeIPMISession) *ipmiClient {
	c := oemTestClient(fake)
	c.config.Address = ""
	return c
}

func TestIPMIPaths_ISOCallsWithoutRedfishFallback(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func(*ipmiClient) error
	}{
		{"MountISO", func(c *ipmiClient) error { return c.MountISO(ctx, "http://10.0.0.5/boot.iso") }},
		{"UnmountISO", func(c *ipmiClient) error { return c.UnmountISO(ctx) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := noRedfishIPMIClient(newFakeIPMISession())
			var initErr ErrRedfishTransportInit
			if err := tt.call(c); !errors.As(err, &initErr) {
				t.Fatalf("error = %v, want ErrRedfishTransportInit", err)
			}
		})
	}
}

func TestIPMIPaths_VirtualMediaStatusWithoutRedfishFallback(t *testing.T) {
	info, err := noRedfishIPMIClient(newFakeIPMISession()).VirtualMediaStatus(context.Background())
	if err != nil {
		t.Fatalf("VirtualMediaStatus error = %v, want the unmounted default", err)
	}
	if info == nil || info.Mounted {
		t.Fatalf("info = %+v, want not mounted", info)
	}
}

func TestIPMIPaths_ResolveSOLPayloadInstanceRedfishPaths(t *testing.T) {
	ctx := context.Background()
	t.Run("no Redfish fallback defaults", func(t *testing.T) {
		c := noRedfishIPMIClient(newFakeIPMISession())
		if got := c.resolveSOLPayloadInstance(ctx); got != defaultSOLPayloadInstance {
			t.Errorf("instance = %#x, want the default", got)
		}
		if c.redfishClient != nil {
			t.Error("a failed fallback build must not leave a Redfish client behind")
		}
	})
	t.Run("non-Redfish fallback client defaults", func(t *testing.T) {
		c := oemTestClient(newFakeIPMISession())
		mock := NewMockClient()
		c.redfishClient = mock
		if got := c.resolveSOLPayloadInstance(ctx); got != defaultSOLPayloadInstance {
			t.Errorf("instance = %#x, want the default", got)
		}
		if mock.HardwareIdentityCalls() != 0 {
			t.Error("a non-Redfish fallback must not be asked for its identity")
		}
	})
	t.Run("discovered Redfish quirk wins", func(t *testing.T) {
		c := oemTestClient(newFakeIPMISession())
		rc := newVmBMCClient(t, &vmBMCServer{}, "Supermicro", false)
		c.redfishClient = rc
		want := rc.resolveQuirk().SOLPayloadInstance
		if want == 0 {
			t.Fatal("the Supermicro quirk must carry a SOL payload instance")
		}
		if got := c.resolveSOLPayloadInstance(ctx); got != want {
			t.Errorf("instance = %#x, want the Redfish quirk's %#x", got, want)
		}
	})
}

func TestIPMIPaths_ConsoleOnClosedClient(t *testing.T) {
	fake := newFakeIPMISession()
	c := oemTestClient(fake)
	c.closed.Store(true)
	sol, err := c.Console(context.Background())
	if !errors.As(err, new(ErrClientClosed)) || sol != nil {
		t.Fatalf("Console = %v, %v; want ErrClientClosed", sol, err)
	}
	if len(fake.sent) != 0 {
		t.Errorf("a closed client must not touch the BMC; %d sends", len(fake.sent))
	}
}

func TestIPMIPaths_GetSystemInfo(t *testing.T) {
	ctx := context.Background()
	t.Run("device ID transport error", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.errs[ipmiKey(netFnApp, cmdGetDeviceID)] = errIPMIPathsTransport
		info, err := oemTestClient(fake).GetSystemInfo(ctx)
		var invErr ErrInventory
		if !errors.As(err, &invErr) || !errors.Is(err, errIPMIPathsTransport) || info != nil {
			t.Fatalf("GetSystemInfo = %+v, %v; want ErrInventory wrapping the transport error", info, err)
		}
	})
	t.Run("FRU and chassis status fill the inventory", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnApp, cmdGetDeviceID)] = deviceIDResponse(ianaSupermicro)
		fake.serveFRU(fruWithIdentity("X11SPM-F", "SYS-5019C-MR"))
		fake.responses[ipmiKey(netFnChassis, cmdChassisStatus)] = []byte{0x00}
		info, err := oemTestClient(fake).GetSystemInfo(ctx)
		if err != nil {
			t.Fatalf("GetSystemInfo error = %v", err)
		}
		if info.Manufacturer != "Supermicro" || info.Product != "SuperServer" {
			t.Errorf("manufacturer/product = %q/%q, want the FRU product area", info.Manufacturer, info.Product)
		}
		if info.SerialNumber != "BSN" {
			t.Errorf("serial = %q, want the board serial when the product has none", info.SerialNumber)
		}
		if info.PowerState != PowerStateOff {
			t.Errorf("power = %v, want off", info.PowerState)
		}
	})
}

func TestIPMIPaths_ReadFRU(t *testing.T) {
	t.Run("zero area size", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = []byte{0x00, 0x00, 0x00}
		_, err := oemTestClient(fake).readFRU(0)
		var fruErr ErrFRURead
		if !errors.As(err, &fruErr) {
			t.Fatalf("error = %v, want ErrFRURead", err)
		}
	})
	t.Run("chunk transport error names the offset", func(t *testing.T) {
		fake := newFakeIPMISession()
		fake.responses[ipmiKey(netFnStorage, cmdGetFRUInventoryArea)] = []byte{0x40, 0x00, 0x00}
		fake.errs[ipmiKey(netFnStorage, cmdReadFRUData)] = errIPMIPathsTransport
		_, err := oemTestClient(fake).readFRU(0)
		var readErr ErrReadFRU
		if !errors.As(err, &readErr) || readErr.Offset != 0 || !errors.Is(err, errIPMIPathsTransport) {
			t.Fatalf("error = %v, want ErrReadFRU at offset 0 wrapping the transport error", err)
		}
	})
}

func TestIPMIPaths_ReadFRUBytesStopsOnBadChunks(t *testing.T) {
	tests := []struct {
		name  string
		chunk []byte
	}{
		{"empty response", nil},
		{"zero count", []byte{0x00}},
		{"count past the data", []byte{0x04, 0xAA, 0xBB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeIPMISession()
			first := true
			fake.handlers[ipmiKey(netFnStorage, cmdReadFRUData)] = func(_ []byte) ([]byte, error) {
				if first {
					first = false
					return []byte{0x02, 0x01, 0x02}, nil
				}
				return tt.chunk, nil
			}
			got, err := oemTestClient(fake).readFRUBytes(0, 0x40)
			if err != nil {
				t.Fatalf("readFRUBytes error = %v", err)
			}
			if !bytesEqual(got, []byte{0x01, 0x02}) {
				t.Errorf("data = %x, want only the first good chunk", got)
			}
		})
	}
}

func TestIPMIPaths_GetSensorsSkipsUnusableRecords(t *testing.T) {
	t.Run("unparseable full record is skipped", func(t *testing.T) {
		truncated := []byte{0x02, 0x00, 0x51, sdrRecordTypeFull, 0x00}
		fake := sdrSession(map[uint16]sdrEntry{
			0x0000: {next: 0x0002, record: fullSDR(0x0001, 0x10, 1, 1, "CPU Temp")},
			0x0002: {next: 0xFFFF, record: truncated},
		}, map[byte][]byte{0x10: {0x2A, 0xC0, 0x00}})
		sensors, err := oemTestClient(fake).GetSensors(context.Background())
		if err != nil {
			t.Fatalf("GetSensors error = %v", err)
		}
		if len(sensors) != 1 || sensors[0].Name != "CPU Temp" {
			t.Fatalf("sensors = %+v, want only CPU Temp", sensors)
		}
	})
	t.Run("short Get SDR response ends iteration", func(t *testing.T) {
		fake := sdrSession(map[uint16]sdrEntry{}, nil)
		fake.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, 0x01, 0x00, 0, 0, 0}
		fake.handlers[ipmiKey(netFnStorage, cmdGetSDR)] = func(_ []byte) ([]byte, error) {
			return []byte{0xFF}, nil
		}
		sensors, err := oemTestClient(fake).GetSensors(context.Background())
		if err != nil || len(sensors) != 0 {
			t.Fatalf("GetSensors = %+v, %v; want no sensors and no error", sensors, err)
		}
	})
}
