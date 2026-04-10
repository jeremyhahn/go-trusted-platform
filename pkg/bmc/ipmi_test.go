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
	"math"
	"testing"
	"time"
)

// --- Factory Tests ---

func TestIPMIClientFactory_NewClient(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())

	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			Address:  "192.168.1.100",
			Port:     623,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolIPMI,
		}
		client, err := factory.NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		client, err := factory.NewClient(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		var target ErrNilConfig
		if !errors.As(err, &target) {
			t.Errorf("expected ErrNilConfig, got %T: %v", err, err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})

	t.Run("invalid config missing address", func(t *testing.T) {
		cfg := &Config{
			Port:     623,
			Protocol: ProtocolIPMI,
		}
		client, err := factory.NewClient(cfg)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
		var target ErrInvalidConfig
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})
}

// --- Closed Client Tests ---

func TestIPMIClient_ClosedState(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())
	cfg := &Config{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
	}
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	ctx := context.Background()

	t.Run("PowerOn after close", func(t *testing.T) {
		err := client.PowerOn(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("PowerOff after close", func(t *testing.T) {
		err := client.PowerOff(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("PowerReset after close", func(t *testing.T) {
		err := client.PowerReset(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("PowerCycle after close", func(t *testing.T) {
		err := client.PowerCycle(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("PowerStatus after close", func(t *testing.T) {
		state, err := client.PowerStatus(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
		if state != PowerStateUnknown {
			t.Errorf("state = %q, want %q", state, PowerStateUnknown)
		}
	})

	t.Run("SetBootDevice after close", func(t *testing.T) {
		err := client.SetBootDevice(ctx, BootDevicePXE, false)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("GetBootDevice after close", func(t *testing.T) {
		_, err := client.GetBootDevice(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("MountISO after close", func(t *testing.T) {
		err := client.MountISO(ctx, "http://example.com/test.iso")
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("UnmountISO after close", func(t *testing.T) {
		err := client.UnmountISO(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("VirtualMediaStatus after close", func(t *testing.T) {
		_, err := client.VirtualMediaStatus(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("GetSensors after close", func(t *testing.T) {
		_, err := client.GetSensors(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("GetSystemInfo after close", func(t *testing.T) {
		_, err := client.GetSystemInfo(ctx)
		var target ErrClientClosed
		if !errors.As(err, &target) {
			t.Errorf("expected ErrClientClosed, got %T: %v", err, err)
		}
	})

	t.Run("double close is idempotent", func(t *testing.T) {
		err := client.Close()
		if err != nil {
			t.Errorf("second Close() should not error, got: %v", err)
		}
	})
}

// --- Virtual Media Unsupported Tests ---

func TestIPMIClient_MountISO_EmptyURL(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())
	cfg := &Config{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
	}
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	err = client.MountISO(context.Background(), "")
	var target ErrVirtualMedia
	if !errors.As(err, &target) {
		t.Errorf("expected ErrVirtualMedia, got %T: %v", err, err)
	}
}

func TestIPMIClient_MountISO_RedfishFallback(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())
	cfg := &Config{
		Address:  "127.0.0.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
	}
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// MountISO delegates to Redfish. With no Redfish server available,
	// it should return an error (connection refused or timeout).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.MountISO(ctx, "http://example.com/test.iso")
	if err == nil {
		t.Error("expected error from MountISO with no Redfish server")
	}
}

func TestIPMIClient_UnmountISO_RedfishFallback(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())
	cfg := &Config{
		Address:  "127.0.0.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
	}
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.UnmountISO(ctx)
	if err == nil {
		t.Error("expected error from UnmountISO with no Redfish server")
	}
}

func TestIPMIClient_VirtualMediaStatus_NotConnected(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())
	cfg := &Config{
		Address:  "127.0.0.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
	}
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// VirtualMediaStatus tries Redfish fallback; with no server available
	// it gracefully returns default (Mounted: false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	info, err := client.VirtualMediaStatus(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Mounted {
		t.Error("expected Mounted=false for IPMI virtual media status")
	}
}

// --- Boot Device Validation Tests ---

func TestIPMIClient_SetBootDevice_InvalidDevice(t *testing.T) {
	factory := NewIPMIClientFactory(slog.Default())
	cfg := &Config{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
	}
	client, err := factory.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	err = client.SetBootDevice(context.Background(), BootDevice("floppy"), false)
	var target ErrInvalidBootDevice
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidBootDevice, got %T: %v", err, err)
	}
}

// --- SDR Parsing Tests ---

func TestParseFullSensorRecord(t *testing.T) {
	t.Run("valid temperature sensor", func(t *testing.T) {
		// Full sensor record: 5-byte header + body.
		// Body needs at least 43 bytes + sensor name.
		// "CPU Temp" = 8 chars, so body = 43 + 8 = 51 bytes, total = 56.
		data := make([]byte, 56)

		// Header
		data[0] = 0x01 // Record ID low
		data[1] = 0x00 // Record ID high
		data[2] = 0x51 // SDR version
		data[3] = 0x01 // Record type: Full
		data[4] = 51   // Record length (body size)

		// Body (starting at data[5])
		body := data[5:]
		body[0] = 0x20 // Sensor Owner ID
		body[1] = 0x00 // Sensor Owner LUN
		body[2] = 0x05 // Sensor Number
		body[7] = 0x01 // Sensor Type: Temperature
		body[8] = 0x01 // Event/Reading Type: threshold

		// Sensor Units 2 = Base Unit at body offset 16
		body[16] = 1 // degrees C

		// M = 1 at body offsets 19-20
		body[19] = 0x01
		body[20] = 0x00

		// B = 0 at body offsets 21-22
		body[21] = 0x00
		body[22] = 0x00

		// R exponent = 0, B exponent = 0 at body offset 24
		body[24] = 0x00

		// Sensor name at body offsets 42-43+
		name := "CPU Temp"
		body[42] = 0xC0 | uint8(len(name))
		copy(body[43:], name)

		rec, err := parseFullSensorRecord(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.RecordID != 1 {
			t.Errorf("RecordID = %d, want 1", rec.RecordID)
		}
		if rec.SensorNumber != 5 {
			t.Errorf("SensorNumber = %d, want 5", rec.SensorNumber)
		}
		if rec.SensorType != 1 {
			t.Errorf("SensorType = %d, want 1", rec.SensorType)
		}
		if rec.Name != "CPU Temp" {
			t.Errorf("Name = %q, want %q", rec.Name, "CPU Temp")
		}
		if rec.BaseUnit != 1 {
			t.Errorf("BaseUnit = %d, want 1 (degrees C)", rec.BaseUnit)
		}
		if rec.M != 1 {
			t.Errorf("M = %d, want 1", rec.M)
		}
		if rec.B != 0 {
			t.Errorf("B = %d, want 0", rec.B)
		}
	})

	t.Run("negative M and B values", func(t *testing.T) {
		// Body needs 43 + 4 ("Vout") = 47, total = 52
		data := make([]byte, 52)
		data[3] = 0x01 // Record type: Full
		data[4] = 47

		body := data[5:]
		body[2] = 0x0A  // Sensor Number
		body[16] = 4    // Base Unit: Volts
		body[19] = 0xFF // M lower 8 = 0xFF
		body[20] = 0xC0 // M upper 2 = 11 -> M = 0x3FF = -1 in 10-bit two's complement
		body[21] = 0x00 // B lower 8 = 0
		body[22] = 0x00 // B upper 2 = 0
		body[24] = 0x00 // Rexp=0, Bexp=0

		body[42] = 0xC0 | 4 // "Vout"
		copy(body[43:], "Vout")

		rec, err := parseFullSensorRecord(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.M != -1 {
			t.Errorf("M = %d, want -1", rec.M)
		}
		if rec.SensorNumber != 0x0A {
			t.Errorf("SensorNumber = %d, want 10", rec.SensorNumber)
		}
	})

	t.Run("data too short", func(t *testing.T) {
		data := make([]byte, 20)
		data[3] = 0x01
		_, err := parseFullSensorRecord(data)
		if err == nil {
			t.Fatal("expected error for short data")
		}
		var target ErrSDRParse
		if !errors.As(err, &target) {
			t.Errorf("expected ErrSDRParse, got %T: %v", err, err)
		}
	})

	t.Run("sensor name fallback", func(t *testing.T) {
		// Minimum valid: 5 header + 43 body = 48
		data := make([]byte, 48)
		data[3] = 0x01
		data[4] = 43
		body := data[5:]
		body[2] = 0x03  // Sensor Number
		body[42] = 0xC1 // End-of-fields marker (no name)

		rec, err := parseFullSensorRecord(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Sensor_3"
		if rec.Name != expected {
			t.Errorf("Name = %q, want %q", rec.Name, expected)
		}
	})
}

func TestTwosComplement10(t *testing.T) {
	tests := []struct {
		name string
		val  uint16
		want int16
	}{
		{"zero", 0x000, 0},
		{"positive max", 0x1FF, 511},
		{"negative one", 0x3FF, -1},
		{"negative max", 0x200, -512},
		{"positive 100", 100, 100},
		{"mask extra bits", 0xFFF, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := twosComplement10(tt.val)
			if got != tt.want {
				t.Errorf("twosComplement10(0x%03X) = %d, want %d", tt.val, got, tt.want)
			}
		})
	}
}

func TestTwosComplement4(t *testing.T) {
	tests := []struct {
		name string
		val  uint8
		want int8
	}{
		{"zero", 0, 0},
		{"positive max", 7, 7},
		{"negative one", 0x0F, -1},
		{"negative max", 0x08, -8},
		{"positive 3", 3, 3},
		{"mask extra bits", 0xFF, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := twosComplement4(tt.val)
			if got != tt.want {
				t.Errorf("twosComplement4(0x%02X) = %d, want %d", tt.val, got, tt.want)
			}
		})
	}
}

// --- Sensor Reading Conversion Tests ---

func TestConvertSensorReading(t *testing.T) {
	tests := []struct {
		name string
		raw  uint8
		rec  sdrFullSensorRecord
		want float64
	}{
		{
			name: "simple M=1 B=0 exp=0",
			raw:  42,
			rec:  sdrFullSensorRecord{M: 1, B: 0, BExp: 0, RExp: 0},
			want: 42.0,
		},
		{
			name: "M=2 B=10 Bexp=0 Rexp=0",
			raw:  100,
			rec:  sdrFullSensorRecord{M: 2, B: 10, BExp: 0, RExp: 0},
			want: 210.0,
		},
		{
			name: "with R exponent",
			raw:  50,
			rec:  sdrFullSensorRecord{M: 1, B: 0, BExp: 0, RExp: -1},
			want: 5.0,
		},
		{
			name: "with B exponent",
			raw:  30,
			rec:  sdrFullSensorRecord{M: 1, B: 5, BExp: 2, RExp: 0},
			want: 530.0,
		},
		{
			name: "zero raw reading",
			raw:  0,
			rec:  sdrFullSensorRecord{M: 10, B: 0, BExp: 0, RExp: 0},
			want: 0.0,
		},
		{
			name: "max raw reading",
			raw:  255,
			rec:  sdrFullSensorRecord{M: 1, B: 0, BExp: 0, RExp: 0},
			want: 255.0,
		},
		{
			name: "negative M",
			raw:  100,
			rec:  sdrFullSensorRecord{M: -1, B: 0, BExp: 0, RExp: 0},
			want: -100.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertSensorReading(tt.raw, &tt.rec)
			if math.Abs(got-tt.want) > 0.001 {
				t.Errorf("convertSensorReading(%d, ...) = %f, want %f", tt.raw, got, tt.want)
			}
		})
	}
}

// --- Sensor Status Tests ---

func TestSensorStatus(t *testing.T) {
	t.Run("valid reading ok", func(t *testing.T) {
		r := &sensorReadingResponse{RawReading: 42, EventStatus: 0x00}
		if got := sensorStatus(r); got != "ok" {
			t.Errorf("sensorStatus = %q, want %q", got, "ok")
		}
	})

	t.Run("invalid reading", func(t *testing.T) {
		r := &sensorReadingResponse{RawReading: 0, EventStatus: 0x40}
		if got := sensorStatus(r); got != "unknown" {
			t.Errorf("sensorStatus = %q, want %q", got, "unknown")
		}
	})

	t.Run("scanning disabled", func(t *testing.T) {
		r := &sensorReadingResponse{RawReading: 0, EventStatus: 0x20}
		if got := sensorStatus(r); got != "unknown" {
			t.Errorf("sensorStatus = %q, want %q", got, "unknown")
		}
	})

	t.Run("upper critical threshold", func(t *testing.T) {
		r := &sensorReadingResponse{RawReading: 90, EventStatus: 0x00, ThresholdHigh: 0x10}
		if got := sensorStatus(r); got != "critical" {
			t.Errorf("sensorStatus = %q, want %q", got, "critical")
		}
	})

	t.Run("lower non-critical warning", func(t *testing.T) {
		r := &sensorReadingResponse{RawReading: 10, EventStatus: 0x00, ThresholdLow: 0x01}
		if got := sensorStatus(r); got != "warning" {
			t.Errorf("sensorStatus = %q, want %q", got, "warning")
		}
	})
}

// --- Sensor Unit String Tests ---

func TestSensorUnitString(t *testing.T) {
	tests := []struct {
		unit uint8
		want string
	}{
		{0, "unspecified"},
		{1, "degrees C"},
		{4, "Volts"},
		{5, "Amps"},
		{6, "Watts"},
		{18, "RPM"},
		{19, "Hz"},
		{255, "unspecified"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := sensorUnitString(tt.unit)
			if got != tt.want {
				t.Errorf("sensorUnitString(%d) = %q, want %q", tt.unit, got, tt.want)
			}
		})
	}
}

// --- FRU Parsing Tests ---

func TestParseFRU(t *testing.T) {
	t.Run("valid FRU with board and product areas", func(t *testing.T) {
		fru := make([]byte, 256)

		// Common header (8 bytes)
		fru[0] = 0x01 // Format version
		fru[1] = 0x00 // No internal use area
		fru[2] = 0x00 // No chassis info area
		fru[3] = 0x01 // Board area at offset 1*8 = 8
		fru[4] = 0x08 // Product area at offset 8*8 = 64 (well past board data)
		fru[7] = 0x00 // Checksum

		// Board Info Area at offset 8
		boardBase := 8
		fru[boardBase+0] = 0x01 // Format version
		fru[boardBase+1] = 0x07 // Length (7*8 = 56 bytes, enough for all fields)
		fru[boardBase+2] = 0x00 // Language

		// Board fields start at boardBase+6 (after 3-byte mfg date)
		offset := boardBase + 6
		// Board Manufacturer: "SMC"
		bmfg := "SMC"
		fru[offset] = 0xC0 | uint8(len(bmfg))
		offset++
		copy(fru[offset:], bmfg)
		offset += len(bmfg)
		// Board Product: "X11DPH"
		bprod := "X11DPH"
		fru[offset] = 0xC0 | uint8(len(bprod))
		offset++
		copy(fru[offset:], bprod)
		offset += len(bprod)
		// Board Serial: "SN123"
		bser := "SN123"
		fru[offset] = 0xC0 | uint8(len(bser))
		offset++
		copy(fru[offset:], bser)
		offset += len(bser)
		// End of fields
		fru[offset] = 0xC1

		// Product Info Area at offset 64
		prodBase := 64
		fru[prodBase+0] = 0x01 // Format version
		fru[prodBase+1] = 0x0A // Length
		fru[prodBase+2] = 0x00 // Language

		offset = prodBase + 3
		// Product Manufacturer: "Supermicro"
		pmfg := "Supermicro"
		fru[offset] = 0xC0 | uint8(len(pmfg))
		offset++
		copy(fru[offset:], pmfg)
		offset += len(pmfg)
		// Product Name: "SYS-6029P"
		pname := "SYS-6029P"
		fru[offset] = 0xC0 | uint8(len(pname))
		offset++
		copy(fru[offset:], pname)
		offset += len(pname)
		// Product Part Number: "AS-2024"
		ppn := "AS-2024"
		fru[offset] = 0xC0 | uint8(len(ppn))
		offset++
		copy(fru[offset:], ppn)
		offset += len(ppn)
		// Product Version: "1.0"
		pver := "1.0"
		fru[offset] = 0xC0 | uint8(len(pver))
		offset++
		copy(fru[offset:], pver)
		offset += len(pver)
		// Product Serial: "PSN987"
		pser := "PSN987"
		fru[offset] = 0xC0 | uint8(len(pser))
		offset++
		copy(fru[offset:], pser)
		offset += len(pser)
		// End of fields
		fru[offset] = 0xC1

		result, err := parseFRU(fru)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.BoardManufacturer != "SMC" {
			t.Errorf("BoardManufacturer = %q, want %q", result.BoardManufacturer, "SMC")
		}
		if result.BoardProduct != "X11DPH" {
			t.Errorf("BoardProduct = %q, want %q", result.BoardProduct, "X11DPH")
		}
		if result.BoardSerial != "SN123" {
			t.Errorf("BoardSerial = %q, want %q", result.BoardSerial, "SN123")
		}
		if result.ProductManufacturer != "Supermicro" {
			t.Errorf("ProductManufacturer = %q, want %q", result.ProductManufacturer, "Supermicro")
		}
		if result.ProductName != "SYS-6029P" {
			t.Errorf("ProductName = %q, want %q", result.ProductName, "SYS-6029P")
		}
		if result.ProductSerial != "PSN987" {
			t.Errorf("ProductSerial = %q, want %q", result.ProductSerial, "PSN987")
		}
		if result.ProductVersion != "1.0" {
			t.Errorf("ProductVersion = %q, want %q", result.ProductVersion, "1.0")
		}
	})

	t.Run("data too short", func(t *testing.T) {
		_, err := parseFRU([]byte{0x01, 0x00})
		if err == nil {
			t.Fatal("expected error for short FRU data")
		}
		var target ErrFRURead
		if !errors.As(err, &target) {
			t.Errorf("expected ErrFRURead, got %T: %v", err, err)
		}
	})

	t.Run("invalid format version", func(t *testing.T) {
		data := make([]byte, 8)
		data[0] = 0x02
		_, err := parseFRU(data)
		if err == nil {
			t.Fatal("expected error for invalid FRU version")
		}
		var target ErrFRURead
		if !errors.As(err, &target) {
			t.Errorf("expected ErrFRURead, got %T: %v", err, err)
		}
	})

	t.Run("no board or product areas", func(t *testing.T) {
		data := make([]byte, 8)
		data[0] = 0x01
		result, err := parseFRU(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ProductName != "" {
			t.Errorf("ProductName = %q, want empty", result.ProductName)
		}
	})
}

func TestReadFRUField(t *testing.T) {
	t.Run("ASCII field", func(t *testing.T) {
		data := []byte{0xC5, 'H', 'e', 'l', 'l', 'o'}
		val, n := readFRUField(data, 0)
		if val != "Hello" {
			t.Errorf("val = %q, want %q", val, "Hello")
		}
		if n != 6 {
			t.Errorf("n = %d, want 6", n)
		}
	})

	t.Run("end of fields marker", func(t *testing.T) {
		data := []byte{0xC1}
		val, n := readFRUField(data, 0)
		if val != "" || n != 0 {
			t.Errorf("expected empty field at end marker, got val=%q, n=%d", val, n)
		}
	})

	t.Run("offset beyond data", func(t *testing.T) {
		data := []byte{0xC3, 'A', 'B', 'C'}
		val, n := readFRUField(data, 10)
		if val != "" || n != 0 {
			t.Errorf("expected empty field for out-of-bounds offset, got val=%q, n=%d", val, n)
		}
	})

	t.Run("field length exceeds data", func(t *testing.T) {
		data := []byte{0xCA}
		val, n := readFRUField(data, 0)
		if val != "" || n != 0 {
			t.Errorf("expected empty field for truncated data, got val=%q, n=%d", val, n)
		}
	})

	t.Run("binary field", func(t *testing.T) {
		data := []byte{0x02, 0xAB, 0xCD}
		val, n := readFRUField(data, 0)
		if val != "abcd" {
			t.Errorf("val = %q, want %q", val, "abcd")
		}
		if n != 3 {
			t.Errorf("n = %d, want 3", n)
		}
	})
}

// --- Sensor Reading Response Tests ---

func TestSensorReadingResponse_IsValid(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		r := &sensorReadingResponse{EventStatus: 0x00}
		if !r.IsValid() {
			t.Error("expected IsValid() = true")
		}
	})

	t.Run("reading unavailable", func(t *testing.T) {
		r := &sensorReadingResponse{EventStatus: 0x40}
		if r.IsValid() {
			t.Error("expected IsValid() = false for unavailable reading")
		}
	})

	t.Run("scanning disabled", func(t *testing.T) {
		r := &sensorReadingResponse{EventStatus: 0x20}
		if r.IsValid() {
			t.Error("expected IsValid() = false for disabled scanning")
		}
	})
}

// --- Error Type Tests ---

func TestErrUnsupportedOperation(t *testing.T) {
	err := ErrUnsupportedOperation{Operation: "mount ISO via IPMI"}
	expected := "bmc: unsupported operation: mount ISO via IPMI"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestErrSensorRead(t *testing.T) {
	cause := errors.New("connection reset")
	err := ErrSensorRead{Cause: cause}
	expected := "bmc: sensor read failed: connection reset"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return the cause")
	}
}

func TestErrFRURead(t *testing.T) {
	err := ErrFRURead{Reason: "area size is zero"}
	expected := "bmc: FRU read failed: area size is zero"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestErrSDRParse(t *testing.T) {
	err := ErrSDRParse{Reason: "record too short"}
	expected := "bmc: SDR parse failed: record too short"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

// --- Boot Device Map Completeness Test ---

func TestBootDeviceBitsMapCompleteness(t *testing.T) {
	for device := range validBootDevices {
		if _, ok := bootDeviceBitsMap[device]; !ok {
			t.Errorf("BootDevice %q has no IPMI bits mapping", device)
		}
	}
}
