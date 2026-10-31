package bmc

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// redfishDelegateClient returns an IPMI client whose lazy Redfish fallback
// is already the given mock, so the delegates reach it without TLS.
func redfishDelegateClient(mock *MockClient) *ipmiClient {
	c := oemTestClient(newFakeIPMISession())
	c.redfishClient = mock
	return c
}

func TestIPMIClient_MountVirtualMedia_DelegatesToRedfish(t *testing.T) {
	mock := NewMockClient()
	c := redfishDelegateClient(mock)
	spec := &MediaSpec{URL: "https://10.0.0.5/boot.iso", Protocol: MediaProtocolHTTPS}

	if err := c.MountVirtualMedia(context.Background(), spec); err != nil {
		t.Fatalf("MountVirtualMedia: %v", err)
	}
	if mock.Media == nil || mock.Media.ImageURL != spec.URL {
		t.Fatalf("Redfish fallback media = %+v, want ImageURL %q", mock.Media, spec.URL)
	}

	if err := c.UnmountVirtualMedia(context.Background()); err != nil {
		t.Fatalf("UnmountVirtualMedia: %v", err)
	}
	if mock.Media == nil || mock.Media.Mounted {
		t.Fatalf("Redfish fallback media after unmount = %+v, want unmounted", mock.Media)
	}
}

func TestIPMIClient_VirtualMediaDelegates_PropagateRedfishErrors(t *testing.T) {
	mountErr := errors.New("insert rejected")
	unmountErr := errors.New("eject rejected")
	mock := NewMockClient()
	mock.MountISOErr = mountErr
	mock.UnmountISOErr = unmountErr
	c := redfishDelegateClient(mock)
	spec := &MediaSpec{URL: "http://10.0.0.5/boot.iso", Protocol: MediaProtocolHTTP}

	if err := c.MountVirtualMedia(context.Background(), spec); !errors.Is(err, mountErr) {
		t.Errorf("MountVirtualMedia error = %v, want %v", err, mountErr)
	}
	if err := c.UnmountVirtualMedia(context.Background()); !errors.Is(err, unmountErr) {
		t.Errorf("UnmountVirtualMedia error = %v, want %v", err, unmountErr)
	}
}

func TestIPMIClient_RedfishDelegates_ClosedClient(t *testing.T) {
	ctx := context.Background()
	spec := &MediaSpec{URL: "http://10.0.0.5/boot.iso", Protocol: MediaProtocolHTTP}
	tests := []struct {
		name string
		call func(*ipmiClient) error
	}{
		{"MountVirtualMedia", func(c *ipmiClient) error { return c.MountVirtualMedia(ctx, spec) }},
		{"UnmountVirtualMedia", func(c *ipmiClient) error { return c.UnmountVirtualMedia(ctx) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockClient()
			c := redfishDelegateClient(mock)
			if err := c.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			var closed ErrClientClosed
			if err := tt.call(c); !errors.As(err, &closed) {
				t.Fatalf("error = %v, want ErrClientClosed", err)
			}
		})
	}
}

func TestIPMIClient_RedfishDelegates_FallbackInitFails(t *testing.T) {
	ctx := context.Background()
	spec := &MediaSpec{URL: "http://10.0.0.5/boot.iso", Protocol: MediaProtocolHTTP}
	tests := []struct {
		name string
		call func(*ipmiClient) error
	}{
		{"MountVirtualMedia", func(c *ipmiClient) error { return c.MountVirtualMedia(ctx, spec) }},
		{"UnmountVirtualMedia", func(c *ipmiClient) error { return c.UnmountVirtualMedia(ctx) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := oemTestClient(newFakeIPMISession())
			// An empty address fails Redfish config validation, so the
			// lazy fallback client can never be built.
			c.config.Address = ""
			var initErr ErrRedfishTransportInit
			if err := tt.call(c); !errors.As(err, &initErr) {
				t.Fatalf("error = %v, want ErrRedfishTransportInit", err)
			}
		})
	}
}

func TestIPMIClient_ClearUEFIBootEntries_DelegatesToRedfish(t *testing.T) {
	mock := NewMockClient()
	c := redfishDelegateClient(mock)

	if err := c.ClearUEFIBootEntries(context.Background()); err != nil {
		t.Fatalf("ClearUEFIBootEntries: %v", err)
	}
	if got := mock.ClearUEFIBootEntriesCalls(); got != 1 {
		t.Fatalf("Redfish ClearUEFIBootEntries calls = %d, want 1", got)
	}

	resetErr := ErrUEFIBootClearUnsupported{Manufacturer: "Supermicro"}
	mock.ClearUEFIBootEntriesErr = resetErr
	var unsupported ErrUEFIBootClearUnsupported
	if err := c.ClearUEFIBootEntries(context.Background()); !errors.As(err, &unsupported) ||
		unsupported.Manufacturer != "Supermicro" {
		t.Fatalf("error = %v, want the Redfish client's ErrUEFIBootClearUnsupported", err)
	}
}

func TestIPMIClient_ClearUEFIBootEntries_NoRedfishFallback(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*ipmiClient)
		cause func(error) bool
	}{
		{
			name:  "closed client",
			setup: func(c *ipmiClient) { c.closed.Store(true) },
			cause: func(err error) bool {
				var closed ErrClientClosed
				return errors.As(err, &closed)
			},
		},
		{
			name:  "fallback init fails",
			setup: func(c *ipmiClient) { c.config.Address = "" },
			cause: func(err error) bool {
				var initErr ErrRedfishTransportInit
				return errors.As(err, &initErr)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := oemTestClient(newFakeIPMISession())
			tt.setup(c)
			err := c.ClearUEFIBootEntries(context.Background())
			var unsupported ErrUEFIBootClearUnsupported
			if !errors.As(err, &unsupported) {
				t.Fatalf("error = %v, want ErrUEFIBootClearUnsupported", err)
			}
			if !tt.cause(unsupported.Cause) {
				t.Fatalf("cause = %v, want the fallback acquisition failure", unsupported.Cause)
			}
		})
	}
}

// fullSDR builds an IPMI 2.0 Full Sensor Record (§43.1) carrying the
// fields GetSensors reads: the sensor number, base unit, the M factor and
// an 8-bit ASCII id string. B and both exponents are zero, so a raw
// reading converts to M*raw.
func fullSDR(recordID uint16, sensorNum, baseUnit, m byte, name string) []byte {
	data := make([]byte, 5+43+len(name))
	binary.LittleEndian.PutUint16(data[0:2], recordID)
	data[2] = 0x51
	data[3] = sdrRecordTypeFull
	data[4] = byte(len(data) - 5)
	body := data[5:]
	body[2] = sensorNum
	body[16] = baseUnit
	body[19] = m
	body[42] = 0xC0 | byte(len(name))
	copy(body[43:], name)
	return data
}

// sdrEntry is one Get SDR answer: the record bytes and the next record id.
type sdrEntry struct {
	next   uint16
	record []byte
}

// sdrSession returns a fake session serving the given SDR chain (keyed by
// record id, starting at 0) and sensor readings (keyed by sensor number;
// a nil reading answers with an error).
func sdrSession(chain map[uint16]sdrEntry, readings map[byte][]byte) *fakeIPMISession {
	s := newFakeIPMISession()
	s.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, byte(len(chain)), 0x00, 0, 0, 0}
	s.responses[ipmiKey(netFnStorage, cmdReserveSDRRepository)] = []byte{0x34, 0x12}
	s.handlers[ipmiKey(netFnStorage, cmdGetSDR)] = func(data []byte) ([]byte, error) {
		if got := binary.LittleEndian.Uint16(data[0:2]); got != 0x1234 {
			return nil, ErrCompletionCode{Code: 0xC5}
		}
		entry, ok := chain[binary.LittleEndian.Uint16(data[2:4])]
		if !ok {
			return nil, ErrCompletionCode{Code: 0xCB}
		}
		resp := make([]byte, 2, 2+len(entry.record))
		binary.LittleEndian.PutUint16(resp, entry.next)
		return append(resp, entry.record...), nil
	}
	s.handlers[ipmiKey(netFnSensorEvent, cmdGetSensorReading)] = func(data []byte) ([]byte, error) {
		reading := readings[data[0]]
		if reading == nil {
			return nil, ErrCompletionCode{Code: 0xCB}
		}
		return reading, nil
	}
	return s
}

func TestIPMIClient_GetSensors_ReadsEveryFullRecord(t *testing.T) {
	chain := map[uint16]sdrEntry{
		0x0000: {next: 0x0001, record: fullSDR(0x0000, 0x10, 1, 1, "CPU Temp")},
		0x0001: {next: 0x0002, record: fullSDR(0x0001, 0x20, 4, 2, "12V")},
		// A compact record (type 0x02) is not a full record and is skipped.
		0x0002: {next: 0x0003, record: []byte{0x02, 0x00, 0x51, 0x02, 0x00}},
		// A record too short to carry a type byte is skipped.
		0x0003: {next: 0x0004, record: []byte{0x03, 0x00}},
		0x0004: {next: 0x0005, record: fullSDR(0x0004, 0x30, 1, 1, "Dead Sensor")},
		0x0005: {next: 0xFFFF, record: fullSDR(0x0005, 0x40, 1, 1, "Scan Off")},
	}
	readings := map[byte][]byte{
		0x10: {42, 0x00, 0x00, 0x00},
		// Upper critical threshold asserted (bit 4 of the high byte).
		0x20: {6, 0x00, 0x00, 0x10},
		// Bit 6 of the event status: reading unavailable.
		0x40: {0, 0x40},
	}
	c := oemTestClient(sdrSession(chain, readings))

	got, err := c.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	want := []SensorReading{
		{Name: "CPU Temp", Value: 42, Units: "degrees C", Status: "ok"},
		{Name: "12V", Value: 12, Units: "Volts", Status: "critical"},
		{Name: "Scan Off", Value: 0, Units: "degrees C", Status: "unknown"},
	}
	if len(got) != len(want) {
		t.Fatalf("GetSensors returned %d readings %+v, want %d (failed sensor skipped)", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reading %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestIPMIClient_GetSensors_GetSDRFailureStopsIteration(t *testing.T) {
	chain := map[uint16]sdrEntry{
		0x0000: {next: 0x0007, record: fullSDR(0x0000, 0x10, 1, 1, "CPU Temp")},
	}
	c := oemTestClient(sdrSession(chain, map[byte][]byte{0x10: {30}}))

	got, err := c.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	if len(got) != 1 || got[0].Name != "CPU Temp" || got[0].Value != 30 {
		t.Fatalf("GetSensors = %+v, want only the record read before the failure", got)
	}
}

func TestIPMIClient_GetSensors_EmptyRepository(t *testing.T) {
	s := newFakeIPMISession()
	s.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, 0, 0, 0, 0, 0}
	c := oemTestClient(s)

	got, err := c.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("GetSensors = %+v, want no readings", got)
	}
	for _, sent := range s.sent {
		if sent.cmd == cmdReserveSDRRepository {
			t.Fatal("an empty repository must not be reserved")
		}
	}
}

func TestIPMIClient_GetSensors_RepositoryErrors(t *testing.T) {
	transport := errors.New("rmcp timeout")
	tests := []struct {
		name  string
		setup func(*fakeIPMISession)
		check func(error) bool
	}{
		{
			name:  "repository info fails",
			setup: func(s *fakeIPMISession) { s.errs[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = transport },
			check: func(err error) bool {
				var info ErrGetSDRRepoInfo
				return errors.As(err, &info) && errors.Is(err, transport)
			},
		},
		{
			name: "repository info too short",
			setup: func(s *fakeIPMISession) {
				s.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, 1}
			},
			check: func(err error) bool {
				var short ErrSDRResponseTooShort
				return errors.As(err, &short) && short.Expected == 6 && short.Length == 2
			},
		},
		{
			name: "reserve fails",
			setup: func(s *fakeIPMISession) {
				s.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, 1, 0, 0, 0, 0}
				s.errs[ipmiKey(netFnStorage, cmdReserveSDRRepository)] = transport
			},
			check: func(err error) bool {
				var reserve ErrReserveSDR
				return errors.As(err, &reserve) && errors.Is(err, transport)
			},
		},
		{
			name: "reserve too short",
			setup: func(s *fakeIPMISession) {
				s.responses[ipmiKey(netFnStorage, cmdGetSDRRepositoryInfo)] = []byte{0x51, 1, 0, 0, 0, 0}
				s.responses[ipmiKey(netFnStorage, cmdReserveSDRRepository)] = []byte{0x34}
			},
			check: func(err error) bool {
				var short ErrSDRResponseTooShort
				return errors.As(err, &short) && short.Expected == 2 && short.Length == 1
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeIPMISession()
			tt.setup(s)
			c := oemTestClient(s)
			_, err := c.GetSensors(context.Background())
			var sensorErr ErrSensorRead
			if !errors.As(err, &sensorErr) {
				t.Fatalf("error = %v, want ErrSensorRead", err)
			}
			if !tt.check(sensorErr.Cause) {
				t.Fatalf("cause = %v, not the expected repository failure", sensorErr.Cause)
			}
		})
	}
}

func TestIPMIClient_GetSensors_ClosedClient(t *testing.T) {
	c := oemTestClient(newFakeIPMISession())
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var closed ErrClientClosed
	if _, err := c.GetSensors(context.Background()); !errors.As(err, &closed) {
		t.Fatalf("error = %v, want ErrClientClosed", err)
	}
}

func TestIPMIClient_ReadSensor_ResponseLengths(t *testing.T) {
	tests := []struct {
		name string
		resp []byte
		want sensorReadingResponse
	}{
		{"empty", nil, sensorReadingResponse{}},
		{"reading only", []byte{7}, sensorReadingResponse{RawReading: 7}},
		{"reading and status", []byte{7, 0x40}, sensorReadingResponse{RawReading: 7, EventStatus: 0x40}},
		{"low threshold", []byte{7, 0, 0x02}, sensorReadingResponse{RawReading: 7, ThresholdLow: 0x02}},
		{"both thresholds", []byte{7, 0, 0x02, 0x10}, sensorReadingResponse{RawReading: 7, ThresholdLow: 0x02, ThresholdHigh: 0x10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeIPMISession()
			s.responses[ipmiKey(netFnSensorEvent, cmdGetSensorReading)] = tt.resp
			c := oemTestClient(s)
			got, err := c.readSensor(0x10)
			if err != nil {
				t.Fatalf("readSensor: %v", err)
			}
			if *got != tt.want {
				t.Fatalf("readSensor = %+v, want %+v", *got, tt.want)
			}
			if sent, ok := s.lastSend(netFnSensorEvent, cmdGetSensorReading); !ok || !bytesEqual(sent.data, []byte{0x10}) {
				t.Fatalf("request = %+v, want Get Sensor Reading for sensor 0x10", sent)
			}
		})
	}
}

func TestIPMIClient_ReadSensor_TransportError(t *testing.T) {
	transport := errors.New("rmcp timeout")
	s := newFakeIPMISession()
	s.errs[ipmiKey(netFnSensorEvent, cmdGetSensorReading)] = transport
	c := oemTestClient(s)
	if _, err := c.readSensor(0x10); !errors.Is(err, transport) {
		t.Fatalf("readSensor error = %v, want %v", err, transport)
	}
}

func TestHTTPSEndpoint_Exported(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"IPMI port maps to 443", &Config{Address: "10.0.0.5", Port: ipmiBMCPort}, "10.0.0.5:443"},
		{"unset port maps to 443", &Config{Address: "10.0.0.5"}, "10.0.0.5:443"},
		{"explicit port kept", &Config{Address: "10.0.0.5", Port: 8443}, "10.0.0.5:8443"},
		{"IPv6 literal bracketed", &Config{Address: "fd00::5", Port: ipmiBMCPort}, "[fd00::5]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTTPSEndpoint(tt.cfg); got != tt.want {
				t.Fatalf("HTTPSEndpoint = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedfishClient_Console_Unsupported(t *testing.T) {
	server, _ := mockRedfishServer(t)
	c := newTestRedfishClient(t, server)

	sol, err := c.Console(context.Background())
	var unsupported ErrUnsupportedOperation
	if !errors.As(err, &unsupported) || unsupported.Operation != "console" {
		t.Fatalf("Console error = %v, want ErrUnsupportedOperation{console}", err)
	}
	if sol != nil {
		t.Fatal("Console must not return a session when unsupported")
	}
}
