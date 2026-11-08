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
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

func TestStandaloneActions_TableOutput(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		setup  func(m *bmc.MockClient)
		want   string
		verify func(t *testing.T, m *bmc.MockClient)
	}{
		{
			name: "power-on",
			args: []string{"power-on"},
			want: "Host:   192.0.2.10\nAction: on\nStatus: success\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.Equal(t, int64(1), m.PowerOnCalls())
				assert.Equal(t, bmc.PowerStateOn, m.Power)
			},
		},
		{
			name:  "power-off",
			args:  []string{"power-off"},
			setup: func(m *bmc.MockClient) { m.Power = bmc.PowerStateOn },
			want:  "Host:   192.0.2.10\nAction: off\nStatus: success\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.Equal(t, int64(1), m.PowerOffCalls())
				assert.Equal(t, bmc.PowerStateOff, m.Power)
			},
		},
		{
			name: "power-reset",
			args: []string{"power-reset"},
			want: "Host:   192.0.2.10\nAction: reset\nStatus: success\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.Equal(t, int64(1), m.PowerResetCalls())
			},
		},
		{
			name: "power-cycle",
			args: []string{"power-cycle"},
			want: "Host:   192.0.2.10\nAction: cycle\nStatus: success\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.Equal(t, int64(1), m.PowerCycleCalls())
			},
		},
		{
			name:  "power-status",
			args:  []string{"power-status"},
			setup: func(m *bmc.MockClient) { m.Power = bmc.PowerStateOn },
			want:  "Host:        192.0.2.10\nPower State: on\n",
		},
		{
			name: "set-boot-device persistent pxe",
			args: []string{"set-boot-device", "--device", "pxe", "--persistent"},
			want: "Host:       192.0.2.10\nDevice:     pxe\nPersistent: true\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.Equal(t, bmc.BootDevicePXE, m.Boot)
				assert.True(t, m.BootPersistent)
			},
		},
		{
			name: "get-boot-device",
			args: []string{"get-boot-device"},
			want: "Host:       192.0.2.10\nDevice:     disk\nPersistent: false\n",
		},
		{
			name: "mount-iso",
			args: []string{"mount-iso", "--iso-url", "https://images.example/os.iso"},
			want: "Host:    192.0.2.10\nAction:  mount\nStatus:  success\nISO URL: https://images.example/os.iso\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.Equal(t, "https://images.example/os.iso", m.Media.ImageURL)
				assert.True(t, m.Media.Mounted)
			},
		},
		{
			name:  "unmount-iso",
			args:  []string{"unmount-iso"},
			setup: func(m *bmc.MockClient) { m.Media = &bmc.VirtualMediaInfo{Mounted: true, ImageURL: "x"} },
			want:  "Host:   192.0.2.10\nAction: unmount\nStatus: success\n",
			verify: func(t *testing.T, m *bmc.MockClient) {
				assert.False(t, m.Media.Mounted)
			},
		},
		{
			name: "media-status mounted prints the ISO URL",
			args: []string{"media-status"},
			setup: func(m *bmc.MockClient) {
				m.Media = &bmc.VirtualMediaInfo{Mounted: true, ImageURL: "https://images.example/os.iso"}
			},
			want: "Host:    192.0.2.10\nMounted: true\nISO URL: https://images.example/os.iso\n",
		},
		{
			name: "media-status unmounted omits the ISO URL",
			args: []string{"media-status"},
			want: "Host:    192.0.2.10\nMounted: false\n",
		},
		{
			name: "sensors",
			args: []string{"sensors"},
			setup: func(m *bmc.MockClient) {
				m.SensorData = []bmc.SensorReading{
					{Name: "CPU Temp", Value: 41.5, Units: "C", Status: "ok"},
					{Name: "FAN1", Value: 5400, Units: "RPM", Status: "warning"},
				}
			},
			want: "Host: 192.0.2.10\nSensors:\n" +
				"  CPU Temp                          41.50 C          [ok]\n" +
				"  FAN1                            5400.00 RPM        [warning]\n",
		},
		{
			name: "system-info",
			args: []string{"system-info"},
			setup: func(m *bmc.MockClient) {
				m.System = &bmc.SystemInfo{
					Manufacturer:    "Supermicro",
					Product:         "X11SPM",
					SerialNumber:    "SN123",
					BIOSVersion:     "3.4",
					FirmwareVersion: "1.73",
					PowerState:      bmc.PowerStateOn,
				}
			},
			want: "Host:          192.0.2.10\n" +
				"Manufacturer:  Supermicro\n" +
				"Model:         X11SPM\n" +
				"Serial Number: SN123\n" +
				"BIOS Version:  3.4\n" +
				"BMC Version:   1.73\n" +
				"Power State:   on\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := bmc.NewMockClient()
			if tt.setup != nil {
				tt.setup(mock)
			}
			defer withMockBMCClient(t, mock)()

			out, err := runBMC(t, tableGetFlags(), withArgs(tt.args, standaloneIPMIArgs...)...)
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
			assert.Equal(t, int64(1), mock.CloseCalls(), "the client must be closed after the action")
			if tt.verify != nil {
				tt.verify(t, mock)
			}
		})
	}
}

func TestStandaloneActions_JSONOutput(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		setup func(m *bmc.MockClient)
		want  any
	}{
		{
			name: "power-cycle",
			args: []string{"power-cycle"},
			want: powerActionResponse{ProfileID: "192.0.2.10", Action: "cycle", Status: "success"},
		},
		{
			name: "power-status",
			args: []string{"power-status"},
			want: powerStatusResponse{ProfileID: "192.0.2.10", PowerState: "off"},
		},
		{
			name: "set-boot-device",
			args: []string{"set-boot-device", "--device", "cdrom"},
			want: bootDeviceResponse{ProfileID: "192.0.2.10", Device: "cdrom"},
		},
		{
			name: "get-boot-device",
			args: []string{"get-boot-device"},
			want: bootDeviceResponse{ProfileID: "192.0.2.10", Device: "disk"},
		},
		{
			name: "mount-iso",
			args: []string{"mount-iso", "--iso-url", "https://images.example/os.iso"},
			want: mediaActionResponse{ProfileID: "192.0.2.10", Action: "mount", Status: "success", ISOURL: "https://images.example/os.iso"},
		},
		{
			name: "unmount-iso",
			args: []string{"unmount-iso"},
			want: mediaActionResponse{ProfileID: "192.0.2.10", Action: "unmount", Status: "success"},
		},
		{
			name:  "media-status",
			args:  []string{"media-status"},
			setup: func(m *bmc.MockClient) { m.Media = &bmc.VirtualMediaInfo{Mounted: true, ImageURL: "u"} },
			want:  mediaStatusResponse{ProfileID: "192.0.2.10", Mounted: true, ISOURL: "u"},
		},
		{
			name: "sensors",
			args: []string{"sensors"},
			setup: func(m *bmc.MockClient) {
				m.SensorData = []bmc.SensorReading{{Name: "CPU Temp", Value: 41.5, Units: "C", Status: "ok"}}
			},
			want: sensorsResponse{ProfileID: "192.0.2.10", Sensors: []sensorReading{{Name: "CPU Temp", Value: 41.5, Units: "C", Status: "ok"}}},
		},
		{
			name: "system-info",
			args: []string{"system-info"},
			setup: func(m *bmc.MockClient) {
				m.System = &bmc.SystemInfo{Manufacturer: "Dell", Product: "R640", PowerState: bmc.PowerStateOff}
			},
			want: systemInfoResponse{ProfileID: "192.0.2.10", Manufacturer: "Dell", Model: "R640", PowerState: "off"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := bmc.NewMockClient()
			if tt.setup != nil {
				tt.setup(mock)
			}
			defer withMockBMCClient(t, mock)()

			out, err := runBMC(t, jsonGetFlags(), withArgs(tt.args, standaloneIPMIArgs...)...)
			require.NoError(t, err)

			got := reflect.New(reflect.TypeOf(tt.want))
			require.NoError(t, json.Unmarshal([]byte(out), got.Interface()), "output: %q", out)
			assert.Equal(t, tt.want, got.Elem().Interface())
		})
	}
}

func TestStandaloneActions_ClientErrorsPropagate(t *testing.T) {
	injected := errors.New("bmc unreachable")
	tests := []struct {
		name   string
		args   []string
		inject func(m *bmc.MockClient)
	}{
		{"power-on", []string{"power-on"}, func(m *bmc.MockClient) { m.PowerOnErr = injected }},
		{"power-off", []string{"power-off"}, func(m *bmc.MockClient) { m.PowerOffErr = injected }},
		{"power-reset", []string{"power-reset"}, func(m *bmc.MockClient) { m.PowerResetErr = injected }},
		{"power-cycle", []string{"power-cycle"}, func(m *bmc.MockClient) { m.PowerCycleErr = injected }},
		{"power-status", []string{"power-status"}, func(m *bmc.MockClient) { m.PowerStatusErr = injected }},
		{"set-boot-device", []string{"set-boot-device", "--device", "pxe"}, func(m *bmc.MockClient) { m.SetBootDeviceErr = injected }},
		{"get-boot-device", []string{"get-boot-device"}, func(m *bmc.MockClient) { m.GetBootDeviceErr = injected }},
		{"mount-iso", []string{"mount-iso", "--iso-url", "u"}, func(m *bmc.MockClient) { m.MountISOErr = injected }},
		{"unmount-iso", []string{"unmount-iso"}, func(m *bmc.MockClient) { m.UnmountISOErr = injected }},
		{"media-status", []string{"media-status"}, func(m *bmc.MockClient) { m.VirtualMediaStatErr = injected }},
		{"sensors", []string{"sensors"}, func(m *bmc.MockClient) { m.GetSensorsErr = injected }},
		{"system-info", []string{"system-info"}, func(m *bmc.MockClient) { m.GetSystemInfoErr = injected }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := bmc.NewMockClient()
			tt.inject(mock)
			defer withMockBMCClient(t, mock)()

			out, err := runBMC(t, tableGetFlags(), withArgs(tt.args, standaloneIPMIArgs...)...)
			require.ErrorIs(t, err, injected)
			assert.Empty(t, out, "nothing is printed when the BMC call fails")
			assert.Equal(t, int64(1), mock.CloseCalls(), "the client must be closed on the error path too")
		})
	}
}

func TestStandaloneActions_ClientConstructionError(t *testing.T) {
	injected := errors.New("rmcp session refused")
	prev := newBMCClient
	newBMCClient = func(_ *bmc.Config, _ *slog.Logger) (bmc.Client, error) { return nil, injected }
	defer func() { newBMCClient = prev }()

	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"power-status"}, standaloneIPMIArgs...)...)
	require.ErrorIs(t, err, injected)
}

func TestStandaloneActions_ConfigErrorBeforeDial(t *testing.T) {
	mock := bmc.NewMockClient()
	defer withMockBMCClient(t, mock)()

	_, err := runBMC(t, tableGetFlags(), "power-on", "--bmc-host", "192.0.2.10", "--bmc-pass", "p", "--bmc-protocol", "ipmi")
	var missing ErrBMCMissingCredential
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, int64(0), mock.PowerOnCalls())
}

func TestStandaloneActions_InvalidBootDevice(t *testing.T) {
	mock := bmc.NewMockClient()
	defer withMockBMCClient(t, mock)()

	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"set-boot-device", "--device", "floppy"}, standaloneIPMIArgs...)...)
	var invalid ErrInvalidBootDevice
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "floppy", invalid.Device)
	assert.Equal(t, int64(0), mock.SetBootDeviceCalls())
}

func TestStandaloneActions_MountISORequiresURL(t *testing.T) {
	mock := bmc.NewMockClient()
	defer withMockBMCClient(t, mock)()

	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"mount-iso"}, standaloneIPMIArgs...)...)
	require.ErrorAs(t, err, &ErrISOURLRequired{})
	assert.Equal(t, int64(0), mock.MountISOCalls())
}

func TestStandaloneActions_ProvisionRequiresDaemon(t *testing.T) {
	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"provision"}, standaloneIPMIArgs...)...)
	var requires ErrBMCRequiresDaemon
	require.ErrorAs(t, err, &requires)
	assert.Equal(t, "provision", requires.Subcommand)
}

func TestStandaloneActions_JSONEncodeFailure(t *testing.T) {
	mock := bmc.NewMockClient()
	mock.SensorData = []bmc.SensorReading{{Name: "broken", Value: math.NaN()}}
	defer withMockBMCClient(t, mock)()

	_, err := runBMC(t, jsonGetFlags(), withArgs([]string{"sensors"}, standaloneIPMIArgs...)...)
	var encodeErr ErrResponseDecodeFailed
	require.ErrorAs(t, err, &encodeErr)
	require.Error(t, encodeErr.Cause)
}

// Every subcommand that accepts both flag sets refuses to run with both, and
// refuses to guess when given neither.
func TestStandaloneActions_ModeSelection(t *testing.T) {
	subcommands := [][]string{
		{"power-on"}, {"power-off"}, {"power-reset"}, {"power-cycle"}, {"power-status"},
		{"set-boot-device", "--device", "pxe"}, {"get-boot-device"},
		{"mount-iso", "--iso-url", "u"}, {"unmount-iso"}, {"media-status"},
		{"sensors"}, {"system-info"}, {"provision"},
	}
	for _, sub := range subcommands {
		t.Run(sub[0]+"/both modes", func(t *testing.T) {
			args := withArgs(sub, standaloneIPMIArgs...)
			args = append(args, "--server-url", "https://platform:8443", "--profile-id", "server-01")
			_, err := runBMC(t, tableGetFlags(), args...)
			var conflict ErrBMCFlagConflict
			require.ErrorAs(t, err, &conflict)
			assert.Equal(t, []string{"--bmc-host", "--server-url/--profile-id"}, conflict.Fields)
		})
		t.Run(sub[0]+"/no mode", func(t *testing.T) {
			_, err := runBMC(t, tableGetFlags(), sub...)
			require.ErrorAs(t, err, &ErrBMCNoMode{})
		})
	}
}
