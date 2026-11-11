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

package fido2hid

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHIDRaw records each report written to it, as a hidraw node would
// receive it, and accepts at most limit bytes of a write when limit > 0.
type fakeHIDRaw struct {
	fido2.HIDDevice
	path    string
	limit   int
	reports [][]byte
}

func (d *fakeHIDRaw) Write(report []byte) (int, error) {
	d.reports = append(d.reports, bytes.Clone(report))
	if d.limit > 0 && len(report) > d.limit {
		return d.limit, nil
	}
	return len(report), nil
}

func (d *fakeHIDRaw) Path() string { return d.path }

type fakeHIDRawEnumerator struct {
	devices []*fakeHIDRaw
}

func (e *fakeHIDRawEnumerator) Enumerate(uint16, uint16) ([]fido2.HIDDevice, error) {
	out := make([]fido2.HIDDevice, 0, len(e.devices))
	for _, d := range e.devices {
		out = append(out, d)
	}
	return out, nil
}

func (e *fakeHIDRawEnumerator) Open(path string) (fido2.HIDDevice, error) {
	for _, d := range e.devices {
		if d.path == path {
			return d, nil
		}
	}
	return nil, fmt.Errorf("no device %s", path)
}

// ctapInitFrame is a 64-byte CTAPHID initialisation frame on channel
// 0x00000001, whose first byte is zero.
func ctapInitFrame() []byte {
	frame := make([]byte, 64)
	frame[3] = 0x01
	frame[4] = 0x90
	frame[6] = 0x01
	frame[7] = 0xAA
	return frame
}

func TestEnumeratorPrefixesReportID(t *testing.T) {
	raw := &fakeHIDRaw{path: "/dev/hidraw0"}
	enum := Enumerator{&fakeHIDRawEnumerator{devices: []*fakeHIDRaw{raw}}}
	frame := ctapInitFrame()

	devs, err := enum.Enumerate(0, 0)
	require.NoError(t, err)
	require.Len(t, devs, 1)
	opened, err := enum.Open("/dev/hidraw0")
	require.NoError(t, err)

	for _, dev := range []fido2.HIDDevice{devs[0], opened} {
		n, err := dev.Write(frame)
		require.NoError(t, err)
		assert.Equal(t, len(frame), n)
	}

	require.Len(t, raw.reports, 2)
	for _, report := range raw.reports {
		require.Len(t, report, 65)
		assert.Equal(t, byte(0), report[0], "unnumbered report ID")
		assert.Equal(t, frame, report[1:], "whole frame, channel ID intact")
	}
}

func TestHIDRawDeviceShortWrite(t *testing.T) {
	raw := &fakeHIDRaw{path: "/dev/hidraw0", limit: 64}
	dev := hidrawDevice{raw}

	n, err := dev.Write(ctapInitFrame())
	require.ErrorIs(t, err, io.ErrShortWrite)
	assert.Equal(t, 63, n)
}

func TestNewEnumeratorIsHIDRawCorrect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("hidraw is the Linux HID transport")
	}
	_, ok := NewEnumerator().(Enumerator)
	assert.True(t, ok, "the enumerator must prefix the hidraw report ID")
}
