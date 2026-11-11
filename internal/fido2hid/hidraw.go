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

// Package fido2hid is the FIDO2 HID transport the installer enrols through
// and the initrd unlocks through, so both reach the authenticator with the
// same frames.
package fido2hid

import (
	"io"
	"runtime"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
)

// NewEnumerator returns the platform's HID enumerator; on Linux its devices
// are wrapped so every CTAPHID frame reaches hidraw intact.
func NewEnumerator() fido2.HIDDeviceEnumerator {
	enum := fido2.NewDefaultEnumerator()
	if runtime.GOOS == "linux" {
		return Enumerator{enum}
	}
	return enum
}

// Enumerator wraps every device it yields in hidrawDevice. The SDK's Linux
// device writes the 64-byte frame to hidraw unchanged, and hidraw takes the
// first byte as the report ID, so a channel ID beginning with zero would lose
// that byte and the device would receive a truncated 63-byte report.
type Enumerator struct {
	fido2.HIDDeviceEnumerator
}

// Enumerate lists the HID devices of the wrapped enumerator, each wrapped
// in hidrawDevice.
func (e Enumerator) Enumerate(vendorID, productID uint16) ([]fido2.HIDDevice, error) {
	devs, err := e.HIDDeviceEnumerator.Enumerate(vendorID, productID)
	if err != nil {
		return nil, err
	}
	wrapped := make([]fido2.HIDDevice, len(devs))
	for i, dev := range devs {
		wrapped[i] = hidrawDevice{dev}
	}
	return wrapped, nil
}

// Open opens the HID device at path, wrapped in hidrawDevice.
func (e Enumerator) Open(path string) (fido2.HIDDevice, error) {
	dev, err := e.HIDDeviceEnumerator.Open(path)
	if err != nil {
		return nil, err
	}
	return hidrawDevice{dev}, nil
}

// hidrawDevice writes each frame as a hidraw output report: the unnumbered
// report ID (zero), then the complete frame. A report hidraw takes only in
// part is an error, never a silently truncated frame.
type hidrawDevice struct {
	fido2.HIDDevice
}

func (d hidrawDevice) Write(frame []byte) (int, error) {
	report := make([]byte, len(frame)+1)
	copy(report[1:], frame)
	n, err := d.HIDDevice.Write(report)
	if n > 0 {
		n--
	}
	if err == nil && n < len(frame) {
		err = io.ErrShortWrite
	}
	return n, err
}
