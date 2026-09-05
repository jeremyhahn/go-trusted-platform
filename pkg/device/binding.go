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

package device

import "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"

// DeviceBinding is the identity a profile is bound to by
// AssignToDeviceWithEK: the EK serial, an optional MAC address and the
// PEM EK certificate to prestage.
type DeviceBinding struct {
	EKSerial string
	MAC      string
	EKCert   string
}

// BindingFromDevice derives the binding for a registered device, filling
// every value the caller left empty from the device record: the EK serial
// from the serial number of the device's stored EK certificate, and the
// certificate itself for prestaging. Explicit values win over derived ones,
// mirroring the CLI's --device / --ek-serial precedence. A device with no
// EK certificate yields ErrDeviceHasNoEKCert unless the caller supplied an
// EK serial or a MAC of its own; a stored certificate that does not parse is
// reported, never silently skipped. Every transport's assign-by-device path
// (gRPC/Unix/QUIC, live REST, MCP) goes through here so the derivation
// exists once and clients never parse certificates (#463).
func BindingFromDevice(dev *entities.Device, ekSerial, mac, ekCertPEM string) (DeviceBinding, error) {
	if dev == nil {
		return DeviceBinding{}, ErrDeviceRequired{}
	}
	binding := DeviceBinding{EKSerial: ekSerial, MAC: mac, EKCert: ekCertPEM}
	if dev.EKCert == "" {
		if binding.EKSerial == "" && binding.MAC == "" {
			return DeviceBinding{}, ErrDeviceHasNoEKCert{DeviceID: dev.ID}
		}
		return binding, nil
	}
	if binding.EKSerial == "" {
		serial, err := entities.EKSerialFromCertPEM(dev.EKCert)
		if err != nil {
			return DeviceBinding{}, err
		}
		binding.EKSerial = serial
	}
	if binding.EKCert == "" {
		binding.EKCert = dev.EKCert
	}
	return binding, nil
}
