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

package luks

import (
	"os"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// candidateDevices lists the common partition paths to probe for a LUKS2
// header when the caller did not specify --device. Order is deliberate: most
// specific / most common first.
var candidateDevices = []string{
	"/dev/vda3", "/dev/vda2",
	"/dev/sda3", "/dev/sda2",
	"/dev/nvme0n1p3", "/dev/nvme0n1p2",
}

// autoDetectLUKSDevice attempts to find a LUKS device on the common partition
// paths. Returns ErrDeviceAutoDetectFailed when none of the candidates have a
// valid LUKS header.
//
// This helper previously lived in the fido2 package (fido2.go:79-101) and
// moves here along with the other LUKS use cases.
func autoDetectLUKSDevice() (string, error) {
	for _, dev := range candidateDevices {
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		isLuks, err := luks2.IsLUKS(dev)
		if err == nil && isLuks {
			return dev, nil
		}
	}
	return "", ErrDeviceAutoDetectFailed{}
}

// resolveDevice returns the explicitly-specified device or auto-detects one.
func resolveDevice(device string) (string, error) {
	if device != "" {
		return device, nil
	}
	return autoDetectLUKSDevice()
}
