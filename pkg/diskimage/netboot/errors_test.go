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

package netboot

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
)

// A netboot build is run by an operator ahead of a fleet rollout: each error
// must say what stopped the build and what to do about it, and keep its cause
// reachable with errors.Is.
func TestErrors_SayWhatStoppedTheBuild(t *testing.T) {
	cause := errors.New("no space left on device")

	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"http boot step", &HTTPBootError{Step: "signing boot.img", Err: cause}, []string{"http boot: signing boot.img", cause.Error()}},
		{"no pi set", &NoPiSetError{}, []string{container.MediaSetRaspberryPi, "boot.img"}},
		{"no eeprom", &NoEEPROMError{Model: "rpi3"}, []string{"rpi3", "no bootloader EEPROM", "Raspberry Pi 4"}},
		{"fleet key file", &FleetKeyRefError{Ref: "/etc/fleet.key"}, []string{"/etc/fleet.key", "kms://", "never a file"}},
		{"staging source", &Error{Source: "rpi.img", Err: cause}, []string{"from rpi.img", cause.Error()}},
		{"missing file", &MissingFileError{File: "config.txt"}, []string{"no config.txt"}},
		{"unpinned release", &UnpinnedReleaseError{Version: "9.9.9", Architecture: "aarch64"}, []string{"9.9.9", "aarch64", "pinned"}},
		{"build step", &BuildError{Set: "rpi", Step: "placing the kernel", Err: cause}, []string{"rpi: placing the kernel", cause.Error()}},
		{"build-wide step", &BuildError{Step: "writing the index", Err: cause}, []string{"diskimage/netboot: writing the index"}},
		{"private key", &PrivateKeyMaterialError{File: "secure-boot-keys/DB.key"}, []string{"secure-boot-keys/DB.key", "resign-mode: remote"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				assert.Contains(t, tc.err.Error(), want)
			}
		})
	}

	for _, wrapped := range []error{
		&HTTPBootError{Step: "writing boot.img", Err: cause},
		&Error{Source: "rpi.img", Err: cause},
		&BuildError{Step: "writing the index", Err: cause},
	} {
		assert.ErrorIs(t, wrapped, cause, "%T keeps its cause", wrapped)
	}
}
