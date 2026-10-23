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

package rpinetboot

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The probe stands in for a Pi on the bench, so its errors are what an
// operator acts on: each must name where the boot stopped and why, and keep
// the cause reachable with errors.Is.
func TestErrors_NameWhereTheBootStopped(t *testing.T) {
	cause := errors.New("connection reset")
	_, unknownModel := LookupModel("rpi9")
	require.Error(t, unknownModel)

	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"unknown model", unknownModel, []string{"rpi9", "rpi4", "rpi5"}},
		{"invalid identity", &InvalidIdentityError{Field: "serial", Value: "xyz"}, []string{"serial", "xyz"}},
		{"dhcp stage", &DHCPError{Stage: "ack", Err: cause}, []string{"dhcp ack", cause.Error()}},
		{"tftp file", &TFTPError{File: "9ffefdef/start4.elf", Err: cause}, []string{"tftp 9ffefdef/start4.elf", cause.Error()}},
		{"timeout", &TimeoutError{What: "DISCOVER", After: 20 * time.Second}, []string{"DISCOVER", "20s"}},
		{"socket option", &SocketError{Option: "SO_BROADCAST", Err: cause}, []string{"SO_BROADCAST", cause.Error()}},
		{"missing http option", &HTTPBootConfigError{Field: "host"}, []string{"host is required"}},
		{"invalid http option", &HTTPBootConfigError{Field: "port", Err: cause}, []string{"invalid port", cause.Error()}},
		{"http fetch", &HTTPFetchError{URL: "http://10.99.99.1:8080/boot.sig", Err: &HTTPStatusError{Status: 404}}, []string{"http://10.99.99.1:8080/boot.sig", "404"}},
		{"http size", &HTTPSizeError{Limit: 96 << 20}, []string{"100663296 bytes"}},
		{"refused", &HTTPBootRefusedError{URL: "http://10.99.99.1:8080/boot.img", Err: cause}, []string{"refuses http://10.99.99.1:8080/boot.img", cause.Error()}},
		{"ramdisk", &RamdiskError{Err: cause}, []string{"not a mountable ramdisk", cause.Error()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				assert.Contains(t, tc.err.Error(), want)
			}
		})
	}

	for _, wrapped := range []error{
		&DHCPError{Stage: "ack", Err: cause},
		&TFTPError{File: "config.txt", Err: cause},
		&SocketError{Option: "SO_REUSEADDR", Err: cause},
		&HTTPBootConfigError{Field: "port", Err: cause},
		&HTTPFetchError{URL: "http://host/boot.img", Err: cause},
		&HTTPBootRefusedError{URL: "http://host/boot.img", Err: cause},
		&RamdiskError{Err: cause},
	} {
		assert.ErrorIs(t, wrapped, cause, "%T keeps its cause", wrapped)
	}
}
