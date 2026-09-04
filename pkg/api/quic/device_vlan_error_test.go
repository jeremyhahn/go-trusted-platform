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

package quic

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// TestDeviceHandler_profileErrorResponse_VLANsNotDistinct asserts the QUIC
// transport maps the typed validation failure to InvalidArgument by type.
//
// It mapped correctly before only because the message happens to contain the
// word "invalid" — a string match that any rewording of the error would have
// broken silently. The wrapped case is the one a substring match could never
// have carried on its own terms.
func TestDeviceHandler_profileErrorResponse_VLANsNotDistinct(t *testing.T) {
	h := &DeviceHandler{}

	tests := []struct {
		name string
		err  error
		want byte
	}{
		{
			name: "typed error maps to invalid argument",
			err:  device.ErrProfileVLANsNotDistinct{VLAN: 200},
			want: StatusInvalidArgument,
		},
		{
			name: "wrapped typed error still maps to invalid argument",
			err:  &device.WrappedError{Msg: "failed to save profile", Err: device.ErrProfileVLANsNotDistinct{VLAN: 200}},
			want: StatusInvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := h.profileErrorResponse(tt.err)
			assert.Equal(t, tt.want, resp.Status)
		})
	}
}
