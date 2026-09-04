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

package daemon

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// TestDeviceGRPCService_toGRPCError_VLANsNotDistinctWrapped is the reason
// #133 asks for errors.As rather than a bare type assertion: the assertion
// this replaced matched only an unwrapped value, so the mapping held solely
// because the service layer happened to return the error unwrapped. Any
// future wrapping on the way out would have downgraded a 400-class failure
// to Internal with nothing to catch it.
func TestDeviceGRPCService_toGRPCError_VLANsNotDistinctWrapped(t *testing.T) {
	svc := &DeviceGRPCService{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			name: "typed error",
			err:  device.ErrProfileVLANsNotDistinct{VLAN: 200},
			want: codes.InvalidArgument,
		},
		{
			name: "wrapped typed error",
			err:  &device.WrappedError{Msg: "failed to save profile", Err: device.ErrProfileVLANsNotDistinct{VLAN: 200}},
			want: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := svc.toGRPCError(tt.err)
			require.Error(t, mapped)
			assert.Equal(t, tt.want, status.Code(mapped))
		})
	}
}
