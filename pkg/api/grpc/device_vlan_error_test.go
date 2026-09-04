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

package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestDeviceGRPCService_mapProfileError_VLANsNotDistinct asserts the gRPC
// transport reports the typed validation failure as InvalidArgument.
// Before #133 it fell through to the Internal default, so a client that sent
// a bad profile was told the server had broken.
func TestDeviceGRPCService_mapProfileError_VLANsNotDistinct(t *testing.T) {
	svc := &DeviceGRPCService{logger: logging.DefaultLogger()}

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{
			name: "typed error maps to invalid argument",
			err:  device.ErrProfileVLANsNotDistinct{VLAN: 200},
			want: codes.InvalidArgument,
		},
		{
			name: "wrapped typed error still maps to invalid argument",
			err:  &device.WrappedError{Msg: "failed to save profile", Err: device.ErrProfileVLANsNotDistinct{VLAN: 200}},
			want: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := svc.mapProfileError("save", tt.err)
			require.Error(t, mapped)
			assert.Equal(t, tt.want, status.Code(mapped))
		})
	}
}
