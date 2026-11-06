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

package tunnel

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrors_Messages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "ErrTunnelCreateFailed",
			err:      &ErrTunnelCreateFailed{Name: "gre1", Cause: io.EOF},
			contains: "gre1",
		},
		{
			name:     "ErrTunnelNotFound",
			err:      &ErrTunnelNotFound{Name: "gre2"},
			contains: "gre2",
		},
		{
			name:     "ErrTunnelAlreadyExists",
			err:      &ErrTunnelAlreadyExists{Name: "gre3"},
			contains: "gre3",
		},
		{
			name:     "ErrInvalidTunnelConfig with name",
			err:      &ErrInvalidTunnelConfig{Name: "gre4", Reason: "bad MTU"},
			contains: "gre4",
		},
		{
			name:     "ErrInvalidTunnelConfig without name",
			err:      &ErrInvalidTunnelConfig{Reason: "empty"},
			contains: "empty",
		},
		{
			name:     "ErrTunnelRemoveFailed",
			err:      &ErrTunnelRemoveFailed{Name: "gre5", Cause: io.EOF},
			contains: "gre5",
		},
		{
			name:     "ErrTunnelStatusFailed",
			err:      &ErrTunnelStatusFailed{Name: "gre6", Cause: io.EOF},
			contains: "gre6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
		})
	}
}

func TestErrors_Unwrap(t *testing.T) {
	cause := io.EOF

	t.Run("ErrTunnelCreateFailed unwraps", func(t *testing.T) {
		err := &ErrTunnelCreateFailed{Name: "gre1", Cause: cause}
		require.True(t, errors.Is(err, io.EOF))
	})

	t.Run("ErrTunnelRemoveFailed unwraps", func(t *testing.T) {
		err := &ErrTunnelRemoveFailed{Name: "gre1", Cause: cause}
		require.True(t, errors.Is(err, io.EOF))
	})

	t.Run("ErrTunnelStatusFailed unwraps", func(t *testing.T) {
		err := &ErrTunnelStatusFailed{Name: "gre1", Cause: cause}
		require.True(t, errors.Is(err, io.EOF))
	})
}

func TestErrXfrmReply(t *testing.T) {
	t.Run("names the SA and the cause", func(t *testing.T) {
		err := &ErrXfrmReply{Spi: 0x1001, Reason: "unparsable attributes", Cause: io.EOF}
		assert.Equal(t, "xfrm state spi 0x1001: unparsable attributes: EOF", err.Error())
		assert.ErrorIs(t, err, io.EOF)
	})
	t.Run("without a cause", func(t *testing.T) {
		err := &ErrXfrmReply{Spi: -1, Reason: "short reply"}
		assert.Equal(t, "xfrm state spi 0xffffffff: short reply", err.Error(), "the SPI is the kernel's u32")
		assert.NoError(t, err.Unwrap())
	})
}
