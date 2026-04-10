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

package ovs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{
			name: "ErrNotConnected",
			err:  ErrNotConnected,
			msg:  "not connected to OVSDB",
		},
		{
			name: "ErrInvalidSocket",
			err:  ErrInvalidSocket,
			msg:  "invalid OVSDB socket path",
		},
		{
			name: "ErrBridgeNotFound",
			err:  ErrBridgeNotFound,
			msg:  "bridge not found",
		},
		{
			name: "ErrBridgeExists",
			err:  ErrBridgeExists,
			msg:  "bridge already exists",
		},
		{
			name: "ErrPortNotFound",
			err:  ErrPortNotFound,
			msg:  "port not found",
		},
		{
			name: "ErrPortExists",
			err:  ErrPortExists,
			msg:  "port already exists",
		},
		{
			name: "ErrFlowNotFound",
			err:  ErrFlowNotFound,
			msg:  "flow not found",
		},
		{
			name: "ErrInvalidFlow",
			err:  ErrInvalidFlow,
			msg:  "invalid flow specification",
		},
		{
			name: "ErrInvalidBridgeName",
			err:  ErrInvalidBridgeName,
			msg:  "invalid bridge name",
		},
		{
			name: "ErrInvalidPortName",
			err:  ErrInvalidPortName,
			msg:  "invalid port name",
		},
		{
			name: "ErrInvalidProtocol",
			err:  ErrInvalidProtocol,
			msg:  "invalid OpenFlow protocol version",
		},
		{
			name: "ErrTransactionFailed",
			err:  ErrTransactionFailed,
			msg:  "OVSDB transaction failed",
		},
		{
			name: "ErrOperationTimeout",
			err:  ErrOperationTimeout,
			msg:  "operation timeout",
		},
		{
			name: "ErrInvalidResponse",
			err:  ErrInvalidResponse,
			msg:  "invalid OVSDB response",
		},
		{
			name: "ErrProtocolViolation",
			err:  ErrProtocolViolation,
			msg:  "OVSDB protocol violation",
		},
		{
			name: "ErrTableNotFound",
			err:  ErrTableNotFound,
			msg:  "database table not found",
		},
		{
			name: "ErrColumnNotFound",
			err:  ErrColumnNotFound,
			msg:  "column not found",
		},
		{
			name: "ErrUUIDRequired",
			err:  ErrUUIDRequired,
			msg:  "UUID is required",
		},
		{
			name: "ErrInvalidUUID",
			err:  ErrInvalidUUID,
			msg:  "invalid UUID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, tt.err)
			assert.Equal(t, tt.msg, tt.err.Error())
			assert.True(t, errors.Is(tt.err, tt.err))
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	baseErr := ErrBridgeNotFound
	wrappedErr := errors.New("wrapped: " + baseErr.Error())

	assert.Error(t, wrappedErr)
	assert.Contains(t, wrappedErr.Error(), baseErr.Error())
}
