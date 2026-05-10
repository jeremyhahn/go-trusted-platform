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

package switchapi

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMissingSwitchName(t *testing.T) {
	err := ErrMissingSwitchName{}
	assert.Contains(t, err.Error(), "switch name is required")
}

func TestErrMissingPortName(t *testing.T) {
	err := ErrMissingPortName{}
	assert.Contains(t, err.Error(), "port name is required")
}

func TestErrInvalidRequestBody(t *testing.T) {
	err := ErrInvalidRequestBody{Reason: "bad json"}
	assert.Contains(t, err.Error(), "bad json")
}

func TestErrMissingVLANID(t *testing.T) {
	err := ErrMissingVLANID{}
	assert.Contains(t, err.Error(), "vlan_id is required")
}

func TestErrInvalidVLANID(t *testing.T) {
	err := ErrInvalidVLANID{Value: 5000}
	assert.Contains(t, err.Error(), "5000")
	assert.Contains(t, err.Error(), "1-4094")
}

func TestErrSwitchNotFound(t *testing.T) {
	err := ErrSwitchNotFound{Name: "core-01"}
	assert.Contains(t, err.Error(), "core-01")
	assert.Contains(t, err.Error(), "not found")
}

func TestErrPortOperationFailed(t *testing.T) {
	cause := errors.New("ssh timeout")
	err := ErrPortOperationFailed{
		Operation: "enable",
		Switch:    "core-01",
		Port:      "Eth1/3",
		Cause:     cause,
	}
	assert.Contains(t, err.Error(), "enable")
	assert.Contains(t, err.Error(), "core-01")
	assert.Contains(t, err.Error(), "Eth1/3")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrListPortsFailed(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrListPortsFailed{Switch: "core-01", Cause: cause}
	assert.Contains(t, err.Error(), "core-01")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrServiceNil(t *testing.T) {
	err := ErrServiceNil{}
	assert.Contains(t, err.Error(), "not initialized")
}
