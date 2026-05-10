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

package switchcmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrSwitchNameRequired(t *testing.T) {
	err := ErrSwitchNameRequired{}
	assert.Contains(t, err.Error(), "--switch is required")
}

func TestErrPortNameRequired(t *testing.T) {
	err := ErrPortNameRequired{}
	assert.Contains(t, err.Error(), "--port is required")
}

func TestErrVLANIDRequired(t *testing.T) {
	err := ErrVLANIDRequired{}
	assert.Contains(t, err.Error(), "--vlan is required")
}

func TestErrInvalidVLANID(t *testing.T) {
	err := ErrInvalidVLANID{Value: 5000}
	assert.Contains(t, err.Error(), "5000")
	assert.Contains(t, err.Error(), "1-4094")
}

func TestErrServerURLRequired(t *testing.T) {
	err := ErrServerURLRequired{}
	assert.Contains(t, err.Error(), "--server-url is required")
}

func TestErrOperationFailed(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrOperationFailed{Operation: "list-ports", Cause: cause}
	assert.Contains(t, err.Error(), "list-ports")
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrClientCreateFailed(t *testing.T) {
	cause := errors.New("bad url")
	err := ErrClientCreateFailed{Cause: cause}
	assert.Contains(t, err.Error(), "create client")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrContextResolveFailed(t *testing.T) {
	cause := errors.New("no config")
	err := ErrContextResolveFailed{Cause: cause}
	assert.Contains(t, err.Error(), "resolve context")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrTLSConfigFailed(t *testing.T) {
	cause := errors.New("bad cert")
	err := ErrTLSConfigFailed{Cause: cause}
	assert.Contains(t, err.Error(), "TLS config")
	assert.Equal(t, cause, err.Unwrap())
}
