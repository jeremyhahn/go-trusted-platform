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

package switchsdk

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrNilHTTPClient(t *testing.T) {
	err := ErrNilHTTPClient{}
	assert.Contains(t, err.Error(), "http client is nil")
}

func TestErrEmptyBaseURL(t *testing.T) {
	err := ErrEmptyBaseURL{}
	assert.Contains(t, err.Error(), "base URL is empty")
}

func TestErrRequestFailed(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrRequestFailed{Method: "GET", URL: "http://example.com", Cause: cause}
	assert.Contains(t, err.Error(), "GET")
	assert.Contains(t, err.Error(), "http://example.com")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrUnexpectedStatus(t *testing.T) {
	err := ErrUnexpectedStatus{StatusCode: 500, Body: "internal error"}
	assert.Contains(t, err.Error(), "500")
	assert.Contains(t, err.Error(), "internal error")
}

func TestErrResponseDecodeFailed(t *testing.T) {
	cause := errors.New("invalid json")
	err := ErrResponseDecodeFailed{Cause: cause}
	assert.Contains(t, err.Error(), "invalid json")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrListPortsFailed(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrListPortsFailed{Switch: "core-01", Cause: cause}
	assert.Contains(t, err.Error(), "core-01")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrGetPortStatusFailed(t *testing.T) {
	cause := errors.New("not found")
	err := ErrGetPortStatusFailed{Switch: "core-01", Port: "Eth1/3", Cause: cause}
	assert.Contains(t, err.Error(), "core-01")
	assert.Contains(t, err.Error(), "Eth1/3")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrSetPortVLANFailed(t *testing.T) {
	cause := errors.New("invalid vlan")
	err := ErrSetPortVLANFailed{Switch: "core-01", Port: "Eth1/3", VLANID: 200, Cause: cause}
	assert.Contains(t, err.Error(), "200")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrEnablePortFailed(t *testing.T) {
	cause := errors.New("ssh error")
	err := ErrEnablePortFailed{Switch: "core-01", Port: "Eth1/3", Cause: cause}
	assert.Contains(t, err.Error(), "enable")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrDisablePortFailed(t *testing.T) {
	cause := errors.New("ssh error")
	err := ErrDisablePortFailed{Switch: "core-01", Port: "Eth1/3", Cause: cause}
	assert.Contains(t, err.Error(), "disable")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrRequestEncodeFailed(t *testing.T) {
	cause := errors.New("marshal error")
	err := ErrRequestEncodeFailed{Cause: cause}
	assert.Contains(t, err.Error(), "encode")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrRequestBuildFailed(t *testing.T) {
	cause := errors.New("invalid url")
	err := ErrRequestBuildFailed{Cause: cause}
	assert.Contains(t, err.Error(), "build request")
	assert.Equal(t, cause, err.Unwrap())
}
