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

package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMissingZoneName_Error(t *testing.T) {
	err := ErrMissingZoneName{}
	assert.Equal(t, "zone name is required", err.Error())
}

func TestErrMissingRecordName_Error(t *testing.T) {
	err := ErrMissingRecordName{}
	assert.Equal(t, "record name is required", err.Error())
}

func TestErrMissingRecordType_Error(t *testing.T) {
	err := ErrMissingRecordType{}
	assert.Equal(t, "record type is required", err.Error())
}

func TestErrInvalidRequestBody_Error(t *testing.T) {
	err := ErrInvalidRequestBody{Reason: "invalid JSON"}
	assert.Equal(t, "invalid request body: invalid JSON", err.Error())
}

func TestErrInvalidRequestBody_Error_Empty(t *testing.T) {
	err := ErrInvalidRequestBody{}
	assert.Equal(t, "invalid request body: ", err.Error())
}

func TestErrInvalidRecordType_Error(t *testing.T) {
	err := ErrInvalidRecordType{Type: "UNKNOWN"}
	assert.Equal(t, "invalid record type: UNKNOWN", err.Error())
}

func TestErrInvalidRecordType_Error_Empty(t *testing.T) {
	err := ErrInvalidRecordType{}
	assert.Equal(t, "invalid record type: ", err.Error())
}

func TestErrMissingFQDN_Error(t *testing.T) {
	err := ErrMissingFQDN{}
	assert.Equal(t, "fqdn is required", err.Error())
}

func TestErrMissingIP_Error(t *testing.T) {
	err := ErrMissingIP{}
	assert.Equal(t, "ip address is required", err.Error())
}

// Test error interface implementation
func TestErrorsImplementErrorInterface(t *testing.T) {
	var _ error = ErrMissingZoneName{}
	var _ error = ErrMissingRecordName{}
	var _ error = ErrMissingRecordType{}
	var _ error = ErrInvalidRequestBody{}
	var _ error = ErrInvalidRecordType{}
	var _ error = ErrMissingFQDN{}
	var _ error = ErrMissingIP{}
}
