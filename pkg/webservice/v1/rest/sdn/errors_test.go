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

package sdn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrInvalidRequestBody_Error(t *testing.T) {
	err := ErrInvalidRequestBody{Reason: "invalid json syntax"}
	assert.Equal(t, "invalid request body: invalid json syntax", err.Error())
}

func TestErrMissingZoneName_Error(t *testing.T) {
	assert.Equal(t, "zone name is required", ErrMissingZoneName{}.Error())
}

func TestErrZoneNameMismatch_Error(t *testing.T) {
	err := ErrZoneNameMismatch{Path: "lab", Body: "prod"}
	assert.Equal(t, "zone name mismatch: path=lab, body=prod", err.Error())
}
