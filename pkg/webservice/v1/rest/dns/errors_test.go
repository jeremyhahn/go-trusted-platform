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

func TestErrInvalidRecordType_Error(t *testing.T) {
	err := &ErrInvalidRecordType{Type: "UNKNOWN"}
	assert.Equal(t, "invalid record type: UNKNOWN", err.Error())
}

func TestErrRecordNotFound_Error(t *testing.T) {
	err := &ErrRecordNotFound{Type: "A", Name: "www"}
	assert.Equal(t, "record not found: A www", err.Error())
}
