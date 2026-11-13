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

package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceTemplate_EntityID(t *testing.T) {
	tests := []struct {
		name     string
		template *DeviceTemplate
		expected uint64
	}{
		{
			name: "returns correct entity ID",
			template: &DeviceTemplate{
				ID: 12345,
			},
			expected: 12345,
		},
		{
			name: "returns zero for uninitialized ID",
			template: &DeviceTemplate{
				ID: 0,
			},
			expected: 0,
		},
		{
			name: "returns max uint64",
			template: &DeviceTemplate{
				ID: ^uint64(0),
			},
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.template.EntityID())
		})
	}
}

func TestDeviceTemplate_SetEntityID(t *testing.T) {
	tests := []struct {
		name     string
		id       uint64
		expected uint64
	}{
		{
			name:     "sets normal ID",
			id:       42,
			expected: 42,
		},
		{
			name:     "sets zero ID",
			id:       0,
			expected: 0,
		},
		{
			name:     "sets max uint64",
			id:       ^uint64(0),
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &DeviceTemplate{}
			tmpl.SetEntityID(tt.id)
			assert.Equal(t, tt.expected, tmpl.ID)
			assert.Equal(t, tt.expected, tmpl.EntityID())
		})
	}
}
