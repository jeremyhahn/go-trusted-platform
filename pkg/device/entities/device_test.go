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

func TestDevice_EntityID(t *testing.T) {
	tests := []struct {
		name     string
		device   *Device
		expected uint64
	}{
		{
			name: "returns correct entity ID",
			device: &Device{
				ID: 12345,
			},
			expected: 12345,
		},
		{
			name: "returns zero for uninitialized ID",
			device: &Device{
				ID: 0,
			},
			expected: 0,
		},
		{
			name: "returns max uint64",
			device: &Device{
				ID: ^uint64(0), // Max uint64
			},
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.device.EntityID()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestDevice_SetEntityID(t *testing.T) {
	tests := []struct {
		name     string
		device   *Device
		newID    uint64
		expected uint64
	}{
		{
			name:     "sets entity ID correctly",
			device:   &Device{ID: 0},
			newID:    99999,
			expected: 99999,
		},
		{
			name:     "updates existing ID",
			device:   &Device{ID: 12345},
			newID:    54321,
			expected: 54321,
		},
		{
			name:     "sets zero ID",
			device:   &Device{ID: 12345},
			newID:    0,
			expected: 0,
		},
		{
			name:     "sets max uint64",
			device:   &Device{ID: 0},
			newID:    ^uint64(0),
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.device.SetEntityID(tt.newID)
			assert.Equal(t, tt.expected, tt.device.ID)
			assert.Equal(t, tt.expected, tt.device.EntityID())
		})
	}
}

func TestDevice_LargeEventLog(t *testing.T) {
	largeLog := make([]byte, 1024*1024) // 1MB
	for i := range largeLog {
		largeLog[i] = byte(i % 256)
	}

	device := &Device{
		ID:       12345,
		EventLog: largeLog,
	}

	assert.Len(t, device.EventLog, 1024*1024)
	assert.Equal(t, largeLog, device.EventLog)
}

func TestDevice_MultipleIDOperations(t *testing.T) {
	device := &Device{}

	assert.Equal(t, uint64(0), device.EntityID())

	device.SetEntityID(100)
	assert.Equal(t, uint64(100), device.EntityID())
	assert.Equal(t, uint64(100), device.ID)

	device.SetEntityID(200)
	assert.Equal(t, uint64(200), device.EntityID())
	assert.Equal(t, uint64(200), device.ID)

	device.ID = 300
	assert.Equal(t, uint64(300), device.EntityID())
}
