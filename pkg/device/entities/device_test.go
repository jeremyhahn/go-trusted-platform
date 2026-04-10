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
	"github.com/stretchr/testify/require"
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

func TestDevice_FieldValues(t *testing.T) {
	device := &Device{
		ID:         12345,
		AttestPub:  "attest-public-key",
		EKCert:     "endorsement-key-cert",
		EventLog:   []byte("event-log-data"),
		HashAlgoId: 11,
		Model:      "TPM2000",
		Serial:     "SN123456789",
		SigningPub: "signing-public-key",
	}

	assert.Equal(t, uint64(12345), device.ID)
	assert.Equal(t, "attest-public-key", device.AttestPub)
	assert.Equal(t, "endorsement-key-cert", device.EKCert)
	assert.Equal(t, []byte("event-log-data"), device.EventLog)
	assert.Equal(t, uint32(11), device.HashAlgoId)
	assert.Equal(t, "TPM2000", device.Model)
	assert.Equal(t, "SN123456789", device.Serial)
	assert.Equal(t, "signing-public-key", device.SigningPub)
}

func TestDevice_EmptyDevice(t *testing.T) {
	device := &Device{}

	assert.Equal(t, uint64(0), device.ID)
	assert.Equal(t, "", device.AttestPub)
	assert.Equal(t, "", device.EKCert)
	assert.Nil(t, device.EventLog)
	assert.Equal(t, uint32(0), device.HashAlgoId)
	assert.Equal(t, "", device.Model)
	assert.Equal(t, "", device.Serial)
	assert.Equal(t, "", device.SigningPub)
}

func TestDevice_NilEventLog(t *testing.T) {
	device := &Device{
		ID:       12345,
		EventLog: nil,
	}

	assert.Nil(t, device.EventLog)
}

func TestDevice_EmptyEventLog(t *testing.T) {
	device := &Device{
		ID:       12345,
		EventLog: []byte{},
	}

	require.NotNil(t, device.EventLog)
	assert.Len(t, device.EventLog, 0)
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
