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

//go:build codec_msgpack

package quic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateDeviceIDFromSerial_Valid(t *testing.T) {
	id := generateDeviceIDFromSerial("ABC-123-XYZ")
	assert.NotZero(t, id)
}

func TestGenerateDeviceIDFromSerial_Empty(t *testing.T) {
	id := generateDeviceIDFromSerial("")
	assert.Equal(t, uint64(0), id)
}

func TestGenerateDeviceIDFromSerial_Deterministic(t *testing.T) {
	id1 := generateDeviceIDFromSerial("serial-001")
	id2 := generateDeviceIDFromSerial("serial-001")
	assert.Equal(t, id1, id2)
}

func TestGenerateDeviceIDFromSerial_Unique(t *testing.T) {
	id1 := generateDeviceIDFromSerial("serial-001")
	id2 := generateDeviceIDFromSerial("serial-002")
	assert.NotEqual(t, id1, id2)
}

func TestGenerateProfileIDFromName_Valid(t *testing.T) {
	id := generateProfileIDFromName("my-profile")
	assert.NotZero(t, id)
}

func TestGenerateProfileIDFromName_Empty(t *testing.T) {
	id := generateProfileIDFromName("")
	assert.Equal(t, uint64(0), id)
}

func TestGenerateProfileIDFromName_Deterministic(t *testing.T) {
	id1 := generateProfileIDFromName("profile-a")
	id2 := generateProfileIDFromName("profile-a")
	assert.Equal(t, id1, id2)
}

func TestCalculateTotalPagesInt32(t *testing.T) {
	tests := []struct {
		name     string
		total    int
		pageSize int
		expected int32
	}{
		{name: "exact pages", total: 20, pageSize: 10, expected: 2},
		{name: "partial page", total: 21, pageSize: 10, expected: 3},
		{name: "zero page size", total: 10, pageSize: 0, expected: 0},
		{name: "negative page size", total: 10, pageSize: -1, expected: 0},
		{name: "zero total", total: 0, pageSize: 10, expected: 0},
		{name: "single item", total: 1, pageSize: 10, expected: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateTotalPagesInt32(tt.total, tt.pageSize)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{name: "exact match", s: "hello", substr: "hello", expected: true},
		{name: "case insensitive", s: "Hello World", substr: "hello", expected: true},
		{name: "uppercase substr", s: "hello world", substr: "HELLO", expected: true},
		{name: "not found", s: "hello", substr: "xyz", expected: false},
		{name: "substr longer", s: "hi", substr: "hello", expected: false},
		{name: "empty substr", s: "hello", substr: "", expected: true},
		{name: "both empty", s: "", substr: "", expected: true},
		{name: "partial match", s: "abcdef", substr: "cde", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsIgnoreCase(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
