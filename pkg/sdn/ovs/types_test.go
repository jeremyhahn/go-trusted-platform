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

package ovs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUUIDMarshalJSON(t *testing.T) {
	uuid := UUID{UUID: "550e8400-e29b-41d4-a716-446655440000"}

	data, err := json.Marshal(uuid)
	require.NoError(t, err)

	expected := `["uuid","550e8400-e29b-41d4-a716-446655440000"]`
	assert.JSONEq(t, expected, string(data))
}

func TestUUIDUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected UUID
		wantErr  bool
	}{
		{
			name:     "array format",
			input:    `["uuid","550e8400-e29b-41d4-a716-446655440000"]`,
			expected: UUID{UUID: "550e8400-e29b-41d4-a716-446655440000"},
			wantErr:  false,
		},
		{
			name:     "object format",
			input:    `{"uuid":"550e8400-e29b-41d4-a716-446655440000"}`,
			expected: UUID{UUID: "550e8400-e29b-41d4-a716-446655440000"},
			wantErr:  false,
		},
		{
			name:    "invalid array - wrong type",
			input:   `["not-uuid","550e8400-e29b-41d4-a716-446655440000"]`,
			wantErr: true,
		},
		{
			name:    "invalid array - single element",
			input:   `["uuid"]`,
			wantErr: true,
		},
		{
			name:    "invalid array - too many elements",
			input:   `["uuid","550e8400-e29b-41d4-a716-446655440000","extra"]`,
			wantErr: true,
		},
		{
			name:    "invalid type - string",
			input:   `"550e8400-e29b-41d4-a716-446655440000"`,
			wantErr: true,
		},
		{
			name:    "invalid type - number",
			input:   `123`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:     "empty object",
			input:    `{}`,
			expected: UUID{UUID: ""},
			wantErr:  false,
		},
		{
			name:    "empty array",
			input:   `[]`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var uuid UUID
			err := json.Unmarshal([]byte(tt.input), &uuid)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, uuid)
			}
		})
	}
}

func TestNamedUUIDMarshalJSON(t *testing.T) {
	namedUUID := NamedUUID{NamedUUID: "new_bridge"}

	data, err := json.Marshal(namedUUID)
	require.NoError(t, err)

	expected := `["named-uuid","new_bridge"]`
	assert.JSONEq(t, expected, string(data))
}

func TestMarshalSet(t *testing.T) {
	tests := []struct {
		name     string
		values   []interface{}
		expected interface{}
	}{
		{
			name:     "empty set",
			values:   []interface{}{},
			expected: Set{Set: []interface{}{}},
		},
		{
			name:     "single value",
			values:   []interface{}{"value1"},
			expected: "value1",
		},
		{
			name:     "multiple values",
			values:   []interface{}{"value1", "value2", "value3"},
			expected: Set{Set: []interface{}{"value1", "value2", "value3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MarshalSet(tt.values)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMarshalMap(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string]string
		expected interface{}
	}{
		{
			name:     "empty map",
			values:   map[string]string{},
			expected: Map{Map: [][]interface{}{}},
		},
		{
			name: "single entry",
			values: map[string]string{
				"key1": "value1",
			},
			expected: Map{Map: [][]interface{}{{"key1", "value1"}}},
		},
		{
			name: "multiple entries",
			values: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expected: Map{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MarshalMap(tt.values)

			if len(tt.values) <= 1 {
				assert.Equal(t, tt.expected, result)
			} else {
				// For multiple entries, just check type
				_, ok := result.(Map)
				assert.True(t, ok)
			}
		})
	}
}

func TestUnmarshalSet(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected []interface{}
		wantErr  bool
	}{
		{
			name:     "slice",
			value:    []interface{}{"value1", "value2"},
			expected: []interface{}{"value1", "value2"},
			wantErr:  false,
		},
		{
			name: "map with set",
			value: map[string]interface{}{
				"set": []interface{}{"value1", "value2"},
			},
			expected: []interface{}{"value1", "value2"},
			wantErr:  false,
		},
		{
			name:     "invalid type",
			value:    "invalid",
			expected: nil,
			wantErr:  true,
		},
		{
			name: "map without set key",
			value: map[string]interface{}{
				"other": []interface{}{"value1"},
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "map with non-array set",
			value: map[string]interface{}{
				"set": "not-an-array",
			},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalSet(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestUnmarshalMap(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected map[string]string
		wantErr  bool
	}{
		{
			name: "valid map",
			value: map[string]interface{}{
				"map": []interface{}{
					[]interface{}{"key1", "value1"},
					[]interface{}{"key2", "value2"},
				},
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			wantErr: false,
		},
		{
			name: "empty map",
			value: map[string]interface{}{
				"map": []interface{}{},
			},
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name:     "invalid type",
			value:    "invalid",
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name: "map with invalid pair - not array",
			value: map[string]interface{}{
				"map": []interface{}{
					"not-an-array",
				},
			},
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name: "map with invalid pair - single element",
			value: map[string]interface{}{
				"map": []interface{}{
					[]interface{}{"key1"},
				},
			},
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name: "map with invalid pair - non-string key",
			value: map[string]interface{}{
				"map": []interface{}{
					[]interface{}{123, "value1"},
				},
			},
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name: "map with invalid pair - non-string value",
			value: map[string]interface{}{
				"map": []interface{}{
					[]interface{}{"key1", 123},
				},
			},
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name: "map without map key",
			value: map[string]interface{}{
				"other": []interface{}{},
			},
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name: "map with non-array map value",
			value: map[string]interface{}{
				"map": "not-an-array",
			},
			expected: map[string]string{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalMap(tt.value)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnmarshalUUID(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
		wantErr  bool
	}{
		{
			name:     "string uuid",
			value:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400-e29b-41d4-a716-446655440000",
			wantErr:  false,
		},
		{
			name:     "array uuid",
			value:    []interface{}{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
			expected: "550e8400-e29b-41d4-a716-446655440000",
			wantErr:  false,
		},
		{
			name: "map uuid",
			value: map[string]interface{}{
				"uuid": "550e8400-e29b-41d4-a716-446655440000",
			},
			expected: "550e8400-e29b-41d4-a716-446655440000",
			wantErr:  false,
		},
		{
			name:     "invalid type",
			value:    123,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "array with wrong first element",
			value:    []interface{}{"not-uuid", "550e8400-e29b-41d4-a716-446655440000"},
			expected: "",
			wantErr:  true,
		},
		{
			name:     "array with non-string uuid",
			value:    []interface{}{"uuid", 123},
			expected: "",
			wantErr:  true,
		},
		{
			name:     "array with single element",
			value:    []interface{}{"uuid"},
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty array",
			value:    []interface{}{},
			expected: "",
			wantErr:  true,
		},
		{
			name: "map with non-string uuid",
			value: map[string]interface{}{
				"uuid": 123,
			},
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty map",
			value:    map[string]interface{}{},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnmarshalUUID(tt.value)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidUUID, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestPortState(t *testing.T) {
	assert.Equal(t, PortState("up"), PortStateUp)
	assert.Equal(t, PortState("down"), PortStateDown)
}

// Note: TestFlowStructure and TestFlowModStructure are defined in flow_test.go
// with more comprehensive tests that verify buildFlowSpec behavior
