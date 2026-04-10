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

// TestMapMarshalJSON tests the Map.MarshalJSON function
func TestMapMarshalJSON(t *testing.T) {
	t.Run("empty map marshals correctly", func(t *testing.T) {
		m := Map{Map: [][]interface{}{}}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		expected := `["map",[]]`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("single entry map marshals correctly", func(t *testing.T) {
		m := Map{
			Map: [][]interface{}{
				{"key1", "value1"},
			},
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		expected := `["map",[["key1","value1"]]]`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("multiple entry map marshals correctly", func(t *testing.T) {
		m := Map{
			Map: [][]interface{}{
				{"key1", "value1"},
				{"key2", "value2"},
			},
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)

		// Check it contains the map structure
		assert.Contains(t, string(data), `"map"`)
		assert.Contains(t, string(data), `"key1"`)
		assert.Contains(t, string(data), `"value1"`)
		assert.Contains(t, string(data), `"key2"`)
		assert.Contains(t, string(data), `"value2"`)
	})

	t.Run("map with different value types", func(t *testing.T) {
		m := Map{
			Map: [][]interface{}{
				{"string_key", "string_value"},
				{"int_key", float64(123)},
				{"bool_key", true},
			},
		}

		data, err := json.Marshal(m)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("map marshaled as part of struct", func(t *testing.T) {
		type TestStruct struct {
			ExternalIDs Map `json:"external_ids"`
		}

		ts := TestStruct{
			ExternalIDs: Map{
				Map: [][]interface{}{
					{"key", "value"},
				},
			},
		}

		data, err := json.Marshal(ts)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"external_ids"`)
		assert.Contains(t, string(data), `"map"`)
	})
}

// TestSetMarshalJSON tests the Set.MarshalJSON function
func TestSetMarshalJSON(t *testing.T) {
	t.Run("empty set marshals correctly", func(t *testing.T) {
		s := Set{Set: []interface{}{}}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		expected := `["set",[]]`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("single element set marshals correctly", func(t *testing.T) {
		s := Set{Set: []interface{}{"value1"}}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		expected := `["set",["value1"]]`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("multiple element set marshals correctly", func(t *testing.T) {
		s := Set{Set: []interface{}{"value1", "value2", "value3"}}

		data, err := json.Marshal(s)
		require.NoError(t, err)

		assert.Contains(t, string(data), `"set"`)
		assert.Contains(t, string(data), `"value1"`)
		assert.Contains(t, string(data), `"value2"`)
		assert.Contains(t, string(data), `"value3"`)
	})

	t.Run("set with different value types", func(t *testing.T) {
		s := Set{
			Set: []interface{}{
				"string",
				float64(123),
				true,
			},
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("set marshaled as part of struct", func(t *testing.T) {
		type TestStruct struct {
			Ports Set `json:"ports"`
		}

		ts := TestStruct{
			Ports: Set{
				Set: []interface{}{
					"port1",
					"port2",
				},
			},
		}

		data, err := json.Marshal(ts)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"ports"`)
		assert.Contains(t, string(data), `"set"`)
	})
}

// TestMarshalSetEdgeCases tests edge cases in MarshalSet
func TestMarshalSetEdgeCases(t *testing.T) {
	t.Run("nil slice returns empty set", func(t *testing.T) {
		result := MarshalSet(nil)
		set, ok := result.(Set)
		assert.True(t, ok)
		assert.Empty(t, set.Set)
	})

	t.Run("single value returns value directly", func(t *testing.T) {
		values := []interface{}{"single"}
		result := MarshalSet(values)
		str, ok := result.(string)
		assert.True(t, ok)
		assert.Equal(t, "single", str)
	})

	t.Run("multiple values return set", func(t *testing.T) {
		values := []interface{}{"first", "second"}
		result := MarshalSet(values)
		set, ok := result.(Set)
		assert.True(t, ok)
		assert.Len(t, set.Set, 2)
	})

	t.Run("set with UUID values", func(t *testing.T) {
		values := []interface{}{
			[]interface{}{"uuid", "uuid-1"},
			[]interface{}{"uuid", "uuid-2"},
		}
		result := MarshalSet(values)
		set, ok := result.(Set)
		assert.True(t, ok)
		assert.Len(t, set.Set, 2)
	})
}

// TestMarshalMapEdgeCases tests edge cases in MarshalMap
func TestMarshalMapEdgeCases(t *testing.T) {
	t.Run("nil map returns empty map", func(t *testing.T) {
		result := MarshalMap(nil)
		m, ok := result.(Map)
		assert.True(t, ok)
		assert.Empty(t, m.Map)
	})

	t.Run("empty map returns empty map", func(t *testing.T) {
		result := MarshalMap(map[string]string{})
		m, ok := result.(Map)
		assert.True(t, ok)
		assert.Empty(t, m.Map)
	})

	t.Run("single entry map", func(t *testing.T) {
		input := map[string]string{"key": "value"}
		result := MarshalMap(input)
		m, ok := result.(Map)
		assert.True(t, ok)
		assert.Len(t, m.Map, 1)
		assert.Equal(t, "key", m.Map[0][0])
		assert.Equal(t, "value", m.Map[0][1])
	})

	t.Run("multiple entry map", func(t *testing.T) {
		input := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}
		result := MarshalMap(input)
		m, ok := result.(Map)
		assert.True(t, ok)
		assert.Len(t, m.Map, 3)

		// Verify all entries are present (order may vary)
		found := make(map[string]string)
		for _, pair := range m.Map {
			found[pair[0].(string)] = pair[1].(string)
		}
		assert.Equal(t, input, found)
	})

	t.Run("map with empty strings", func(t *testing.T) {
		input := map[string]string{"": "empty_key", "empty_value": ""}
		result := MarshalMap(input)
		m, ok := result.(Map)
		assert.True(t, ok)
		assert.Len(t, m.Map, 2)
	})

	t.Run("map with special characters", func(t *testing.T) {
		input := map[string]string{
			"key.with.dots":        "value",
			"key-with-dashes":      "value",
			"key_with_underscores": "value",
		}
		result := MarshalMap(input)
		m, ok := result.(Map)
		assert.True(t, ok)
		assert.Len(t, m.Map, 3)
	})
}

// TestUnmarshalUUIDEdgeCases tests additional edge cases for UnmarshalUUID
func TestUnmarshalUUIDEdgeCases(t *testing.T) {
	t.Run("array with three elements returns error", func(t *testing.T) {
		value := []interface{}{"uuid", "actual-uuid", "extra"}
		_, err := UnmarshalUUID(value)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidUUID, err)
	})

	t.Run("array with wrong prefix", func(t *testing.T) {
		value := []interface{}{"not-uuid", "actual-uuid"}
		_, err := UnmarshalUUID(value)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidUUID, err)
	})

	t.Run("map with wrong key type", func(t *testing.T) {
		value := map[string]interface{}{
			"other_key": "value",
		}
		_, err := UnmarshalUUID(value)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidUUID, err)
	})

	t.Run("bool value returns error", func(t *testing.T) {
		_, err := UnmarshalUUID(true)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidUUID, err)
	})

	t.Run("float value returns error", func(t *testing.T) {
		_, err := UnmarshalUUID(123.456)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidUUID, err)
	})

	t.Run("nil value returns error", func(t *testing.T) {
		_, err := UnmarshalUUID(nil)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidUUID, err)
	})
}

// TestUUIDRoundTrip tests UUID marshal/unmarshal round trip
func TestUUIDRoundTrip(t *testing.T) {
	original := UUID{UUID: "550e8400-e29b-41d4-a716-446655440000"}

	// Marshal
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	var result UUID
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, original, result)
}

// TestNamedUUIDEdgeCases tests edge cases for NamedUUID
func TestNamedUUIDEdgeCases(t *testing.T) {
	t.Run("empty named-uuid", func(t *testing.T) {
		namedUUID := NamedUUID{NamedUUID: ""}

		data, err := json.Marshal(namedUUID)
		require.NoError(t, err)

		expected := `["named-uuid",""]`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("named-uuid with special characters", func(t *testing.T) {
		namedUUID := NamedUUID{NamedUUID: "new_bridge-123"}

		data, err := json.Marshal(namedUUID)
		require.NoError(t, err)

		assert.Contains(t, string(data), "named-uuid")
		assert.Contains(t, string(data), "new_bridge-123")
	})
}

// TestOVSDBTypesInContext tests OVSDB types used in realistic scenarios
func TestOVSDBTypesInContext(t *testing.T) {
	t.Run("bridge-like structure with sets and maps", func(t *testing.T) {
		type BridgeRow struct {
			Name        string `json:"name"`
			Ports       Set    `json:"ports"`
			ExternalIDs Map    `json:"external_ids"`
		}

		bridge := BridgeRow{
			Name: "br0",
			Ports: Set{
				Set: []interface{}{
					[]interface{}{"uuid", "port-uuid-1"},
					[]interface{}{"uuid", "port-uuid-2"},
				},
			},
			ExternalIDs: Map{
				Map: [][]interface{}{
					{"bridge-id", "br0"},
					{"created-by", "test"},
				},
			},
		}

		data, err := json.Marshal(bridge)
		require.NoError(t, err)
		assert.Contains(t, string(data), "br0")
		assert.Contains(t, string(data), "ports")
		assert.Contains(t, string(data), "external_ids")
	})

	t.Run("port-like structure with optional fields", func(t *testing.T) {
		type PortRow struct {
			Name       string      `json:"name"`
			Tag        interface{} `json:"tag"`
			Trunks     Set         `json:"trunks"`
			Interfaces Set         `json:"interfaces"`
		}

		// Port with no VLAN tag (empty set)
		port := PortRow{
			Name: "eth0",
			Tag:  Set{Set: []interface{}{}},
			Trunks: Set{
				Set: []interface{}{
					float64(100),
					float64(200),
				},
			},
			Interfaces: Set{
				Set: []interface{}{
					[]interface{}{"uuid", "iface-uuid"},
				},
			},
		}

		data, err := json.Marshal(port)
		require.NoError(t, err)
		assert.Contains(t, string(data), "eth0")
	})
}

// TestComplexTypeConversions tests complex type conversion scenarios
func TestComplexTypeConversions(t *testing.T) {
	t.Run("nested sets and maps", func(t *testing.T) {
		complexMap := Map{
			Map: [][]interface{}{
				{"key1", Set{Set: []interface{}{"val1", "val2"}}},
				{"key2", Map{Map: [][]interface{}{{"nested", "value"}}}},
			},
		}

		data, err := json.Marshal(complexMap)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("set of UUIDs", func(t *testing.T) {
		uuidSet := Set{
			Set: []interface{}{
				[]interface{}{"uuid", "uuid-1"},
				[]interface{}{"uuid", "uuid-2"},
				[]interface{}{"uuid", "uuid-3"},
			},
		}

		data, err := json.Marshal(uuidSet)
		require.NoError(t, err)
		assert.Contains(t, string(data), "set")
		assert.Contains(t, string(data), "uuid")
	})

	t.Run("map with mixed value types", func(t *testing.T) {
		mixedMap := Map{
			Map: [][]interface{}{
				{"string", "value"},
				{"number", float64(42)},
				{"bool", true},
				{"null", nil},
			},
		}

		data, err := json.Marshal(mixedMap)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
}
