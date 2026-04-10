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

package serializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestStruct struct {
	Name  string `json:"name" yaml:"name"`
	Age   int    `json:"age" yaml:"age"`
	Email string `json:"email" yaml:"email"`
}

func TestSerializerType_String(t *testing.T) {
	tests := []struct {
		name     string
		st       SerializerType
		expected string
	}{
		{
			name:     "JSON serializer",
			st:       SERIALIZER_JSON,
			expected: "json",
		},
		{
			name:     "YAML serializer",
			st:       SERIALIZER_YAML,
			expected: "yaml",
		},
		{
			name:     "Invalid serializer",
			st:       SerializerType(999),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.st.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewSerializer(t *testing.T) {
	t.Run("Create JSON serializer", func(t *testing.T) {
		serializer, err := NewSerializer[TestStruct](SERIALIZER_JSON)
		require.NoError(t, err)
		require.NotNil(t, serializer)
		assert.Equal(t, SERIALIZER_JSON, serializer.Type())
		assert.Equal(t, "json", serializer.Name())
		assert.Equal(t, ".json", serializer.Extension())
	})

	t.Run("Create YAML serializer", func(t *testing.T) {
		serializer, err := NewSerializer[TestStruct](SERIALIZER_YAML)
		require.NoError(t, err)
		require.NotNil(t, serializer)
		assert.Equal(t, SERIALIZER_YAML, serializer.Type())
		assert.Equal(t, "yaml", serializer.Name())
		assert.Equal(t, ".yaml", serializer.Extension())
	})

	t.Run("Invalid serializer type", func(t *testing.T) {
		serializer, err := NewSerializer[TestStruct](SerializerType(999))
		assert.ErrorIs(t, err, ErrInvalidSerializer)
		assert.Nil(t, serializer)
	})
}

func TestSerialize(t *testing.T) {
	testData := TestStruct{
		Name:  "John Doe",
		Age:   30,
		Email: "john@example.com",
	}

	t.Run("Serialize with JSON", func(t *testing.T) {
		data, err := Serialize(testData, SERIALIZER_JSON)
		require.NoError(t, err)
		require.NotNil(t, data)
		assert.Contains(t, string(data), "John Doe")
		assert.Contains(t, string(data), "john@example.com")
	})

	t.Run("Serialize with YAML", func(t *testing.T) {
		data, err := Serialize(testData, SERIALIZER_YAML)
		require.NoError(t, err)
		require.NotNil(t, data)
		assert.Contains(t, string(data), "John Doe")
		assert.Contains(t, string(data), "john@example.com")
	})

	t.Run("Serialize with invalid serializer", func(t *testing.T) {
		data, err := Serialize(testData, SerializerType(999))
		assert.ErrorIs(t, err, ErrInvalidSerializer)
		assert.Nil(t, data)
	})
}

func TestDeserialize(t *testing.T) {
	t.Run("Deserialize JSON", func(t *testing.T) {
		jsonData := []byte(`{"name":"Jane Doe","age":25,"email":"jane@example.com"}`)
		var result TestStruct
		err := Deserialize(jsonData, &result, SERIALIZER_JSON)
		require.NoError(t, err)
		assert.Equal(t, "Jane Doe", result.Name)
		assert.Equal(t, 25, result.Age)
		assert.Equal(t, "jane@example.com", result.Email)
	})

	t.Run("Deserialize YAML", func(t *testing.T) {
		yamlData := []byte(`name: Jane Doe
age: 25
email: jane@example.com`)
		var result TestStruct
		err := Deserialize(yamlData, &result, SERIALIZER_YAML)
		require.NoError(t, err)
		assert.Equal(t, "Jane Doe", result.Name)
		assert.Equal(t, 25, result.Age)
		assert.Equal(t, "jane@example.com", result.Email)
	})

	t.Run("Deserialize with invalid serializer", func(t *testing.T) {
		data := []byte(`{"name":"Test"}`)
		var result TestStruct
		err := Deserialize(data, &result, SerializerType(999))
		assert.ErrorIs(t, err, ErrInvalidSerializer)
	})

	t.Run("Deserialize invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{invalid json}`)
		var result TestStruct
		err := Deserialize(invalidJSON, &result, SERIALIZER_JSON)
		assert.Error(t, err)
	})

	t.Run("Deserialize invalid YAML", func(t *testing.T) {
		invalidYAML := []byte(`invalid: yaml: structure: [`)
		var result TestStruct
		err := Deserialize(invalidYAML, &result, SERIALIZER_YAML)
		assert.Error(t, err)
	})
}

func TestSerializerExtension(t *testing.T) {
	tests := []struct {
		name       string
		serializer SerializerType
		expected   string
	}{
		{
			name:       "JSON extension",
			serializer: SERIALIZER_JSON,
			expected:   ".json",
		},
		{
			name:       "YAML extension",
			serializer: SERIALIZER_YAML,
			expected:   ".yaml",
		},
		{
			name:       "Invalid serializer",
			serializer: SerializerType(999),
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SerializerExtension(tt.serializer)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSerializer(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    SerializerType
		expectError bool
		expectedErr error
	}{
		{
			name:        "Parse json",
			input:       "json",
			expected:    SERIALIZER_JSON,
			expectError: false,
		},
		{
			name:        "Parse yaml",
			input:       "yaml",
			expected:    SERIALIZER_YAML,
			expectError: false,
		},
		{
			name:        "Parse invalid",
			input:       "xml",
			expectError: true,
			expectedErr: ErrInvalidSerializer,
		},
		{
			name:        "Parse empty string",
			input:       "",
			expectError: true,
			expectedErr: ErrInvalidSerializer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSerializer(tt.input)
			if tt.expectError {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	original := TestStruct{
		Name:  "Alice Smith",
		Age:   35,
		Email: "alice@example.com",
	}

	t.Run("JSON round trip", func(t *testing.T) {
		// Serialize
		data, err := Serialize(original, SERIALIZER_JSON)
		require.NoError(t, err)

		// Deserialize
		var result TestStruct
		err = Deserialize(data, &result, SERIALIZER_JSON)
		require.NoError(t, err)

		// Verify
		assert.Equal(t, original.Name, result.Name)
		assert.Equal(t, original.Age, result.Age)
		assert.Equal(t, original.Email, result.Email)
	})

	t.Run("YAML round trip", func(t *testing.T) {
		// Serialize
		data, err := Serialize(original, SERIALIZER_YAML)
		require.NoError(t, err)

		// Deserialize
		var result TestStruct
		err = Deserialize(data, &result, SERIALIZER_YAML)
		require.NoError(t, err)

		// Verify
		assert.Equal(t, original.Name, result.Name)
		assert.Equal(t, original.Age, result.Age)
		assert.Equal(t, original.Email, result.Email)
	})
}
