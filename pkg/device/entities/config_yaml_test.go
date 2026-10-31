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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestMarshalConfigYAML_NumbersArePlainScalars pins #125: a config the DAO
// decoded with UseNumber holds json.Number, which plain yaml.Marshal quotes.
// Each number, at any depth, is emitted unquoted with its digits unchanged.
func TestMarshalConfigYAML_NumbersArePlainScalars(t *testing.T) {
	config := map[string]any{
		"big":      json.Number("9007199254740993"),
		"negative": json.Number("-42"),
		"half":     json.Number("1.5"),
		"exp":      json.Number("1e3"),
		"nested":   map[string]any{"id": json.Number("9007199254740993")},
		"list":     []any{json.Number("9007199254740993"), "text", true},
	}

	out, err := MarshalConfigYAML(config)
	require.NoError(t, err)

	text := string(out)
	assert.Contains(t, text, "big: 9007199254740993\n")
	assert.Contains(t, text, "negative: -42\n")
	assert.Contains(t, text, "half: 1.5\n")
	assert.Contains(t, text, "exp: 1e3\n")
	assert.Contains(t, text, "    id: 9007199254740993\n")
	assert.Contains(t, text, "    - 9007199254740993\n")
	assert.NotContains(t, text, `"`)

	var decoded struct {
		Big    uint64            `yaml:"big"`
		Half   float64           `yaml:"half"`
		Nested map[string]uint64 `yaml:"nested"`
		List   []any             `yaml:"list"`
	}
	require.NoError(t, yaml.Unmarshal(out, &decoded))
	assert.Equal(t, uint64(9007199254740993), decoded.Big)
	assert.Equal(t, 1.5, decoded.Half)
	assert.Equal(t, uint64(9007199254740993), decoded.Nested["id"])
	assert.Equal(t, []any{9007199254740993, "text", true}, decoded.List)
}

// A config that is not a decoded JSON tree (a typed struct) is encoded as
// plain yaml.Marshal would encode it.
func TestMarshalConfigYAML_TypedConfigUnchanged(t *testing.T) {
	type platform struct {
		Domain string `yaml:"domain"`
		Port   int    `yaml:"port"`
	}
	config := &platform{Domain: "example.com", Port: 8443}

	out, err := MarshalConfigYAML(config)
	require.NoError(t, err)

	want, err := yaml.Marshal(config)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(out))
}

func TestMarshalConfigYAML_InvalidNumber(t *testing.T) {
	for _, value := range []string{"", "abc", `"1"`, "1.2.3", "true"} {
		config := map[string]any{"nested": []any{json.Number(value)}}

		_, err := MarshalConfigYAML(config)

		var invalid ErrInvalidConfigNumber
		require.ErrorAs(t, err, &invalid, "value %q", value)
		assert.Equal(t, value, invalid.Value)
	}
}
