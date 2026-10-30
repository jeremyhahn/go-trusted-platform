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
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrInvalidConfigNumber is returned when a json.Number in a profile config
// does not hold a JSON number, so it has no YAML int or float to stand for.
type ErrInvalidConfigNumber struct {
	Value string
}

func (e ErrInvalidConfigNumber) Error() string {
	return "profile config holds an invalid number: " + e.Value
}

// MarshalConfigYAML encodes a profile's type-erased platform config
// (DeviceProfile.Config or PlatformdConfig.Inline) as YAML.
//
// A config read back from the device-profile store holds its numbers as
// json.Number, because the DAO decodes with UseNumber so integers above 2^53
// stay exact (#125). yaml.v3 would emit a json.Number as a quoted string; here
// each one is emitted as the plain YAML int or float it stands for, with its
// digits unchanged.
func MarshalConfigYAML(config any) ([]byte, error) {
	value, err := yamlNumbers(config)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(value)
}

// yamlNumbers returns a copy of the decoded JSON tree v with every json.Number
// replaced by a YAML scalar node. Other values are returned unchanged.
func yamlNumbers(v any) (any, error) {
	switch value := v.(type) {
	case json.Number:
		return numberNode(value)
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			converted, err := yamlNumbers(item)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			converted, err := yamlNumbers(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	default:
		return v, nil
	}
}

// numberNode returns the YAML scalar for a JSON number: !!int when it has no
// fraction or exponent, !!float otherwise. Every JSON number is also a valid
// YAML 1.2 core-schema int or float, so its text is used as it is.
func numberNode(n json.Number) (*yaml.Node, error) {
	text := string(n)
	if !isJSONNumber(text) {
		return nil, ErrInvalidConfigNumber{Value: text}
	}
	tag := "!!int"
	if strings.ContainsAny(text, ".eE") {
		tag = "!!float"
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: text}, nil
}

// isJSONNumber reports whether text is a JSON number (RFC 8259 §6): a valid
// JSON value that starts with a minus sign or a digit.
func isJSONNumber(text string) bool {
	if text == "" || !json.Valid([]byte(text)) {
		return false
	}
	first := text[0]
	return first == '-' || (first >= '0' && first <= '9')
}
