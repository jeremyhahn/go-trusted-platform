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

package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// ErrMergeUnmarshal indicates a YAML unmarshal failure during merge.
type ErrMergeUnmarshal struct {
	Cause error
}

// Error returns the error message.
func (e *ErrMergeUnmarshal) Error() string {
	return "config: failed to unmarshal yaml: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrMergeUnmarshal) Unwrap() error {
	return e.Cause
}

// ErrMergeMarshal indicates a YAML marshal failure during merge.
type ErrMergeMarshal struct {
	Cause error
}

// Error returns the error message.
func (e *ErrMergeMarshal) Error() string {
	return "config: failed to marshal yaml: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrMergeMarshal) Unwrap() error {
	return e.Cause
}

// ErrMergeReadFile indicates a failure to read a YAML file during merge.
type ErrMergeReadFile struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e *ErrMergeReadFile) Error() string {
	return "config: failed to read file " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrMergeReadFile) Unwrap() error {
	return e.Cause
}

// DeepMergeYAML merges override YAML bytes onto base YAML bytes.
// Override values replace base values. Maps merge recursively.
// Slices from override replace base slices entirely. Zero/nil values
// in override do NOT clear base values.
func DeepMergeYAML(base, overrides []byte) ([]byte, error) {
	var baseMap map[string]interface{}
	if err := yaml.Unmarshal(base, &baseMap); err != nil {
		return nil, &ErrMergeUnmarshal{Cause: err}
	}
	if baseMap == nil {
		baseMap = make(map[string]interface{})
	}

	var overrideMap map[string]interface{}
	if err := yaml.Unmarshal(overrides, &overrideMap); err != nil {
		return nil, &ErrMergeUnmarshal{Cause: err}
	}

	deepMergeMaps(baseMap, overrideMap)

	merged, err := yaml.Marshal(baseMap)
	if err != nil {
		return nil, &ErrMergeMarshal{Cause: err}
	}
	return merged, nil
}

// DeepMergeYAMLFiles reads two YAML files and returns merged bytes.
func DeepMergeYAMLFiles(basePath, overridesPath string) ([]byte, error) {
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		return nil, &ErrMergeReadFile{Path: basePath, Cause: err}
	}

	overrideData, err := os.ReadFile(overridesPath)
	if err != nil {
		return nil, &ErrMergeReadFile{Path: overridesPath, Cause: err}
	}

	return DeepMergeYAML(baseData, overrideData)
}

// deepMergeMaps recursively merges src into dst. For each key in src:
//   - If both dst and src have a map at the key, recurse.
//   - If src has a non-nil value, replace dst value.
//   - If src has nil or key is missing, keep dst value.
func deepMergeMaps(dst, src map[string]interface{}) {
	if src == nil {
		return
	}
	for key, srcVal := range src {
		if srcVal == nil {
			continue
		}

		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}

		srcMap, srcIsMap := toStringMap(srcVal)
		dstMap, dstIsMap := toStringMap(dstVal)

		if srcIsMap && dstIsMap {
			deepMergeMaps(dstMap, srcMap)
			dst[key] = dstMap
			continue
		}

		dst[key] = srcVal
	}
}

// toStringMap attempts to convert a value to map[string]interface{}.
// yaml.v2 unmarshals maps as map[interface{}]interface{}, so this
// function handles both forms.
func toStringMap(v interface{}) (map[string]interface{}, bool) {
	switch m := v.(type) {
	case map[string]interface{}:
		return m, true
	case map[interface{}]interface{}:
		result := make(map[string]interface{}, len(m))
		for k, val := range m {
			key, ok := k.(string)
			if !ok {
				return nil, false
			}
			// Recursively normalize nested maps.
			if nested, isMap := toStringMap(val); isMap {
				result[key] = nested
			} else {
				result[key] = val
			}
		}
		return result, true
	default:
		return nil, false
	}
}
