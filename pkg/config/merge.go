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

// identityKeys lists the YAML map keys used to identify elements
// within arrays of objects. When both the base and override arrays
// contain objects sharing the same identity key value, the override
// object replaces (and deep-merges into) the base object instead of
// being appended.
var identityKeys = []string{"name", "id", "role"}

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
// Slices of objects are merged by matching on identity keys (name, id,
// role); plain scalar slices from override replace base slices entirely.
// Zero/nil values in override do NOT clear base values.
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
//   - If both dst and src have slices, merge using mergeSlices.
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

		srcSlice, srcIsSlice := srcVal.([]interface{})
		dstSlice, dstIsSlice := dstVal.([]interface{})

		if srcIsSlice && dstIsSlice {
			dst[key] = mergeSlices(dstSlice, srcSlice)
			continue
		}

		dst[key] = srcVal
	}
}

// mergeSlices merges two slices of interface{} values. If both slices
// contain map objects that share a common identity key (name, id, role),
// elements are matched by that key and deep-merged. Override elements
// with no match in the base are appended. Base elements with no match
// in the override are preserved. If no common identity key is found
// (e.g. scalar slices), the override slice replaces the base entirely.
func mergeSlices(base, override []interface{}) []interface{} {
	if len(base) == 0 {
		return override
	}
	if len(override) == 0 {
		return base
	}

	// Determine if both slices contain maps with a shared identity key.
	idKey := detectIdentityKey(base, override)
	if idKey == "" {
		// No identity key found — plain replacement semantics.
		return override
	}

	// Build an index of base elements by identity key value.
	type indexEntry struct {
		pos int
		m   map[string]interface{}
	}
	baseIndex := make(map[interface{}]indexEntry, len(base))
	for i, elem := range base {
		if m, ok := toStringMap(elem); ok {
			if keyVal, exists := m[idKey]; exists {
				baseIndex[keyVal] = indexEntry{pos: i, m: m}
			}
		}
	}

	// Track which base positions were matched so we preserve order.
	matched := make(map[int]bool, len(override))

	// Process override elements: merge into matching base or collect as new.
	var appended []interface{}
	for _, elem := range override {
		overrideMap, ok := toStringMap(elem)
		if !ok {
			appended = append(appended, elem)
			continue
		}
		keyVal, exists := overrideMap[idKey]
		if !exists {
			appended = append(appended, elem)
			continue
		}
		entry, found := baseIndex[keyVal]
		if !found {
			appended = append(appended, elem)
			continue
		}
		// Deep merge override into the base element.
		deepMergeMaps(entry.m, overrideMap)
		base[entry.pos] = entry.m
		matched[entry.pos] = true
	}

	// Result: all base elements (some now merged) + any new override elements.
	result := make([]interface{}, 0, len(base)+len(appended))
	result = append(result, base...)
	result = append(result, appended...)
	return result
}

// detectIdentityKey checks whether both slices contain map objects that
// share a common identity key field. Returns the first matching key from
// identityKeys, or "" if none is found.
func detectIdentityKey(a, b []interface{}) string {
	for _, key := range identityKeys {
		if sliceHasKey(a, key) && sliceHasKey(b, key) {
			return key
		}
	}
	return ""
}

// sliceHasKey returns true if at least one element of the slice is a map
// containing the given key.
func sliceHasKey(s []interface{}, key string) bool {
	for _, elem := range s {
		if m, ok := toStringMap(elem); ok {
			if _, exists := m[key]; exists {
				return true
			}
		}
	}
	return false
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
