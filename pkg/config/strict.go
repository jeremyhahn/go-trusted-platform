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
	"encoding"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// UnknownKey is one configuration key no field of the section's Go type
// accepts.
type UnknownKey struct {
	// Path is the full key path, e.g. "network.bridges[0].members".
	Path string
	// Line is the YAML line of the key; zero when the configuration was
	// read through viper, which keeps no positions.
	Line int
}

// ErrUnknownConfigKeys is returned when a strictly checked configuration
// section carries keys its Go type does not have — a misspelt key, or one a
// pre-release schema change removed. Such a key is a configuration error,
// never something to ignore: an ignored key is a setting the operator
// believes is in force and is not.
type ErrUnknownConfigKeys struct {
	// Section is the top-level section, e.g. "network".
	Section string
	// Keys lists every unknown key, sorted by path.
	Keys []UnknownKey
}

// Error implements the error interface.
func (e *ErrUnknownConfigKeys) Error() string {
	parts := make([]string, len(e.Keys))
	for i, k := range e.Keys {
		if k.Line > 0 {
			parts[i] = fmt.Sprintf("%s (line %d)", k.Path, k.Line)
		} else {
			parts[i] = k.Path
		}
	}
	return fmt.Sprintf("config: section %q has unknown keys: %s", e.Section, strings.Join(parts, ", "))
}

// CheckViperSection decodes section of v into a fresh value of target's
// type, with the platform DecodeHook, and returns *ErrUnknownConfigKeys
// naming every key the type does not accept. A missing section is not an
// error. target must be a pointer to the section's Go type; it is filled as
// a side effect.
func CheckViperSection(v *viper.Viper, section string, target any) error {
	if !v.IsSet(section) {
		return nil
	}
	var md mapstructure.Metadata
	if err := v.UnmarshalKey(section, target, DecodeHook(), func(c *mapstructure.DecoderConfig) {
		c.Metadata = &md
	}); err != nil {
		return &WrappedError{Msg: "config: decode section " + section, Err: err}
	}
	if len(md.Unused) == 0 {
		return nil
	}
	keys := make([]UnknownKey, len(md.Unused))
	for i, u := range md.Unused {
		keys[i] = UnknownKey{Path: section + "." + u}
	}
	return newUnknownKeys(section, keys)
}

// CheckYAMLSection walks section of the YAML document doc against target's
// Go type (yaml tags) and returns *ErrUnknownConfigKeys naming every key
// the type does not accept, with its line. A missing section is not an
// error. target is only inspected for its type.
func CheckYAMLSection(doc []byte, section string, target any) error {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return &WrappedError{Msg: "config: parse yaml", Err: err}
	}
	if len(root.Content) == 0 {
		return nil
	}
	top := resolveAlias(root.Content[0])
	if top.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != section {
			continue
		}
		var keys []UnknownKey
		walkYAML(top.Content[i+1], reflect.TypeOf(target), section, &keys)
		if len(keys) == 0 {
			return nil
		}
		return newUnknownKeys(section, keys)
	}
	return nil
}

// newUnknownKeys sorts keys and builds the typed error.
func newUnknownKeys(section string, keys []UnknownKey) error {
	sort.Slice(keys, func(i, j int) bool { return keys[i].Path < keys[j].Path })
	return &ErrUnknownConfigKeys{Section: section, Keys: keys}
}

var (
	yamlUnmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
)

// decodesItself reports whether t (or *t) owns its YAML decoding, so its
// keys are not the walker's to judge.
func decodesItself(t reflect.Type) bool {
	pt := reflect.PointerTo(t)
	return t.Implements(yamlUnmarshalerType) || pt.Implements(yamlUnmarshalerType) ||
		t.Implements(textUnmarshalerType) || pt.Implements(textUnmarshalerType)
}

// resolveAlias follows YAML aliases to the node they name.
func resolveAlias(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

// walkYAML records every mapping key under n that type t does not accept.
// A node whose shape does not match t is left to the real decoder, which
// reports type errors itself.
func walkYAML(n *yaml.Node, t reflect.Type, path string, keys *[]UnknownKey) {
	n = resolveAlias(n)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if decodesItself(t) {
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return
		}
		fields, openMap := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "<<" {
				walkYAML(v, t, path, keys)
				continue
			}
			ft, ok := fields[k.Value]
			if !ok {
				if !openMap {
					*keys = append(*keys, UnknownKey{Path: path + "." + k.Value, Line: k.Line})
				}
				continue
			}
			walkYAML(v, ft, path+"."+k.Value, keys)
		}
	case reflect.Slice, reflect.Array:
		if n.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range n.Content {
			walkYAML(item, t.Elem(), path+"["+strconv.Itoa(i)+"]", keys)
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			walkYAML(n.Content[i+1], t.Elem(), path+"."+n.Content[i].Value, keys)
		}
	}
}

// yamlFields maps the YAML key of every field of struct t to its type,
// following yaml.v3's rules: the tag name, else the lowercased field name;
// "-" and unexported fields excluded; ",inline" structs merged. openMap is
// true when t has an inline map, which accepts any key.
func yamlFields(t reflect.Type) (map[string]reflect.Type, bool) {
	fields := make(map[string]reflect.Type, t.NumField())
	openMap := false
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("yaml")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if strings.Contains(opts, "inline") {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			switch ft.Kind() {
			case reflect.Map:
				openMap = true
			case reflect.Struct:
				inner, innerOpen := yamlFields(ft)
				for k, v := range inner {
					fields[k] = v
				}
				openMap = openMap || innerOpen
			}
			continue
		}
		if f.PkgPath != "" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		fields[name] = f.Type
	}
	return fields, openMap
}
