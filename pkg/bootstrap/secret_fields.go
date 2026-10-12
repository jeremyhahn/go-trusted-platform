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

package bootstrap

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// PlaintextSecretFields reports every key of the YAML document doc that the
// schema marks as a secret (a struct field tagged `secret:"true"`) and that
// holds a literal value rather than a secret reference (IsSecretURI). The
// schema is the struct the document is loaded into; keys are matched the way
// the loaders match them — yaml, mapstructure or json name, or the field
// name, case-insensitively — and inline or squashed structs are flattened.
// Keys the schema does not know are ignored.
//
// Paths are dotted YAML keys with [i] for sequence elements, in document
// order, for example "bmc.password" or "switches[0].password".
func PlaintextSecretFields(doc []byte, schema reflect.Type) ([]string, error) {
	if schema == nil || indirectType(schema).Kind() != reflect.Struct {
		return nil, ErrSecretSchemaNotStruct{Type: fmt.Sprint(schema)}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, ErrSecretDocumentParse{Err: err}
	}
	w := &secretWalker{active: make(map[*yaml.Node]bool)}
	w.walk(&root, indirectType(schema), "")
	return w.found, nil
}

// ErrSecretSchemaNotStruct is a PlaintextSecretFields schema that is not a
// struct (or a pointer to one), so it carries no field tags to read.
type ErrSecretSchemaNotStruct struct {
	Type string
}

func (e ErrSecretSchemaNotStruct) Error() string {
	return "secret field schema " + e.Type + " is not a struct"
}

// ErrSecretDocumentParse is a PlaintextSecretFields document that is not
// valid YAML.
type ErrSecretDocumentParse struct {
	Err error
}

func (e ErrSecretDocumentParse) Error() string {
	return "parsing the document for secret fields: " + e.Err.Error()
}

func (e ErrSecretDocumentParse) Unwrap() error {
	return e.Err
}

// secretSchemaField is one key a struct accepts: its type, and whether the
// schema marks it as a secret.
type secretSchemaField struct {
	typ    reflect.Type
	secret bool
}

// secretWalker walks a YAML node tree against a Go type. active holds the
// alias targets being walked, so a self-referencing anchor ends the walk
// instead of recursing forever.
type secretWalker struct {
	found  []string
	active map[*yaml.Node]bool
}

func (w *secretWalker) walk(node *yaml.Node, t reflect.Type, path string) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			w.walk(child, t, path)
		}
		return
	case yaml.AliasNode:
		w.followAlias(node, func(target *yaml.Node) { w.walk(target, t, path) })
		return
	}

	t = indirectType(t)
	switch t.Kind() {
	case reflect.Struct:
		w.walkStruct(node, t, path)
	case reflect.Slice, reflect.Array:
		if node.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range node.Content {
			w.walk(item, t.Elem(), path+"["+strconv.Itoa(i)+"]")
		}
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			w.walk(node.Content[i+1], t.Elem(), joinSecretPath(path, key))
		}
	}
}

func (w *secretWalker) walkStruct(node *yaml.Node, t reflect.Type, path string) {
	if node.Kind != yaml.MappingNode {
		return
	}
	fields := secretSchemaFields(t)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag == "!!merge" {
			w.walkMerge(value, t, path)
			continue
		}
		field, ok := fields[strings.ToLower(key.Value)]
		if !ok {
			continue
		}
		child := joinSecretPath(path, key.Value)
		if field.secret {
			if w.holdsPlaintext(value) {
				w.found = append(w.found, child)
			}
			continue
		}
		w.walk(value, field.typ, child)
	}
}

// walkMerge applies a YAML merge key (<<: *anchor, or a sequence of them)
// to the struct the mapping it sits in is loaded into.
func (w *secretWalker) walkMerge(value *yaml.Node, t reflect.Type, path string) {
	if value.Kind == yaml.SequenceNode {
		for _, item := range value.Content {
			w.walk(item, t, path)
		}
		return
	}
	w.walk(value, t, path)
}

// holdsPlaintext reports whether any scalar under a secret field is a
// literal rather than a secret reference. Empty and null values hold
// nothing.
func (w *secretWalker) holdsPlaintext(node *yaml.Node) bool {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!null" || node.Value == "" {
			return false
		}
		return !IsSecretURI(node.Value)
	case yaml.AliasNode:
		plaintext := false
		w.followAlias(node, func(target *yaml.Node) { plaintext = w.holdsPlaintext(target) })
		return plaintext
	}
	for _, child := range node.Content {
		if w.holdsPlaintext(child) {
			return true
		}
	}
	return false
}

func (w *secretWalker) followAlias(node *yaml.Node, visit func(target *yaml.Node)) {
	target := node.Alias
	if target == nil || w.active[target] {
		return
	}
	w.active[target] = true
	visit(target)
	delete(w.active, target)
}

// secretSchemaFields indexes the keys struct t accepts by lower-cased name.
func secretSchemaFields(t reflect.Type) map[string]secretSchemaField {
	fields := make(map[string]secretSchemaField)
	addSecretSchemaFields(fields, t)
	return fields
}

func addSecretSchemaFields(fields map[string]secretSchemaField, t reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		yamlName, yamlInline := tagNameAndOption(f.Tag.Get("yaml"), "inline")
		msName, msSquash := tagNameAndOption(f.Tag.Get("mapstructure"), "squash")
		jsonName, _ := tagNameAndOption(f.Tag.Get("json"), "")
		embedded := f.Anonymous && yamlName == "" && msName == ""
		if (yamlInline || msSquash || embedded) && indirectType(f.Type).Kind() == reflect.Struct {
			addSecretSchemaFields(fields, indirectType(f.Type))
			if !embedded {
				continue
			}
		}
		field := secretSchemaField{typ: f.Type, secret: f.Tag.Get(SecretStructTag) == "true"}
		for _, name := range []string{yamlName, msName, jsonName, f.Name} {
			if name == "" || name == "-" {
				continue
			}
			key := strings.ToLower(name)
			if existing, ok := fields[key]; ok && existing.secret {
				continue
			}
			fields[key] = field
		}
	}
}

// tagNameAndOption splits a struct tag value into its name and whether it
// carries option.
func tagNameAndOption(tag, option string) (string, bool) {
	name, opts, _ := strings.Cut(tag, ",")
	if option == "" {
		return name, false
	}
	for _, opt := range strings.Split(opts, ",") {
		if opt == option {
			return name, true
		}
	}
	return name, false
}

func indirectType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func joinSecretPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
