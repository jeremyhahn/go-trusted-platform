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

package app

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// The shipped example deployments beside the templates, and the repository's
// example configs. configs/platform/old is not loaded by any test and is not
// covered here.
const (
	standaloneRoot = "../../configs/platform/standalone"
	clusterRoot    = "../../configs/platform/cluster"
	examplesRoot   = "../../examples"
)

const (
	// retiredPolicyKey is the boolean key-config field go-quicbaas v0.14
	// replaced with tpm-policy. The TPM sections (tpm.platform-srk, the
	// identity key configs) still read a boolean platform-policy of their own.
	retiredPolicyKey = "platform-policy"
	tpmPolicyKey     = "tpm-policy"
)

// TestShippedConfigs_KeyConfigsUseTPMPolicy pins the tpm-policy migration
// (#720) in every shipped template and example: no key config carries
// platform-policy, and every tpm-policy sits in a key config. A key config
// that still carries platform-policy has it silently ignored, which leaves
// TPMPolicy empty and turns off the password-sealing path of the key.
func TestShippedConfigs_KeyConfigsUseTPMPolicy(t *testing.T) {
	var paths []string
	for _, root := range []string{templateRoot, standaloneRoot, clusterRoot, examplesRoot} {
		paths = append(paths, platformConfigsUnder(t, root)...)
	}
	schema := reflect.TypeOf(App{})
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)

		for _, key := range keysNamed(t, path, raw, retiredPolicyKey) {
			if isKeyConfig(schema, key.parent) {
				t.Errorf("%s:%d: %s is ignored by the schema; a key config takes %s: %s",
					path, key.line, key, tpmPolicyKey, common.TPMPolicyPlatform)
			}
		}
		for _, key := range keysNamed(t, path, raw, tpmPolicyKey) {
			if !isKeyConfig(schema, key.parent) {
				t.Errorf("%s:%d: %s is not in a key config the schema reads", path, key.line, key)
			}
		}
	}
}

// TestIsKeyConfig_ResolvesSchemaPositions proves the schema walk the guard
// relies on: key configs reached through pointers, slices and squashed
// structs resolve as key configs; TPM sections and unknown paths do not.
func TestIsKeyConfig_ResolvesSchemaPositions(t *testing.T) {
	schema := reflect.TypeOf(App{})
	for _, parent := range [][]string{
		{"webservice", "key"},
		{"webservices", "[1]", "key"},
		{"certificate-authority", "identity", "[0]", "keys", "[2]"},
		{"acme", "client", "account", "key"},
	} {
		require.True(t, isKeyConfig(schema, parent), "%v", parent)
	}
	for _, parent := range [][]string{
		{"tpm", "platform-srk"},
		{"tpm", "ssrk"},
		{"webservice"},
		{"no-such-section", "key"},
		{"webservice", "key", "[0]"},
	} {
		require.False(t, isKeyConfig(schema, parent), "%v", parent)
	}
}

// TestKeysNamed_FindsNestedAndListedKeys proves the YAML walk reports a key
// inside mappings and sequences, with its parent path, and nothing else.
func TestKeysNamed_FindsNestedAndListedKeys(t *testing.T) {
	doc := []byte(`
tpm:
  platform-srk:
    platform-policy: true
certificate-authority:
  identity:
    - keys:
        - cn: root
          platform-policy: true
webservice:
  key:
    tpm-policy: platform
`)
	got := keysNamed(t, "inline", doc, retiredPolicyKey)
	require.Len(t, got, 2)
	require.Equal(t, "tpm.platform-srk.platform-policy", got[0].String())
	require.Equal(t, "certificate-authority.identity[0].keys[0].platform-policy", got[1].String())
	require.Equal(t, []string{"certificate-authority", "identity", "[0]", "keys", "[0]"}, got[1].parent)
}

// yamlKey is one occurrence of a key in a YAML document.
type yamlKey struct {
	parent []string // mapping keys and "[i]" sequence indexes down to the key
	name   string
	line   int
}

func (k yamlKey) String() string {
	var b strings.Builder
	for _, seg := range k.parent {
		if b.Len() > 0 && !strings.HasPrefix(seg, "[") {
			b.WriteByte('.')
		}
		b.WriteString(seg)
	}
	if b.Len() > 0 {
		b.WriteByte('.')
	}
	b.WriteString(k.name)
	return b.String()
}

// keysNamed returns every occurrence of the key name in a YAML document.
func keysNamed(t *testing.T, path string, raw []byte, name string) []yamlKey {
	t.Helper()
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(raw, &root), path)
	var out []yamlKey
	var walk func(n *yaml.Node, parent []string)
	walk = func(n *yaml.Node, parent []string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, parent)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				key := n.Content[i].Value
				if key == name {
					out = append(out, yamlKey{
						parent: append([]string(nil), parent...),
						name:   key,
						line:   n.Content[i].Line,
					})
				}
				walk(n.Content[i+1], append(parent, key))
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, append(parent, "["+strconv.Itoa(i)+"]"))
			}
		}
	}
	walk(&root, nil)
	return out
}

// isKeyConfig reports whether the mapping at path decodes, under the
// platform config schema, into a key config: a struct with a tpm-policy
// field (common.KeyConfig, or the go-xkms KeyConfig of the CA and ACME
// sections).
func isKeyConfig(schema reflect.Type, path []string) bool {
	typ := schema
	for _, seg := range path {
		typ = derefType(typ)
		switch typ.Kind() {
		case reflect.Struct:
			if strings.HasPrefix(seg, "[") {
				return false
			}
			field, ok := fieldByKey(typ, seg)
			if !ok {
				return false
			}
			typ = field
		case reflect.Slice, reflect.Array:
			if !strings.HasPrefix(seg, "[") {
				return false
			}
			typ = typ.Elem()
		case reflect.Map:
			typ = typ.Elem()
		default:
			return false
		}
	}
	typ = derefType(typ)
	if typ.Kind() != reflect.Struct {
		return false
	}
	_, ok := fieldByKey(typ, tpmPolicyKey)
	return ok
}

// fieldByKey finds the type of the struct field the config decoder fills
// from key, following mapstructure tags and squashed embedded structs.
func fieldByKey(typ reflect.Type, key string) (reflect.Type, bool) {
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("mapstructure")
		name, opts, _ := strings.Cut(tag, ",")
		if strings.Contains(opts, "squash") || (f.Anonymous && name == "") {
			if embedded := derefType(f.Type); embedded.Kind() == reflect.Struct {
				if found, ok := fieldByKey(embedded, key); ok {
					return found, true
				}
			}
			continue
		}
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if strings.EqualFold(name, key) {
			return f.Type, true
		}
	}
	return nil, false
}

func derefType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}
