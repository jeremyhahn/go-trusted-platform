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
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
)

func TestStringToSecretValueHookFunc(t *testing.T) {
	ref := "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"
	stringType := reflect.TypeOf("")

	got, err := StringToSecretValueHookFunc(stringType, secretValueType, ref)
	require.NoError(t, err)
	assert.Equal(t, secret.SecretValue{Raw: ref}, got, "a string becomes an unresolved SecretValue carrying the reference")

	got, err = StringToSecretValueHookFunc(stringType, reflect.PointerTo(secretValueType), ref)
	require.NoError(t, err)
	assert.Equal(t, &secret.SecretValue{Raw: ref}, got, "a *SecretValue field is decoded the same way")
}

// TestStringToSecretValueHookFunc_LeavesOtherFieldsAlone covers the pass-through
// paths: the hook must not touch any field that is not a SecretValue, nor a
// SecretValue whose source is not a string (a map, as a structured value).
func TestStringToSecretValueHookFunc_LeavesOtherFieldsAlone(t *testing.T) {
	got, err := StringToSecretValueHookFunc(reflect.TypeOf(""), reflect.TypeOf(""), "plain")
	require.NoError(t, err)
	assert.Equal(t, "plain", got)

	src := map[string]any{"raw": "x"}
	got, err = StringToSecretValueHookFunc(reflect.TypeOf(src), secretValueType, src)
	require.NoError(t, err)
	assert.Equal(t, src, got)
}

// TestDecodeHook_ShippedControlPlaneCAKeyPasswords is the regression for the
// control plane that crash-looped at start after the go-xkms v0.17 adoption:
//
//	'certificate-authority.identity[1].keys[0].password' expected a map or
//	struct, got "string"
//
// go-xkms v0.17 holds CA key passwords as a SecretValue, and viper decodes
// through mapstructure, which refused the templates' string passwords. Every
// shipped control-plane template is decoded here through DecodeHook exactly as
// platformd decodes it, and every CA key password must arrive as an
// unresolved reference for App.ProcessSecrets to resolve.
func TestDecodeHook_ShippedControlPlaneCAKeyPasswords(t *testing.T) {
	root := filepath.Join("..", "..", "configs", "platform", "templates")
	var templates []string
	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, "control-plane.yaml") {
			templates = append(templates, path)
		}
		return nil
	}))
	require.NotEmpty(t, templates, "no control-plane templates found; the test would pass vacuously")

	for _, path := range templates {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			v := viper.New()
			v.SetConfigType("yaml")
			require.NoError(t, v.ReadConfig(bytes.NewReader(data)))

			var ca trustedca.CAConfig
			require.NoError(t, v.UnmarshalKey("certificate-authority", &ca, DecodeHook()),
				"the shipped certificate-authority section must decode")

			passwords := 0
			for _, identity := range ca.Identity {
				for _, key := range identity.Keys {
					if key.Password.Raw == "" {
						continue
					}
					passwords++
					assert.True(t, strings.HasPrefix(key.Password.Raw, "kms://"),
						"a CA key password decodes to its unresolved reference, got %q", key.Password.Raw)
				}
			}
			assert.Positive(t, passwords, "the template's CA key passwords must survive the decode")
		})
	}
}
