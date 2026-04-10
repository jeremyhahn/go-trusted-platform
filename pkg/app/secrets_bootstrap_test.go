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
	"context"
	"reflect"
	"strings"
	"testing"

	casdk "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveAutoGenSecrets_PlatformPINs verifies that autogen:// URIs in
// PlatformConfig.SOPin and UserPin are resolved to actual values.
func TestResolveAutoGenSecrets_PlatformPINs(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin:   "autogen://6/numeric",
			UserPin: "autogen://6/numeric",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)

	// Both PINs should be resolved
	assert.Equal(t, 2, result.ResolvedCount())
	assert.Equal(t, 0, result.ErrorCount())

	// Resolved values should be 6-digit numeric strings
	assert.Len(t, app.PlatformConfig.SOPin, 6)
	assert.Len(t, app.PlatformConfig.UserPin, 6)

	// Should not contain the autogen:// prefix anymore
	assert.False(t, strings.HasPrefix(app.PlatformConfig.SOPin, "autogen://"))
	assert.False(t, strings.HasPrefix(app.PlatformConfig.UserPin, "autogen://"))

	// Should be all digits
	for _, c := range app.PlatformConfig.SOPin {
		assert.True(t, c >= '0' && c <= '9', "SO PIN should be numeric, got: %c", c)
	}
	for _, c := range app.PlatformConfig.UserPin {
		assert.True(t, c >= '0' && c <= '9', "User PIN should be numeric, got: %c", c)
	}
}

// TestResolveAutoGenSecrets_Base64Password verifies autogen:// with base64 encoding.
func TestResolveAutoGenSecrets_Base64Password(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin: "autogen://32/base64",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.ResolvedCount())

	// 32 bytes base64 encoded = 44 chars
	assert.Len(t, app.PlatformConfig.SOPin, 44)
	assert.False(t, strings.HasPrefix(app.PlatformConfig.SOPin, "autogen://"))
}

// TestResolveAutoGenSecrets_HexEncoding verifies autogen:// with hex encoding.
func TestResolveAutoGenSecrets_HexEncoding(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin: "autogen://16/hex",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, result.ResolvedCount())

	// 16 bytes hex encoded = 32 chars
	assert.Len(t, app.PlatformConfig.SOPin, 32)
}

// TestResolveAutoGenSecrets_NoAutoGenFields verifies that non-autogen fields are untouched.
func TestResolveAutoGenSecrets_NoAutoGenFields(t *testing.T) {
	app := &App{
		Logger:   logging.DefaultLogger(),
		Hostname: "myhost",
		Domain:   "example.com",
		PlatformConfig: &PlatformInitConfig{
			SOPin:   "123456",
			UserPin: "654321",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.ResolvedCount())

	// Original values should remain unchanged
	assert.Equal(t, "123456", app.PlatformConfig.SOPin)
	assert.Equal(t, "654321", app.PlatformConfig.UserPin)
	assert.Equal(t, "myhost", app.Hostname)
	assert.Equal(t, "example.com", app.Domain)
}

// TestResolveAutoGenSecrets_NilPlatformConfig verifies nil PlatformConfig does not panic.
func TestResolveAutoGenSecrets_NilPlatformConfig(t *testing.T) {
	app := &App{
		Logger:         logging.DefaultLogger(),
		PlatformConfig: nil,
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.ResolvedCount())
	assert.Equal(t, 0, result.ErrorCount())
}

// TestResolveAutoGenSecrets_CAKeyPasswords verifies autogen:// URIs in CA identity
// key password fields are resolved through the nested struct/slice walk.
func TestResolveAutoGenSecrets_CAKeyPasswords(t *testing.T) {
	cfg := casdk.CADefaultConfig()
	cfg.Identity = []casdk.CAIdentity{
		{
			Keys: []*xkmssdk.KeyConfig{
				{
					Password: "autogen://32/base64",
				},
				{
					Password: "literal-password",
				},
			},
		},
	}

	app := &App{
		Logger:   logging.DefaultLogger(),
		CAConfig: &cfg,
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)

	// Only the first key's password should be resolved
	assert.Equal(t, 1, result.ResolvedCount())

	// First key should have a resolved base64 value
	resolvedPw := app.CAConfig.Identity[0].Keys[0].Password
	assert.False(t, strings.HasPrefix(resolvedPw, "autogen://"))
	assert.Len(t, resolvedPw, 44) // 32 bytes base64

	// Second key should remain unchanged
	assert.Equal(t, "literal-password", app.CAConfig.Identity[0].Keys[1].Password)
}

// TestResolveAutoGenSecrets_InvalidURI verifies that invalid autogen:// URIs produce errors
// in the result but do not fail the overall resolution.
func TestResolveAutoGenSecrets_InvalidURI(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin:   "autogen://abc/base64",
			UserPin: "autogen://6/numeric",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)

	// One resolved, one error
	assert.Equal(t, 1, result.ResolvedCount())
	assert.Equal(t, 1, result.ErrorCount())

	// The invalid URI should remain unchanged
	assert.Equal(t, "autogen://abc/base64", app.PlatformConfig.SOPin)

	// The valid URI should be resolved
	assert.Len(t, app.PlatformConfig.UserPin, 6)
	assert.False(t, strings.HasPrefix(app.PlatformConfig.UserPin, "autogen://"))

	// Error should be ErrBootstrapSecretResolution
	var bsrErr ErrBootstrapSecretResolution
	assert.ErrorAs(t, result.Errors[0], &bsrErr)
	assert.Equal(t, "platform.so-pin", bsrErr.Path)
}

// TestResolveAutoGenSecrets_EmptyFields verifies empty string fields are skipped.
func TestResolveAutoGenSecrets_EmptyFields(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin:   "",
			UserPin: "",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.ResolvedCount())
	assert.Equal(t, 0, result.ErrorCount())
}

// TestResolveAutoGenSecrets_CaseInsensitive verifies that autogen:// matching is case-insensitive.
func TestResolveAutoGenSecrets_CaseInsensitive(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin:   "AUTOGEN://6/numeric",
			UserPin: "AutoGen://8/hex",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, result.ResolvedCount())

	assert.Len(t, app.PlatformConfig.SOPin, 6)
	assert.Len(t, app.PlatformConfig.UserPin, 16) // 8 bytes hex = 16 chars
}

// TestResolveAutoGenSecrets_UniqueValues verifies that each autogen:// URI resolves
// to a distinct random value.
func TestResolveAutoGenSecrets_UniqueValues(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin:   "autogen://32/hex",
			UserPin: "autogen://32/hex",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, result.ResolvedCount())

	// Extremely unlikely (2^-256) that two 32-byte random values collide
	assert.NotEqual(t, app.PlatformConfig.SOPin, app.PlatformConfig.UserPin)
}

// TestResolveAutoGenSecrets_UnsupportedEncoding verifies that unsupported encoding
// produces an error without crashing.
func TestResolveAutoGenSecrets_UnsupportedEncoding(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
		PlatformConfig: &PlatformInitConfig{
			SOPin: "autogen://32/unsupported",
		},
	}

	result, err := app.resolveAutoGenSecrets(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, result.ResolvedCount())
	assert.Equal(t, 1, result.ErrorCount())

	// Value should remain unchanged
	assert.Equal(t, "autogen://32/unsupported", app.PlatformConfig.SOPin)
}

// TestBootstrapSecretsResult_Methods verifies the result helper methods.
func TestBootstrapSecretsResult_Methods(t *testing.T) {
	t.Run("empty_result", func(t *testing.T) {
		result := &BootstrapSecretsResult{
			Resolved: make([]string, 0),
			Errors:   make([]error, 0),
		}
		assert.Equal(t, 0, result.ResolvedCount())
		assert.Equal(t, 0, result.ErrorCount())
	})

	t.Run("populated_result", func(t *testing.T) {
		result := &BootstrapSecretsResult{
			Resolved: []string{"a", "b", "c"},
			Errors:   []error{ErrBootstrapSecretResolution{Path: "x"}},
		}
		assert.Equal(t, 3, result.ResolvedCount())
		assert.Equal(t, 1, result.ErrorCount())
	})
}

// TestErrBootstrapSecretResolution_Error verifies error message formatting.
func TestErrBootstrapSecretResolution_Error(t *testing.T) {
	t.Run("with_cause", func(t *testing.T) {
		cause := ErrInvalidAutoGenURI{URI: "autogen://bad", Reason: "invalid"}
		err := ErrBootstrapSecretResolution{Path: "platform.so-pin", URI: "autogen://bad", Cause: cause}
		assert.Contains(t, err.Error(), "platform.so-pin")
		assert.Contains(t, err.Error(), "invalid")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without_cause", func(t *testing.T) {
		err := ErrBootstrapSecretResolution{Path: "platform.so-pin"}
		assert.Contains(t, err.Error(), "platform.so-pin")
		assert.Nil(t, err.Unwrap())
	})
}

// TestBootstrapFieldPath verifies field path construction from struct tags.
func TestBootstrapFieldPath(t *testing.T) {
	t.Run("yaml_tag", func(t *testing.T) {
		field := makeStructField("yaml", "so-pin,omitempty")
		assert.Equal(t, "so-pin", bootstrapFieldPath("", field))
		assert.Equal(t, "platform.so-pin", bootstrapFieldPath("platform", field))
	})

	t.Run("json_tag_fallback", func(t *testing.T) {
		field := makeStructField("json", "my_field")
		assert.Equal(t, "my_field", bootstrapFieldPath("", field))
	})

	t.Run("skip_dash", func(t *testing.T) {
		field := makeStructField("yaml", "-")
		assert.Equal(t, "", bootstrapFieldPath("", field))
	})

	t.Run("empty_tags_uses_field_name", func(t *testing.T) {
		field := makeStructFieldNoTag("MyField")
		assert.Equal(t, "myfield", bootstrapFieldPath("", field))
	})
}

// makeStructField creates a reflect.StructField with the given tag for testing.
func makeStructField(tagKey, tagValue string) reflect.StructField {
	return reflect.StructField{
		Name: "TestField",
		Type: reflect.TypeOf(""),
		Tag:  reflect.StructTag(tagKey + `:"` + tagValue + `"`),
	}
}

// makeStructFieldNoTag creates a reflect.StructField with no tags for testing.
func makeStructFieldNoTag(name string) reflect.StructField {
	return reflect.StructField{
		Name: name,
		Type: reflect.TypeOf(""),
	}
}
