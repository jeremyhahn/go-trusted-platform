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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

type decodeYAMLTarget struct {
	Name    string        `mapstructure:"name"`
	Timeout time.Duration `mapstructure:"timeout"`
	CA      struct {
		Password secret.SecretValue `mapstructure:"password"`
	} `mapstructure:"ca"`
}

func TestDecodeYAML_SecretReferenceStaysUnresolved(t *testing.T) {
	ref := "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"
	doc := []byte("name: node1\ntimeout: 30s\nca:\n  password: \"" + ref + "\"\n")

	var got decodeYAMLTarget
	require.NoError(t, DecodeYAML(doc, &got))

	assert.Equal(t, "node1", got.Name)
	assert.Equal(t, 30*time.Second, got.Timeout)
	assert.Equal(t, ref, got.CA.Password.Raw)
}

func TestDecodeYAML_MalformedDocumentReturnsTypedError(t *testing.T) {
	var got decodeYAMLTarget
	err := DecodeYAML([]byte("name: [unterminated\n"), &got)

	var decodeErr ErrDecodeYAML
	require.True(t, errors.As(err, &decodeErr))
	assert.Error(t, decodeErr.Unwrap())
}

func TestDecodeYAML_TypeMismatchReturnsTypedError(t *testing.T) {
	var got decodeYAMLTarget
	err := DecodeYAML([]byte("timeout: not-a-duration\n"), &got)

	var decodeErr ErrDecodeYAML
	assert.True(t, errors.As(err, &decodeErr))
}
