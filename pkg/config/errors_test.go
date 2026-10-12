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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestCause = errors.New("spiffe-trust-domain is required")

// TestErrInvalidConfigKey_NamesFileAndKey proves the message carries both
// the file and the key, and that the cause stays matchable.
func TestErrInvalidConfigKey_NamesFileAndKey(t *testing.T) {
	err := error(&ErrInvalidConfigKey{
		File: "/etc/platform/config.yaml",
		Key:  "quicbaas.spiffe-trust-domain",
		Err:  errTestCause,
	})

	assert.Equal(t,
		`config file "/etc/platform/config.yaml": key quicbaas.spiffe-trust-domain: spiffe-trust-domain is required`,
		err.Error())
	assert.ErrorIs(t, err, errTestCause)

	var keyErr *ErrInvalidConfigKey
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, "quicbaas.spiffe-trust-domain", keyErr.Key)
}

// TestErrInvalidConfigKey_NilCause covers a zero cause: Error must not
// panic and must still name the file and key.
func TestErrInvalidConfigKey_NilCause(t *testing.T) {
	err := &ErrInvalidConfigKey{File: "c.yaml", Key: "quicbaas.transport"}

	assert.Equal(t, `config file "c.yaml": key quicbaas.transport: invalid`, err.Error())
	assert.NoError(t, err.Unwrap())
}
