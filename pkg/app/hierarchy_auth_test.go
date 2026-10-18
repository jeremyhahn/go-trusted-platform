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
	"testing"

	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealHierarchyAuth_SealsThePIN(t *testing.T) {
	pin := mustPassword(t, []byte("so-pin-secret"))

	auth, err := sealHierarchyAuth(pin)
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.Equal(t, quicbaassecret.StrategyLiteral, auth.Strategy)
	assert.Empty(t, auth.Raw, "the PIN must live only in the enclave, never in Raw")

	var sealed []byte
	require.NoError(t, auth.WithBytes(func(b []byte) error {
		sealed = append([]byte(nil), b...)
		return nil
	}))
	assert.Equal(t, []byte("so-pin-secret"), sealed)
	assert.Equal(t, []byte("so-pin-secret"), pin.Bytes(), "sealing must not wipe the caller's PIN")
}

// hierarchyAuthValue opens a sealed hierarchy auth for comparison; a nil
// auth (an unowned hierarchy) reads as the empty string.
func hierarchyAuthValue(t *testing.T, auth *quicbaassecret.SecretValue) string {
	t.Helper()
	if auth == nil {
		return ""
	}
	var value string
	require.NoError(t, auth.WithBytes(func(b []byte) error {
		value = string(b)
		return nil
	}))
	return value
}

func TestSealHierarchyAuth_NoPINIsNoAuth(t *testing.T) {
	// A nil or empty SO PIN is the TCG factory state: the hierarchy keeps
	// empty auth, so the config field stays nil rather than holding an
	// empty secret.
	auth, err := sealHierarchyAuth(nil)
	require.NoError(t, err)
	assert.Nil(t, auth)

	auth, err = sealHierarchyAuth(mustPassword(t, nil))
	require.NoError(t, err)
	assert.Nil(t, auth)
}
