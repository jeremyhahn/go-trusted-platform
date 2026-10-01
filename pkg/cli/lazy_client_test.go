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

package cli

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLazyClient_ConnectsOnceOnFirstUse(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")
	_, cleanup := startTestGRPCServer(t, socketPath)
	defer cleanup()
	contexts := 0
	flags := &CommonFlags{
		NoColor: true,
		GetContext: func() (*Context, error) {
			contexts++
			return &Context{Name: "lazy", Type: ContextTypeLocal, Local: &LocalContext{SocketPath: socketPath}}, nil
		},
	}

	lazy := NewLazyClient(flags)
	require.NoError(t, lazy.Close(), "closing an unopened client is a no-op")
	assert.Zero(t, contexts, "nothing connects before first use")

	first, err := lazy.Client()
	require.NoError(t, err)
	second, err := lazy.Client()
	require.NoError(t, err)
	assert.Same(t, first, second)
	assert.Equal(t, 1, contexts, "one connection for every use")
	require.NoError(t, lazy.Close())
}

func TestLazyClient_NoContext(t *testing.T) {
	_, err := NewLazyClient(&CommonFlags{}).Client()
	var noCtx ErrNoContextSet
	require.ErrorAs(t, err, &noCtx)
}
