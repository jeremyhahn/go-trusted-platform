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

package iso

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyWithContext_Coverage(t *testing.T) {
	t.Run("copy all data", func(t *testing.T) {
		src := strings.NewReader("hello, world!")
		var dst bytes.Buffer

		ctx := context.Background()
		written, err := copyWithContext(ctx, &dst, src)
		require.NoError(t, err)
		assert.Equal(t, int64(13), written)
		assert.Equal(t, "hello, world!", dst.String())
	})

	t.Run("copy empty data", func(t *testing.T) {
		src := strings.NewReader("")
		var dst bytes.Buffer

		ctx := context.Background()
		written, err := copyWithContext(ctx, &dst, src)
		require.NoError(t, err)
		assert.Equal(t, int64(0), written)
	})

	t.Run("copy with canceled context", func(t *testing.T) {
		// Create a large reader that will be interrupted
		largeData := make([]byte, 1024*1024) // 1MB
		src := bytes.NewReader(largeData)
		var dst bytes.Buffer

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := copyWithContext(ctx, &dst, src)
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}
