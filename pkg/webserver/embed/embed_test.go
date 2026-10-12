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

package embed

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsEmbedded(t *testing.T) {
	t.Run("IsEmbedded returns consistent value", func(t *testing.T) {
		first := IsEmbedded()
		second := IsEmbedded()
		assert.Equal(t, first, second, "IsEmbedded should return consistent value")
	})
}

func TestWebFS_UsagePattern(t *testing.T) {
	t.Run("IsEmbedded true means WebFS is usable", func(t *testing.T) {
		if IsEmbedded() {
			assert.NotNil(t, WebFS)
		}
	})
}

func TestWebFS_StubBehavior(t *testing.T) {
	t.Run("WebFS nil check is safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			_ = WebFS == nil
		})
	})

	t.Run("IsEmbedded implies WebFS is set", func(t *testing.T) {
		if IsEmbedded() {
			assert.NotNil(t, WebFS)
		}
	})
}

func BenchmarkIsEmbedded(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = IsEmbedded()
	}
}

func BenchmarkWebFSNilCheck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = WebFS == nil
	}
}
