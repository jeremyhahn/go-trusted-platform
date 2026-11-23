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

package tenant

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iamOnlyManager builds a Manager the way the daemon's startup paths do
// (pkg/daemon/commands/serve_tenant.go): IAM clients only, DEK isolation
// off, no barrier client and no DEK client.
func iamOnlyManager(t *testing.T) *Manager {
	t.Helper()
	iamClient := newMockIAMClient()
	cfg := DefaultConfig()
	cfg.EnableDEKIsolation = false
	m, err := NewManager(&ManagerConfig{
		IAMTenantClient: iamClient,
		IAMRoleClient:   iamClient,
		Config:          cfg,
	})
	require.NoError(t, err)
	return m
}

func TestManager_BarrierConfigured(t *testing.T) {
	t.Run("an IAM-only manager has no barrier backend", func(t *testing.T) {
		assert.False(t, iamOnlyManager(t).BarrierConfigured())
	})

	t.Run("a manager with a barrier client has one", func(t *testing.T) {
		iamClient := newMockIAMClient()
		cfg := DefaultConfig()
		cfg.EnableDEKIsolation = false
		m, err := NewManager(&ManagerConfig{
			IAMTenantClient:     iamClient,
			IAMRoleClient:       iamClient,
			TenantBarrierClient: newTestBarrierClient(),
			Config:              cfg,
		})
		require.NoError(t, err)
		assert.True(t, m.BarrierConfigured())
	})

	t.Run("a nil manager has none", func(t *testing.T) {
		var m *Manager
		assert.False(t, m.BarrierConfigured())
	})
}

func TestManager_DEKConfigured(t *testing.T) {
	t.Run("an IAM-only manager has no DEK backend", func(t *testing.T) {
		assert.False(t, iamOnlyManager(t).DEKConfigured())
	})

	t.Run("a manager with a DEK client has one", func(t *testing.T) {
		iamClient := newMockIAMClient()
		m, err := NewManager(&ManagerConfig{
			IAMTenantClient: iamClient,
			IAMRoleClient:   iamClient,
			DEKClient:       newMockDEKClient(),
			Config:          DefaultConfig(),
		})
		require.NoError(t, err)
		assert.True(t, m.DEKConfigured())
	})

	t.Run("a nil manager has none", func(t *testing.T) {
		var m *Manager
		assert.False(t, m.DEKConfigured())
	})
}
