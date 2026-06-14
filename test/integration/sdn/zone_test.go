//go:build integration

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

package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetworkZone_CRUD exercises zone create, list, update, assign, and delete
// across every SDN adapter protocol.
func TestNetworkZone_CRUD(t *testing.T) {
	t.Parallel()

	adapters := []struct {
		name    string
		adapter SDNTestAdapter
	}{
		{"CLI", NewSDNCLIAdapter()},
		{"REST", NewSDNRESTAdapter()},
		{"gRPC", NewSDNGRPCAdapter()},
		{"QUIC", NewSDNQUICAdapter()},
		{"MCP", NewSDNMCPAdapter()},
		{"Unix", NewSDNUnixAdapter()},
	}

	for _, tc := range adapters {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			t.Cleanup(cancel)

			if err := tc.adapter.Setup(ctx); err != nil {
				skipIfNotImplemented(t, err)
				t.Fatalf("Setup: %v", err)
			}
			t.Cleanup(func() {
				if err := tc.adapter.Teardown(); err != nil {
					t.Logf("Teardown warning: %v", err)
				}
			})

			zoneName := fmt.Sprintf("test-zone-%s-%d", strings.ToLower(tc.name), time.Now().UnixNano())
			t.Cleanup(func() { cleanupZone(ctx, tc.adapter, zoneName) })

			// ─── Create ───────────────────────────────────────────────────────────

			t.Run("Create", func(t *testing.T) {
				entry, err := tc.adapter.CreateZone(ctx, ZoneCreateRequest{
					Name:    zoneName,
					Isolate: true,
				})
				skipIfNotImplemented(t, err)
				require.NoError(t, err, "CreateZone should succeed")
				require.NotNil(t, entry, "CreateZone must return an entry")
				assert.Equal(t, zoneName, entry.Name)
				// A brand-new zone never requires restart.
				assert.False(t, entry.RestartRequired, "new zone must not require restart")
			})

			// ─── List ─────────────────────────────────────────────────────────────

			t.Run("List", func(t *testing.T) {
				resp, err := tc.adapter.ListZones(ctx, "")
				skipIfNotImplemented(t, err)
				require.NoError(t, err, "ListZones should succeed")
				require.NotNil(t, resp)

				found := false
				for _, z := range resp.Zones {
					if z.Name == zoneName {
						found = true
						assert.True(t, z.Isolate, "created zone Isolate flag must be set")
						break
					}
				}
				assert.True(t, found, "newly created zone %q must appear in list", zoneName)
			})

			// ─── Update ───────────────────────────────────────────────────────────

			t.Run("Update", func(t *testing.T) {
				entry, err := tc.adapter.UpdateZone(ctx, zoneName, ZoneUpdateRequest{
					Isolate:          true,
					IsolatePerTenant: true,
				})
				skipIfNotImplemented(t, err)
				require.NoError(t, err, "UpdateZone should succeed")
				require.NotNil(t, entry)
				// IsolatePerTenant is a policy-relevant change → restartRequired.
				assert.True(t, entry.RestartRequired, "policy change must set restart_required")
			})

			// ─── Assign ───────────────────────────────────────────────────────────

			t.Run("Assign", func(t *testing.T) {
				restartRequired, err := tc.adapter.AssignZone(ctx, "corp-lan", zoneName)
				skipIfNotImplemented(t, err)
				require.NoError(t, err, "AssignZone should succeed")
				assert.True(t, restartRequired, "zone assignment must return restart_required=true")
			})

			// ─── Delete ───────────────────────────────────────────────────────────

			t.Run("Delete", func(t *testing.T) {
				_, err := tc.adapter.DeleteZone(ctx, zoneName)
				skipIfNotImplemented(t, err)
				require.NoError(t, err, "DeleteZone should succeed")

				// Verify zone no longer appears in list.
				resp, err := tc.adapter.ListZones(ctx, "")
				skipIfNotImplemented(t, err)
				require.NoError(t, err)
				for _, z := range resp.Zones {
					assert.NotEqual(t, zoneName, z.Name, "deleted zone must not appear in list")
				}
			})
		})
	}
}

// TestNetworkZone_ListFilter verifies lifecycle role filtering works correctly
// across all adapters that implement it.
func TestNetworkZone_ListFilter(t *testing.T) {
	t.Parallel()

	adapters := []struct {
		name    string
		adapter SDNTestAdapter
	}{
		{"CLI", NewSDNCLIAdapter()},
		{"REST", NewSDNRESTAdapter()},
		{"gRPC", NewSDNGRPCAdapter()},
		{"QUIC", NewSDNQUICAdapter()},
		{"MCP", NewSDNMCPAdapter()},
		{"Unix", NewSDNUnixAdapter()},
	}

	for _, tc := range adapters {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			t.Cleanup(cancel)

			if err := tc.adapter.Setup(ctx); err != nil {
				skipIfNotImplemented(t, err)
				t.Fatalf("Setup: %v", err)
			}
			t.Cleanup(func() { _ = tc.adapter.Teardown() })

			resp, err := tc.adapter.ListZones(ctx, "provisioning")
			skipIfNotImplemented(t, err)
			require.NoError(t, err, "ListZones(provisioning) must succeed")
			require.NotNil(t, resp)

			for _, z := range resp.Zones {
				assert.Equal(t, "provisioning", z.LifecycleRole,
					"all returned zones must have lifecycle_role=provisioning")
			}
		})
	}
}

// TestNetworkZone_CreateDuplicate verifies that creating a zone with a
// duplicate name returns an error on protocols that enforce uniqueness directly.
func TestNetworkZone_CreateDuplicate(t *testing.T) {
	t.Parallel()

	adapters := []struct {
		name    string
		adapter SDNTestAdapter
	}{
		{"REST", NewSDNRESTAdapter()},
		{"gRPC", NewSDNGRPCAdapter()},
		{"Unix", NewSDNUnixAdapter()},
	}

	for _, tc := range adapters {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			t.Cleanup(cancel)

			if err := tc.adapter.Setup(ctx); err != nil {
				skipIfNotImplemented(t, err)
				t.Fatalf("Setup: %v", err)
			}
			t.Cleanup(func() { _ = tc.adapter.Teardown() })

			zoneName := fmt.Sprintf("dup-zone-%s-%d", strings.ToLower(tc.name), time.Now().UnixNano())
			t.Cleanup(func() { cleanupZone(ctx, tc.adapter, zoneName) })

			// First create — must succeed.
			_, err := tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: zoneName})
			skipIfNotImplemented(t, err)
			require.NoError(t, err, "first create should succeed")

			// Duplicate create — must fail.
			_, err = tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: zoneName})
			assert.Error(t, err, "duplicate create must return an error")
		})
	}
}

// cleanupZone attempts to delete a zone, ignoring any errors (best-effort cleanup).
func cleanupZone(ctx context.Context, adapter SDNTestAdapter, name string) {
	_, _ = adapter.DeleteZone(ctx, name)
}
