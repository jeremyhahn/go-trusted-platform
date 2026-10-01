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

// zoneAdapters is every transport with the owner-zone offset its CRUD test
// uses: the subtests run in parallel against one daemon, and two zones may
// never share an offset.
func zoneAdapters() []struct {
	name    string
	offset  uint8
	adapter SDNTestAdapter
} {
	return []struct {
		name    string
		offset  uint8
		adapter SDNTestAdapter
	}{
		{"CLI", 10, NewSDNCLIAdapter()},
		{"REST", 11, NewSDNRESTAdapter()},
		{"gRPC", 12, NewSDNGRPCAdapter()},
		{"QUIC", 13, NewSDNQUICAdapter()},
		{"MCP", 14, NewSDNMCPAdapter()},
		{"Unix", 15, NewSDNUnixAdapter()},
	}
}

// setupZoneAdapter sets an adapter up and registers its teardown.
func setupZoneAdapter(t *testing.T, a SDNTestAdapter) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	require.NoError(t, a.Setup(ctx), "Setup")
	t.Cleanup(func() {
		if err := a.Teardown(); err != nil {
			t.Logf("Teardown warning: %v", err)
		}
	})
	return ctx
}

// TestNetworkZone_CRUD creates an owner-defined zone carrying the whole
// zone schema (offset, port class, an audited path into control-plane),
// lists, updates and deletes it, on every transport.
func TestNetworkZone_CRUD(t *testing.T) {
	t.Parallel()

	for _, tc := range zoneAdapters() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := setupZoneAdapter(t, tc.adapter)

			zoneName := fmt.Sprintf("it-%s-%d", strings.ToLower(tc.name), time.Now().UnixNano()%1_000_000)
			t.Cleanup(func() { cleanupZone(ctx, tc.adapter, zoneName) })

			spec := ZoneSpec{
				Offset:               tc.offset,
				PortClasses:          []string{"hypervisor"},
				Isolate:              true,
				Services:             []string{"ssh"},
				AllowTo:              []ZonePathEntry{{Zone: "control-plane", Services: []string{"dns"}}},
				PrivilegedReason:     "integration test resolver",
				PrivilegedApprovedBy: "integration-test",
			}

			entry, err := tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: zoneName, ZoneSpec: spec})
			require.NoError(t, err, "CreateZone")
			require.NotNil(t, entry)
			assert.Equal(t, zoneName, entry.Name)
			assert.Equal(t, tc.offset, entry.Offset)
			assert.Equal(t, []string{"hypervisor"}, entry.PortClasses)
			assert.Equal(t, "integration-test", entry.PrivilegedApprovedBy)
			require.Len(t, entry.AllowTo, 1)
			assert.Equal(t, "control-plane", entry.AllowTo[0].Zone)
			assert.True(t, entry.RestartRequired, "the plan is derived at startup")

			resp, err := tc.adapter.ListZones(ctx, "")
			require.NoError(t, err, "ListZones")
			var listed *ZoneEntry
			for i := range resp.Zones {
				if resp.Zones[i].Name == zoneName {
					listed = &resp.Zones[i]
				}
			}
			require.NotNil(t, listed, "zone %q must be listed", zoneName)
			assert.True(t, listed.Isolate)
			assert.Equal(t, []string{"ssh"}, listed.Services)

			spec.Services = []string{"ssh", "https"}
			entry, err = tc.adapter.UpdateZone(ctx, zoneName, ZoneUpdateRequest{ZoneSpec: spec})
			require.NoError(t, err, "UpdateZone")
			assert.Equal(t, []string{"ssh", "https"}, entry.Services)
			assert.True(t, entry.RestartRequired)

			_, err = tc.adapter.DeleteZone(ctx, zoneName)
			require.NoError(t, err, "DeleteZone")
			resp, err = tc.adapter.ListZones(ctx, "")
			require.NoError(t, err)
			for _, z := range resp.Zones {
				assert.NotEqual(t, zoneName, z.Name, "deleted zone must not be listed")
			}
		})
	}
}

// TestNetworkZone_Refusals checks every transport refuses what the zone
// model forbids: an unaudited path into control-plane, a renumbered
// built-in, an overlay kind as a zone name, and removing a required
// built-in.
func TestNetworkZone_Refusals(t *testing.T) {
	t.Parallel()

	for _, tc := range zoneAdapters() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := setupZoneAdapter(t, tc.adapter)

			name := fmt.Sprintf("bad-%s-%d", strings.ToLower(tc.name), time.Now().UnixNano()%1_000_000)
			t.Cleanup(func() { cleanupZone(ctx, tc.adapter, name) })

			_, err := tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: name, ZoneSpec: ZoneSpec{
				Offset: tc.offset + 50, PortClasses: []string{"gateway"},
				AllowTo: []ZonePathEntry{{Zone: "control-plane"}},
			}})
			assert.Error(t, err, "a path into control-plane needs privileged_access")

			_, err = tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: "public", ZoneSpec: ZoneSpec{
				Offset: tc.offset + 50, PortClasses: []string{"gateway"},
			}})
			assert.Error(t, err, "overlay kinds are not zones")

			_, err = tc.adapter.UpdateZone(ctx, "storage", ZoneUpdateRequest{ZoneSpec: ZoneSpec{Offset: 30, Isolate: true}})
			assert.Error(t, err, "a built-in zone cannot be renumbered")

			_, err = tc.adapter.DeleteZone(ctx, "fabric")
			assert.Error(t, err, "fabric is required")
		})
	}
}

// TestNetworkZone_ListFilter verifies the lifecycle role filter on every
// transport.
func TestNetworkZone_ListFilter(t *testing.T) {
	t.Parallel()

	for _, tc := range zoneAdapters() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := setupZoneAdapter(t, tc.adapter)

			resp, err := tc.adapter.ListZones(ctx, "provisioning")
			require.NoError(t, err, "ListZones(provisioning)")
			require.Len(t, resp.Zones, 1)
			assert.Equal(t, "provisioning", resp.Zones[0].Name)
			assert.Equal(t, uint8(5), resp.Zones[0].Offset)
			assert.Equal(t, "provisioning", resp.Zones[0].LifecycleRole)
		})
	}
}

// TestNetworkZone_CreateDuplicate verifies a second create with the same
// name is refused.
func TestNetworkZone_CreateDuplicate(t *testing.T) {
	t.Parallel()

	for _, tc := range zoneAdapters() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := setupZoneAdapter(t, tc.adapter)

			name := fmt.Sprintf("dup-%s-%d", strings.ToLower(tc.name), time.Now().UnixNano()%1_000_000)
			t.Cleanup(func() { cleanupZone(ctx, tc.adapter, name) })
			spec := ZoneSpec{Offset: tc.offset + 20, PortClasses: []string{"gateway"}}

			_, err := tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: name, ZoneSpec: spec})
			require.NoError(t, err, "first create")
			_, err = tc.adapter.CreateZone(ctx, ZoneCreateRequest{Name: name, ZoneSpec: spec})
			assert.Error(t, err, "duplicate create")
		})
	}
}

// cleanupZone deletes a zone, ignoring errors (best-effort cleanup).
func cleanupZone(ctx context.Context, adapter SDNTestAdapter, name string) {
	_, _ = adapter.DeleteZone(ctx, name)
}
