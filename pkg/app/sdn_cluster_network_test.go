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
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubOVSBridge replaces the OVS bridge step with a counter, so the link
// bring-up runs without an OVS database socket.
func stubOVSBridge(t *testing.T) *int {
	t.Helper()
	calls := 0
	original := initOVSBridgeFn
	initOVSBridgeFn = func(*App, context.Context) error {
		calls++
		return nil
	}
	t.Cleanup(func() { initOVSBridgeFn = original })
	return &calls
}

// raftHostAssigned reports whether assigned (entries "<port> <addr/len>")
// carries the host of raftAddress.
func raftHostAssigned(t *testing.T, assigned []string, raftAddress string) bool {
	t.Helper()
	host, _, err := net.SplitHostPort(raftAddress)
	require.NoError(t, err)
	for _, a := range assigned {
		_, cidr, ok := strings.Cut(a, " ")
		if ok && strings.HasPrefix(cidr, host+"/") {
			return true
		}
	}
	return false
}

// TestShippedHATemplates_RaftAddressUpBeforeStores is the fresh-boot order
// of each shipped HA control plane (#1702): the clustered datastore's
// raft-address lives on a zone port platformd creates, so initClusterNetwork,
// which Init runs before initStores, must assign it.
func TestShippedHATemplates_RaftAddressUpBeforeStores(t *testing.T) {
	for id := 1; id <= 3; id++ {
		path := filepath.Join(haTemplateRoot, fmt.Sprintf("cp%d", id), "control-plane.yaml")
		t.Run(fmt.Sprintf("cp%d", id), func(t *testing.T) {
			a := loadTemplate(t, path)
			a.Logger = newDADTestApp(t).Logger
			require.NotNil(t, a.QuicBaaSConfig, path)
			require.True(t, a.QuicBaaSConfig.IsClustered(), path)

			bridge := stubOVSBridge(t)
			stubZonePorts(t, newFakeZonePorts())
			assigned := stubBridgeNetlink(t)
			stubProbe(t, func(context.Context, string, net.IP) error { return nil })

			require.NoError(t, a.initClusterNetwork(context.Background()), path)
			assert.Equal(t, 1, *bridge, "%s: OVS bridge created once", path)
			assert.True(t, a.sdnLinksUp, path)
			assert.True(t, raftHostAssigned(t, *assigned, a.QuicBaaSConfig.RaftAddress),
				"%s: raft-address %s not assigned before the datastore starts (assigned %v)",
				path, a.QuicBaaSConfig.RaftAddress, *assigned)
		})
	}
}

// TestInitClusterNetwork_StandaloneKeepsStorageFirst leaves a standalone
// datastore's order alone: nothing is brought up before initStores.
func TestInitClusterNetwork_StandaloneKeepsStorageFirst(t *testing.T) {
	for name, cfg := range map[string]*quicbaas.Config{
		"no quicbaas section": nil,
		"standalone":          {NodeID: 1, RaftAddress: "127.0.0.1:63000"},
	} {
		t.Run(name, func(t *testing.T) {
			a := zoneAddressApp(t)
			a.QuicBaaSConfig = cfg
			bridge := stubOVSBridge(t)
			stubZonePorts(t, newFakeZonePorts())
			assigned := stubBridgeNetlink(t)
			stubProbe(t, func(context.Context, string, net.IP) error { return nil })

			require.NoError(t, a.initClusterNetwork(context.Background()))
			assert.Zero(t, *bridge)
			assert.Empty(t, *assigned)
			assert.False(t, a.sdnLinksUp)
		})
	}
}

// TestInitSDN_SkipsLinksAlreadyUp: after initClusterNetwork brought the links
// up, initSDN neither recreates the bridge nor reassigns an address.
func TestInitSDN_SkipsLinksAlreadyUp(t *testing.T) {
	a := zoneAddressApp(t)
	a.NetworkConfig.Bonds[0].Mode = "balance-tcp"
	a.QuicBaaSConfig = &quicbaas.Config{
		NodeID:        1,
		RaftAddress:   "10.4.6.10:63000",
		JoinAddresses: []string{"1=10.4.6.10:63000", "2=10.4.6.11:63000", "3=10.4.6.12:63000"},
	}
	bridge := stubOVSBridge(t)
	stubZonePorts(t, newFakeZonePorts())
	assigned := stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	require.NoError(t, a.initClusterNetwork(context.Background()))
	require.True(t, raftHostAssigned(t, *assigned, a.QuicBaaSConfig.RaftAddress), "%v", *assigned)
	before := len(*assigned)

	require.NoError(t, a.initSDN(context.Background()))
	assert.Equal(t, 1, *bridge, "bridge created once")
	assert.Len(t, *assigned, before, "no address assigned twice")
}
