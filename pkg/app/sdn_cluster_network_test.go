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
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubOVSBridge replaces the OVS bridge step with a counter, so the link
// bring-up runs without an OVS database socket.
func stubOVSBridge(t *testing.T) *int {
	t.Helper()
	calls, _ := stubOVSBridgeClient(t)
	return calls
}

// stubOVSBridgeClient replaces the OVS bridge bring-up with one that
// connects app.ovsClient to a fake client, so bond creation runs through
// AddBond the way it does against a live OVSDB.
func stubOVSBridgeClient(t *testing.T) (*int, *fakeOVSClient) {
	t.Helper()
	calls := 0
	client := &fakeOVSClient{}
	original := initOVSBridgeFn
	initOVSBridgeFn = func(app *App, _ context.Context) error {
		calls++
		app.ovsClient = client
		return nil
	}
	t.Cleanup(func() { initOVSBridgeFn = original })
	return &calls, client
}

// fakeOVSClient is the slice of ovs.ClientInterface bond creation uses.
// Any other method panics on the nil embedded interface, so a new OVS
// call on the cluster-network path shows up in these tests.
type fakeOVSClient struct {
	ovs.ClientInterface
	bonds      []string
	addBondErr error
}

func (f *fakeOVSClient) GetPort(_ context.Context, name string) (*ovs.Port, error) {
	return nil, fmt.Errorf("port %s not found", name)
}

func (f *fakeOVSClient) AddBond(_ context.Context, _, bondName string, _ []string, _, _ string) (*ovs.Port, error) {
	f.bonds = append(f.bonds, bondName)
	if f.addBondErr != nil {
		return nil, f.addBondErr
	}
	return &ovs.Port{Name: bondName}, nil
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

// TestInitClusterNetwork_FailedZoneAddressRetried: a zone address that fails
// to assign leaves the links marked down, so initSDN sets them up again and
// the raft-address lands on the retry.
func TestInitClusterNetwork_FailedZoneAddressRetried(t *testing.T) {
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

	starts := 0
	original := initStoresFn
	initStoresFn = func(app *App) error {
		starts++
		assert.True(t, raftHostAssigned(t, *assigned, app.QuicBaaSConfig.RaftAddress),
			"datastore started before raft-address %s was assigned (assigned %v)",
			app.QuicBaaSConfig.RaftAddress, *assigned)
		return nil
	}
	t.Cleanup(func() { initStoresFn = original })

	ok := assignBridgeAddrFn
	assignBridgeAddrFn = func(context.Context, string, string) error {
		return errors.New("netlink: address assignment refused")
	}
	require.Error(t, a.initNetworkAndStores(context.Background()))
	assert.False(t, a.sdnLinksUp, "links marked up after a failed zone address")
	assert.Empty(t, *assigned)
	assert.Zero(t, starts, "datastore started after a failed zone address")

	// The fault clears: the next preparation retries the link setup and
	// the datastore starts with its raft-address up.
	assignBridgeAddrFn = ok
	require.NoError(t, a.initNetworkAndStores(context.Background()))
	assert.Equal(t, 2, *bridge, "the second preparation retried the link setup")
	assert.True(t, a.sdnLinksUp)
	assert.True(t, raftHostAssigned(t, *assigned, a.QuicBaaSConfig.RaftAddress), "%v", *assigned)
	assert.Equal(t, 1, starts, "datastore did not start once the fault cleared")
}

// TestInitLinkSetupErrors: the bond and zone-address helpers report each
// failed item instead of swallowing it.
func TestInitLinkSetupErrors(t *testing.T) {
	a := zoneAddressApp(t)
	stubOVSBridge(t)
	stubZonePorts(t, newFakeZonePorts())
	stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })
	setBridgeUpFn = func(context.Context, string) error { return errors.New("link down") }

	err := a.initZoneAddresses(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "link down")
	assert.ErrorAs(t, a.initSDNLinks(context.Background()), new(ErrSDNLinkSetup))
	assert.False(t, a.sdnLinksUp)
}

// TestInitNetworkAndStores_RaftAddressUpAtDatastoreStart drives Init's
// datastore boundary: when the datastore starts, the clustered node's
// raft-address is already on its zone port. Running initStores before
// initClusterNetwork fails this test.
func TestInitNetworkAndStores_RaftAddressUpAtDatastoreStart(t *testing.T) {
	a := zoneAddressApp(t)
	a.NetworkConfig.Bonds[0].Mode = "balance-tcp"
	a.QuicBaaSConfig = &quicbaas.Config{
		NodeID:        1,
		RaftAddress:   "10.4.6.10:63000",
		JoinAddresses: []string{"1=10.4.6.10:63000", "2=10.4.6.11:63000", "3=10.4.6.12:63000"},
	}
	stubOVSBridge(t)
	stubZonePorts(t, newFakeZonePorts())
	assigned := stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	started := false
	original := initStoresFn
	initStoresFn = func(app *App) error {
		started = true
		assert.True(t, raftHostAssigned(t, *assigned, app.QuicBaaSConfig.RaftAddress),
			"datastore started before raft-address %s was assigned (assigned %v)",
			app.QuicBaaSConfig.RaftAddress, *assigned)
		return nil
	}
	t.Cleanup(func() { initStoresFn = original })

	require.NoError(t, a.initNetworkAndStores(context.Background()))
	assert.True(t, started, "datastore never started")
}

// TestInitNetworkAndStores_BondCreatedBeforeStores covers PR #1867
// Codex round 4: the Type=ovs bond is the physical path to the Raft
// peers, so it must be created in OVS before the datastore starts.
func TestInitNetworkAndStores_BondCreatedBeforeStores(t *testing.T) {
	a := zoneAddressApp(t)
	a.NetworkConfig.Bonds[0].Mode = "balance-tcp"
	a.QuicBaaSConfig = &quicbaas.Config{
		NodeID:        1,
		RaftAddress:   "10.4.6.10:63000",
		JoinAddresses: []string{"1=10.4.6.10:63000", "2=10.4.6.11:63000", "3=10.4.6.12:63000"},
	}
	_, client := stubOVSBridgeClient(t)
	stubZonePorts(t, newFakeZonePorts())
	stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	started := false
	original := initStoresFn
	initStoresFn = func(*App) error {
		started = true
		assert.Equal(t, []string{"bond0"}, client.bonds,
			"datastore started before OVS bond bond0 was created")
		return nil
	}
	t.Cleanup(func() { initStoresFn = original })

	require.NoError(t, a.initNetworkAndStores(context.Background()))
	assert.True(t, started, "datastore never started")
	assert.True(t, a.sdnLinksUp)
}

// TestInitNetworkAndStores_FailedBondFailsBeforeStores covers PR #1867
// Codex round 4: an AddBond failure fails cluster-network preparation,
// keeps the datastore stopped and leaves the links retryable.
func TestInitNetworkAndStores_FailedBondFailsBeforeStores(t *testing.T) {
	a := zoneAddressApp(t)
	a.NetworkConfig.Bonds[0].Mode = "balance-tcp"
	a.QuicBaaSConfig = &quicbaas.Config{
		NodeID:        1,
		RaftAddress:   "10.4.6.10:63000",
		JoinAddresses: []string{"1=10.4.6.10:63000", "2=10.4.6.11:63000", "3=10.4.6.12:63000"},
	}
	_, client := stubOVSBridgeClient(t)
	client.addBondErr = errors.New("ovsdb: bond member eth7 busy")
	stubZonePorts(t, newFakeZonePorts())
	stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	started := false
	original := initStoresFn
	initStoresFn = func(*App) error {
		started = true
		return nil
	}
	t.Cleanup(func() { initStoresFn = original })

	err := a.initNetworkAndStores(context.Background())
	require.Error(t, err)
	var clusterErr ErrClusterNetworkLinkSetup
	require.ErrorAs(t, err, &clusterErr)
	assert.ErrorAs(t, err, new(ErrSDNLinkSetup))
	assert.Contains(t, err.Error(), "bond bond0", "error does not name the bond")
	assert.Equal(t, []string{"bond0"}, client.bonds)
	assert.False(t, a.sdnLinksUp)
	assert.False(t, started, "datastore started after a failed OVS bond")

	client.addBondErr = nil
	require.NoError(t, a.initNetworkAndStores(context.Background()))
	assert.Equal(t, []string{"bond0", "bond0"}, client.bonds, "bond creation not retried")
	assert.True(t, a.sdnLinksUp)
	assert.True(t, started, "datastore never started after the retry")
}

// A failed zone address of a clustered node fails cluster-network
// preparation: the datastore's explicit raft bind address would be absent,
// and Init would never reach the later initSDN retry (Codex round 3, #1867).
func TestInitNetworkAndStores_FailedZoneAddressFailsBeforeStores(t *testing.T) {
	a := zoneAddressApp(t)
	a.NetworkConfig.Bonds[0].Mode = "balance-tcp"
	a.QuicBaaSConfig = &quicbaas.Config{
		NodeID:        1,
		RaftAddress:   "10.4.6.10:63000",
		JoinAddresses: []string{"1=10.4.6.10:63000", "2=10.4.6.11:63000", "3=10.4.6.12:63000"},
	}
	stubOVSBridge(t)
	stubZonePorts(t, newFakeZonePorts())
	stubBridgeNetlink(t)
	stubProbe(t, func(context.Context, string, net.IP) error { return nil })

	ok := assignBridgeAddrFn
	assignBridgeAddrFn = func(_ context.Context, port, addr string) error {
		if addr == "10.4.6.10/24" {
			return errors.New("netlink: address assignment refused")
		}
		return ok(context.Background(), port, addr)
	}
	t.Cleanup(func() { assignBridgeAddrFn = ok })

	started := false
	original := initStoresFn
	initStoresFn = func(*App) error {
		started = true
		return nil
	}
	t.Cleanup(func() { initStoresFn = original })

	err := a.initNetworkAndStores(context.Background())
	require.Error(t, err)
	var clusterErr ErrClusterNetworkLinkSetup
	require.ErrorAs(t, err, &clusterErr)
	assert.ErrorAs(t, err, new(ErrSDNLinkSetup))
	assert.Contains(t, err.Error(), "zone address 10.4.6.10/24 on ", "error does not name the link")
	assert.False(t, a.sdnLinksUp)
	assert.False(t, started, "datastore started after a failed zone address")
}
