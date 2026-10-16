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

package modes

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

func TestOverlayModeConfig_Validate(t *testing.T) {
	tests := []struct {
		name string
		edit func(*OverlayModeConfig)
		want error
	}{
		{name: "symmetric IRB", edit: func(*OverlayModeConfig) {}},
		{name: "bridging only, without EVPN or an admitter", edit: func(c *OverlayModeConfig) {
			c.EVPNConfig, c.AnycastGateways, c.Subnets, c.AnycastGatewayMAC, c.L3VNI = nil, nil, nil, nil, 0
			c.Admitter = nil
		}},
		{name: "EVPN without an admitter", edit: func(c *OverlayModeConfig) { c.Admitter = nil }, want: ErrAdmitterNil},
		{name: "no VTEP config", edit: func(c *OverlayModeConfig) { c.VTEPConfig = nil }, want: ErrVTEPConfigNil},
		{name: "invalid VTEP config", edit: func(c *OverlayModeConfig) { c.VTEPConfig.UnderlayIface = "" }, want: vxlan.ErrUnderlayNotReady},
		{name: "IPv6 VTEP", edit: func(c *OverlayModeConfig) { c.VTEPConfig.LocalIP = netip.MustParseAddr("fd00::1") }, want: ErrInvalidVTEPIP},
		{name: "no bridge", edit: func(c *OverlayModeConfig) { c.BridgeName = "" }, want: ErrBridgeNameEmpty},
		{name: "no access port", edit: func(c *OverlayModeConfig) { c.AccessPort = "" }, want: ErrAccessPortEmpty},
		{name: "no logger", edit: func(c *OverlayModeConfig) { c.Logger = nil }, want: ErrLoggerNil},
		{name: "anycast IP without a MAC", edit: func(c *OverlayModeConfig) { c.AnycastGatewayMAC = nil }, want: ErrAnycastGatewayIncomplete},
		{name: "anycast MAC without an IP", edit: func(c *OverlayModeConfig) { c.AnycastGateways = nil }, want: ErrAnycastGatewayIncomplete},
		{name: "IPv6 anycast gateway", edit: func(c *OverlayModeConfig) { c.AnycastGateways[ovlL2VNI] = netip.MustParseAddr("fd00::1") }, want: ErrAnycastGatewayIncomplete},
		{name: "anycast gateway on a VNI beyond 24 bits", edit: func(c *OverlayModeConfig) { c.AnycastGateways[1<<24] = ovlAnycastIP }, want: ErrVNIOutOfRange},
		{name: "L3VNI beyond 24 bits", edit: func(c *OverlayModeConfig) { c.L3VNI = 1 << 24 }, want: ErrVNIOutOfRange},
		{name: "L3VNI without EVPN", edit: func(c *OverlayModeConfig) { c.EVPNConfig = nil }, want: ErrRouterMACRequired},
		{name: "L3VNI without a router MAC", edit: func(c *OverlayModeConfig) { c.EVPNConfig.RouterMAC = nil }, want: ErrRouterMACRequired},
		{name: "L3VNI without the anycast gateway", edit: func(c *OverlayModeConfig) {
			c.AnycastGateways, c.Subnets, c.AnycastGatewayMAC = nil, nil, nil
		}, want: ErrAnycastGatewayRequired},
		{name: "routed subnets without an L3VNI", edit: func(c *OverlayModeConfig) { c.L3VNI = 0 }},
		{name: "subnet on a VNI without an anycast gateway", edit: func(c *OverlayModeConfig) {
			c.Subnets[ovlL2VNI+1] = netip.MustParsePrefix("10.2.0.0/24")
		}, want: ErrRoutedSubnetInvalid},
		{name: "subnet not holding its anycast gateway", edit: func(c *OverlayModeConfig) {
			c.Subnets[ovlL2VNI] = netip.MustParsePrefix("10.2.0.0/24")
		}, want: ErrRoutedSubnetInvalid},
		{name: "subnet with host bits", edit: func(c *OverlayModeConfig) {
			c.Subnets[ovlL2VNI] = netip.MustParsePrefix("10.1.0.1/24")
		}, want: ErrRoutedSubnetInvalid},
		{name: "IPv6 subnet", edit: func(c *OverlayModeConfig) {
			c.Subnets[ovlL2VNI] = netip.MustParsePrefix("fd00::/64")
		}, want: ErrRoutedSubnetInvalid},
		{name: "two VNIs with the same subnet", edit: func(c *OverlayModeConfig) {
			c.AnycastGateways[ovlL2VNI+1] = ovlAnycastIP
			c.Subnets[ovlL2VNI+1] = ovlSubnet
		}, want: ErrRoutedSubnetInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := overlayConfig(newFakeSpeaker())
			tt.edit(cfg)

			err := cfg.Validate()

			if tt.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestNewOverlayModeHandler(t *testing.T) {
	ovs, sw := newFakeOverlayOVS(), newFakeSwitch()

	t.Run("builds a stopped handler", func(t *testing.T) {
		h, err := NewOverlayModeHandler(overlayConfig(newFakeSpeaker()), ovs, sw)

		require.NoError(t, err)
		assert.False(t, h.GetStatus().Running)
		assert.Empty(t, sw.table(), "nothing is installed before Start")
	})

	t.Run("refuses missing or invalid parts", func(t *testing.T) {
		_, err := NewOverlayModeHandler(nil, ovs, sw)
		assert.ErrorIs(t, err, ErrConfigNil)

		cfg := overlayConfig(newFakeSpeaker())
		cfg.BridgeName = ""
		_, err = NewOverlayModeHandler(cfg, ovs, sw)
		assert.ErrorIs(t, err, ErrBridgeNameEmpty)

		_, err = NewOverlayModeHandler(overlayConfig(newFakeSpeaker()), nil, sw)
		assert.ErrorIs(t, err, ErrOVSClientNil)

		_, err = NewOverlayModeHandler(overlayConfig(newFakeSpeaker()), ovs, nil)
		assert.ErrorIs(t, err, ErrOpenFlowClientNil)
	})

	t.Run("reports an EVPN manager it cannot build", func(t *testing.T) {
		cfg := overlayConfig(nil)

		_, err := NewOverlayModeHandler(cfg, ovs, sw)

		var initErr *ErrOverlayInitFailed
		require.ErrorAs(t, err, &initErr)
		assert.Equal(t, "EVPNManager", initErr.Component)
	})
}

func TestOverlayModeHandler_Start(t *testing.T) {
	t.Run("creates the flow-based VXLAN port and the base pipeline", func(t *testing.T) {
		f := newOverlayFixture(t, nil)

		port, err := f.ovs.GetVXLANPortWithOptions(context.Background(), "br-int", f.handler.vtepManager.PortName())
		require.NoError(t, err)
		assert.True(t, port.IsFlowRemote, "remote_ip=flow")
		assert.True(t, port.IsFlowKey, "key=flow")
		assert.Equal(t, ovlBaseTable, f.sw.table())

		status := f.handler.GetStatus()
		assert.True(t, status.Running)
		assert.Equal(t, ovlVTEPA, status.LocalVTEP)
		assert.False(t, status.StartedAt.IsZero())
	})

	t.Run("replaces the flows a previous run left", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		stale := testBuilder(t).decapAllow(ovlL2VNI, ovlVTEPC)
		require.NoError(t, f.sw.SendFlowMods(context.Background(), []*openflow.FlowMod{stale}))

		require.NoError(t, f.handler.Start(context.Background()))
		t.Cleanup(func() { require.NoError(t, f.handler.Stop(context.Background())) })

		assert.Equal(t, ovlBaseTable, f.sw.table())
	})

	t.Run("installs the pipeline fail-closed", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		mark := f.sw.batchCount()

		require.NoError(t, f.handler.Start(context.Background()))
		t.Cleanup(func() { require.NoError(t, f.handler.Stop(context.Background())) })

		assertFailClosed(t, f.sw.batchesSince(mark)[0])
	})

	t.Run("a running handler refuses a second start", func(t *testing.T) {
		f := newOverlayFixture(t, nil)

		assert.ErrorIs(t, f.handler.Start(context.Background()), ErrAlreadyRunning)
	})

	t.Run("a VXLAN port OVS refuses fails the start", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		f.ovs.addErr = errSwitchDown

		err := f.handler.Start(context.Background())

		assertStartFailed(t, err, "VTEPManager")
		assert.False(t, f.handler.GetStatus().Running)
	})

	failures := []struct {
		name      string
		component string
		breakIt   func(*overlayFixture)
	}{
		{name: "an unknown access port", component: "AccessPort", breakIt: func(f *overlayFixture) {
			delete(f.ovs.ofPorts, ovlAccessPort)
		}},
		{name: "an access port without an OpenFlow number", component: "AccessPort", breakIt: func(f *overlayFixture) {
			f.ovs.ofPorts[ovlAccessPort] = -1
		}},
		{name: "an EVPN watch the speaker refuses", component: "EVPNManager", breakIt: func(f *overlayFixture) {
			f.speaker.watchErr = errSwitchDown
		}},
		{name: "a switch refusing the pipeline", component: "OpenFlow", breakIt: func(f *overlayFixture) {
			f.sw.fail(errSwitchDown)
		}},
	}
	for _, tt := range failures {
		t.Run(tt.name+" fails the start and removes the VXLAN port", func(t *testing.T) {
			f := newStoppedOverlay(t, nil)
			tt.breakIt(f)

			err := f.handler.Start(context.Background())

			assertStartFailed(t, err, tt.component)
			assert.False(t, f.handler.GetStatus().Running)
			assert.False(t, f.ovs.hasPort(f.handler.vtepManager.PortName()))
		})
	}

	t.Run("a failed start can be retried", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		f.sw.fail(errSwitchDown)
		require.Error(t, f.handler.Start(context.Background()))
		f.sw.fail(nil)

		require.NoError(t, f.handler.Start(context.Background()), "EVPN and the VTEP were stopped")
		require.NoError(t, f.handler.Stop(context.Background()))
	})

	t.Run("a switch applying part of the pipeline is left with no overlay flows", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		f.sw.refuse(2, nil)

		err := f.handler.Start(context.Background())

		assertStartFailed(t, err, "OpenFlow")
		var partial *openflow.ErrBatchPartialFailure
		assert.ErrorAs(t, err, &partial)
		assert.Empty(t, f.sw.table())
	})
}

func assertStartFailed(t *testing.T, err error, component string) {
	t.Helper()
	var startErr *ErrOverlayStartFailed
	require.ErrorAs(t, err, &startErr)
	assert.Equal(t, component, startErr.Component)
}

func TestOverlayModeHandler_Stop(t *testing.T) {
	t.Run("withdraws, removes every flow and the VXLAN port", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		require.NoError(t, f.handler.Start(context.Background()))
		f.withVNI(t)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))

		require.NoError(t, f.handler.Stop(context.Background()))

		assert.Empty(t, f.sw.table())
		assert.False(t, f.ovs.hasPort(f.handler.vtepManager.PortName()))
		assert.Contains(t, f.speaker.deletedTypes(), bgp.EVPNTypeInclusiveMulticast)
		status := f.handler.GetStatus()
		assert.False(t, status.Running)
		assert.Zero(t, status.VNICount)
		assert.Zero(t, status.RemoteVTEPCount)
	})

	t.Run("a stopped handler refuses", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)

		assert.ErrorIs(t, f.handler.Stop(context.Background()), ErrNotRunning)
	})

	t.Run("carries on past failures and reports them all", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		require.NoError(t, f.handler.Start(context.Background()))
		f.sw.fail(errSwitchDown)
		f.ovs.deleteErr = errSwitchDown

		err := f.handler.Stop(context.Background())

		var flowErr *ErrFlowOperationFailed
		require.ErrorAs(t, err, &flowErr)
		var stopErr *ErrStopFailed
		require.ErrorAs(t, err, &stopErr)
		assert.Equal(t, "VTEPManager", stopErr.Component)
		assert.False(t, f.handler.GetStatus().Running)
	})
}

func TestOverlayModeHandler_AddVNI(t *testing.T) {
	t.Run("carries the VNI and places this VTEP on it", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		assert.Len(t, f.sw.matching("tun_id=10100"), 4, "ingress, flood, gateway-MAC ingress, gateway ARP")
		assert.Equal(t, "pop_vlan,set:tun_id=10100 goto:20", f.sw.lookup(t, TableVXLANDecap, "in_port=3", "vlan=100"))
		assert.Equal(t, "push_vlan,set:vlan=100,output:3,pop_vlan", f.sw.lookup(t, TableEgress, "tun_id=10100"))
		assert.Contains(t, f.speaker.addedTypes(), bgp.EVPNTypeInclusiveMulticast)
		assert.Equal(t, 1, f.handler.GetStatus().VNICount)
	})

	t.Run("refuses invalid VNIs and VLANs", func(t *testing.T) {
		f := newOverlayFixture(t, nil)
		ctx := context.Background()

		assert.ErrorIs(t, f.handler.AddVNI(ctx, 0, ovlVLAN), ErrVNIOutOfRange)
		assert.ErrorIs(t, f.handler.AddVNI(ctx, 1<<24, ovlVLAN), ErrVNIOutOfRange)
		assert.ErrorIs(t, f.handler.AddVNI(ctx, ovlL2VNI, 0), ErrVLANOutOfRange)
		assert.ErrorIs(t, f.handler.AddVNI(ctx, ovlL2VNI, 4095), ErrVLANOutOfRange)
		assert.ErrorIs(t, f.handler.AddVNI(ctx, ovlL3VNI, ovlVLAN), ErrVNIAlreadyExists, "the L3VNI is not a segment")
	})

	t.Run("refuses a VNI or VLAN already in use", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()

		assert.ErrorIs(t, f.handler.AddVNI(ctx, ovlL2VNI, ovlVLAN+1), ErrVNIAlreadyExists)
		assert.ErrorIs(t, f.handler.AddVNI(ctx, ovlL2VNI+1, ovlVLAN), ErrVLANInUse)
	})

	t.Run("a stopped handler refuses", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)

		assert.ErrorIs(t, f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN), ErrNotRunning)
	})

	t.Run("a switch refusing the flows adds nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil)
		f.sw.fail(errSwitchDown)

		err := f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN)

		assertVNIFailed(t, err, "install")
		f.sw.fail(nil)
		assert.Zero(t, f.handler.GetStatus().VNICount)
		assert.Empty(t, f.speaker.addedTypes(), "EVPN never heard of it")
	})

	t.Run("a join EVPN refuses removes the VNI again", func(t *testing.T) {
		f := newOverlayFixture(t, nil)
		f.speaker.failAdds(errSwitchDown)

		err := f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN)

		assertVNIFailed(t, err, "join")
		assert.Equal(t, ovlBaseTable, f.sw.table())
		f.speaker.failAdds(nil)
		require.NoError(t, f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN), "the VLAN is free again")
	})

	t.Run("without EVPN the VNI bridges locally", func(t *testing.T) {
		f := newOverlayFixture(t, func(c *OverlayModeConfig) {
			c.EVPNConfig, c.AnycastGateways, c.Subnets, c.AnycastGatewayMAC, c.L3VNI = nil, nil, nil, nil, 0
		}).withVNI(t)

		assert.Len(t, f.sw.matching("tun_id=10100"), 2, "ingress and flood")
	})
}

func assertVNIFailed(t *testing.T, err error, operation string) {
	t.Helper()
	var vniErr *ErrVNIOperationFailed
	require.ErrorAs(t, err, &vniErr)
	assert.Equal(t, operation, vniErr.Operation)
	assert.Equal(t, ovlL2VNI, vniErr.VNI)
}

func TestOverlayModeHandler_SubnetOrigination(t *testing.T) {
	originated := []bgp.PrefixRoute{{Prefix: ovlSubnet, VNI: ovlL3VNI}}

	t.Run("a routed VNI originates its subnet in the L3VNI's IP-VRF", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		assert.Equal(t, originated, f.speaker.addedPrefixes())
	})

	t.Run("a bridged VNI originates nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		require.NoError(t, f.handler.AddVNI(context.Background(), ovlL2VNI+1, ovlVLAN+1))

		assert.Equal(t, originated, f.speaker.addedPrefixes(), "only the routed VNI's subnet")
	})

	t.Run("without an L3VNI nothing is originated or withdrawn", func(t *testing.T) {
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.L3VNI = 0 }).withVNI(t)

		require.NoError(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI))

		assert.Empty(t, f.speaker.addedPrefixes())
		assert.Empty(t, f.speaker.deletedPrefixes())
	})

	t.Run("removing the VNI withdraws its subnet once", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.AddVNI(context.Background(), ovlL2VNI+1, ovlVLAN+1))

		require.NoError(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI))
		assert.Equal(t, originated, f.speaker.deletedPrefixes(), "withdrawn while the IP-VRF has another VNI")

		require.NoError(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI+1))
		assert.Equal(t, originated, f.speaker.deletedPrefixes(), "not withdrawn again with the last VNI")
	})

	t.Run("stop withdraws the subnet", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		require.NoError(t, f.handler.Start(context.Background()))
		f.withVNI(t)

		require.NoError(t, f.handler.Stop(context.Background()))

		assert.Equal(t, originated, f.speaker.deletedPrefixes())
	})

	t.Run("an origination EVPN refuses removes the VNI again", func(t *testing.T) {
		f := newOverlayFixture(t, nil)
		f.speaker.refuseRoutes(bgp.EVPNTypeIPPrefix, errSwitchDown)

		err := f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN)

		assertVNIFailed(t, err, "originate")
		assert.ErrorIs(t, err, errSwitchDown)
		assert.Equal(t, ovlBaseTable, f.sw.table())
		assert.Zero(t, f.handler.GetStatus().VNICount)
		assert.Contains(t, f.speaker.deletedTypes(), bgp.EVPNTypeInclusiveMulticast, "the VNI left EVPN")
		f.speaker.refuseRoutes(bgp.EVPNTypeIPPrefix, nil)
		require.NoError(t, f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN), "the VNI can be added again")
		assert.Equal(t, originated, f.speaker.addedPrefixes())
	})

	t.Run("a refused withdrawal is reported and the VNI still leaves", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.speaker.refuseRoutes(bgp.EVPNTypeIPPrefix, errSwitchDown)

		err := f.handler.RemoveVNI(context.Background(), ovlL2VNI)

		assertVNIFailed(t, err, "withdraw")
		assert.ErrorIs(t, err, errSwitchDown)
		assert.Zero(t, f.handler.GetStatus().VNICount)
		assert.Contains(t, f.speaker.deletedTypes(), bgp.EVPNTypeInclusiveMulticast)
	})
}

func TestOverlayModeHandler_RemoveVNI(t *testing.T) {
	t.Run("removes the segment, its hosts and, with the last VNI, the prefixes", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")))
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))

		require.NoError(t, f.handler.RemoveVNI(ctx, ovlL2VNI))

		assert.Equal(t, ovlBaseTable, f.sw.table())
		status := f.handler.GetStatus()
		assert.Zero(t, status.VNICount)
		assert.Zero(t, status.LocalMACCount+status.RemoteMACCount)
		assert.Zero(t, status.PrefixCount)
		assert.Contains(t, f.speaker.deletedTypes(), bgp.EVPNTypeInclusiveMulticast)
		require.NoError(t, f.handler.AddVNI(ctx, ovlL2VNI+1, ovlVLAN), "the VLAN is free again")
	})

	t.Run("keeps the prefixes while another VNI is left", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.handler.AddVNI(ctx, ovlL2VNI+1, ovlVLAN+1))
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")))

		require.NoError(t, f.handler.RemoveVNI(ctx, ovlL2VNI))

		assert.Equal(t, 1, f.handler.GetStatus().PrefixCount)
		assert.Len(t, f.sw.matching("ipv4_dst=10.2.0.0/24"), 1)
	})

	t.Run("refuses an unknown VNI or a stopped handler", func(t *testing.T) {
		f := newOverlayFixture(t, nil)
		assert.ErrorIs(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI), ErrVNINotFound)

		stopped := newStoppedOverlay(t, nil)
		assert.ErrorIs(t, stopped.handler.RemoveVNI(context.Background(), ovlL2VNI), ErrNotRunning)
	})

	t.Run("a switch refusing the removal keeps the VNI", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.fail(errSwitchDown)

		err := f.handler.RemoveVNI(context.Background(), ovlL2VNI)

		assertVNIFailed(t, err, "remove")
		f.sw.fail(nil)
		assert.Equal(t, 1, f.handler.GetStatus().VNICount)
		require.NoError(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI), "the removal can be retried")
		assert.Equal(t, ovlBaseTable, f.sw.table())
	})

	t.Run("stop completes after a refused removal", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		require.NoError(t, f.handler.Start(context.Background()))
		f.withVNI(t)
		f.sw.fail(errSwitchDown)
		require.Error(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI))
		f.sw.fail(nil)

		assert.NoError(t, f.handler.Stop(context.Background()))
	})
}

func TestOverlayModeHandler_LearnMAC(t *testing.T) {
	t.Run("delivers to a local host, routes to it and advertises it", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))

		assert.Equal(t, "push_vlan,set:vlan=100 goto:70",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:01:10"))
		assert.Equal(t, "output:IN_PORT", f.sw.lookup(t, TableLocalDelivery, "in_port=3"), "hairpin to a local host")
		assert.Equal(t, "output:3", f.sw.lookup(t, TableLocalDelivery, "in_port=7"))
		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.10"), "set:eth_dst=02:00:00:00:01:10")
		assert.Len(t, f.sw.matching("t=40 ", "arp_tpa=10.1.0.10"), 1)

		advertised := f.speaker.addedMACIPs()
		require.Len(t, advertised, 1)
		assert.Equal(t, ovlHostMAC, advertised[0].MAC)
		assert.Equal(t, ovlHostIP, advertised[0].IP)
		assert.Equal(t, ovlL2VNI, advertised[0].VNI)
	})

	t.Run("a second IP adds to the host", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		second := netip.MustParseAddr("10.1.0.11")
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))

		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, second))

		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		require.NoError(t, err)
		assert.Equal(t, []netip.Addr{ovlHostIP, second}, entry.IPs)
		assert.Equal(t, MACSourceLocal, entry.Source)
		assert.False(t, entry.VTEPIP.IsValid())
		assert.Len(t, f.sw.matching("t=50 ", "eth_dst=02:00:00:00:01:10"), 2)
	})

	t.Run("a local host replaces a remote one", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlRemoteMAC, netip.Addr{}))

		assert.Equal(t, "push_vlan,set:vlan=100 goto:70",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"))
		assert.Empty(t, f.sw.matching("tun_src=10.0.0.2"), "nothing is tunnelled from B any more")
		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, err)
		assert.Empty(t, entry.IPs, "the remote bindings went with the remote host")
	})

	t.Run("refuses invalid input and unknown VNIs", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()

		assert.ErrorIs(t, f.handler.LearnMAC(ctx, ovlL2VNI, nil, ovlHostIP), ErrMACNil)
		assert.ErrorIs(t, f.handler.LearnMAC(ctx, ovlL2VNI, net.HardwareAddr{1, 2, 3}, ovlHostIP), ErrMACInvalid)
		assert.ErrorIs(t, f.handler.LearnMAC(ctx, ovlL2VNI+1, ovlHostMAC, ovlHostIP), ErrVNINotFound)

		stopped := newStoppedOverlay(t, nil)
		assert.ErrorIs(t, stopped.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP), ErrNotRunning)
	})

	t.Run("a switch refusing the flows learns nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.fail(errSwitchDown)

		err := f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP)

		assertMACFailed(t, err, "learn")
		f.sw.fail(nil)
		_, err = f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		assert.ErrorIs(t, err, ErrMACNotFound)
		assert.Empty(t, f.speaker.addedMACIPs())
	})

	t.Run("a failed advertisement keeps the local flows", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.speaker.failAdds(errSwitchDown)

		err := f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP)

		assertMACFailed(t, err, "advertise")
		_, err = f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		assert.NoError(t, err)
		f.speaker.failAdds(nil)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP), "learning again retries")
		assert.Len(t, f.speaker.addedMACIPs(), 1)
	})
}

func assertMACFailed(t *testing.T, err error, operation string) {
	t.Helper()
	var macErr *ErrMACOperationFailed
	require.ErrorAs(t, err, &macErr)
	assert.Equal(t, operation, macErr.Operation)
}

func TestOverlayModeHandler_ForgetMAC(t *testing.T) {
	t.Run("removes the host and withdraws its routes", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, netip.Addr{}))

		require.NoError(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC))

		assert.Empty(t, f.sw.matching("02:00:00:00:01:10"))
		assert.Empty(t, f.sw.matching("10.1.0.10"))
		assert.Len(t, f.speaker.deletedTypes(), 2, "both Type-2 routes withdrawn")
		_, err := f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		assert.ErrorIs(t, err, ErrMACNotFound)
	})

	t.Run("a withdrawal BGP refused is retried by forgetting the MAC again", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))
		f.speaker.failDeletes(errSwitchDown)

		err := f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC)

		assertMACFailed(t, err, "withdraw")
		assert.Empty(t, f.sw.matching("02:00:00:00:01:10"), "the host is gone from the switch")
		assertMACFailed(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC), "withdraw")
		assert.Empty(t, f.speaker.deletedTypes())

		f.speaker.failDeletes(nil)
		require.NoError(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC))
		assert.Equal(t, []bgp.EVPNRouteType{bgp.EVPNTypeMACIPAdvertisement}, f.speaker.deletedTypes())
		assert.ErrorIs(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC), ErrMACNotFound, "nothing is left to withdraw")
	})

	t.Run("a pending withdrawal is dropped once the MAC is learned again", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))
		f.speaker.failDeletes(errSwitchDown)
		require.Error(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC))
		f.speaker.failDeletes(nil)

		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))

		_, err := f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		assert.NoError(t, err)
		assert.Empty(t, f.handler.unwithdrawn)
	})

	t.Run("removing the VNI drops its pending withdrawals", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))
		f.speaker.failDeletes(errSwitchDown)
		require.Error(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC))
		f.speaker.failDeletes(nil)

		require.NoError(t, f.handler.RemoveVNI(ctx, ovlL2VNI))

		assert.Contains(t, f.speaker.deletedTypes(), bgp.EVPNTypeMACIPAdvertisement, "leaving the VNI withdrew the route")
		assert.Empty(t, f.handler.unwithdrawn)
		assert.ErrorIs(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC), ErrMACNotFound)
	})

	t.Run("a route never advertised is not an error", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.speaker.failAdds(errSwitchDown)
		require.Error(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
		f.speaker.failAdds(nil)

		assert.NoError(t, f.handler.ForgetMAC(context.Background(), ovlL2VNI, ovlHostMAC))
	})

	t.Run("refuses invalid, unknown and remote MACs", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		ctx := context.Background()
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		assert.ErrorIs(t, f.handler.ForgetMAC(ctx, ovlL2VNI, nil), ErrMACNil)
		assert.ErrorIs(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC), ErrMACNotFound)
		assert.ErrorIs(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlRemoteMAC), ErrMACNotFound, "EVPN owns a remote MAC")

		stopped := newStoppedOverlay(t, nil)
		assert.ErrorIs(t, stopped.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC), ErrNotRunning)
	})

	t.Run("a switch refusing the removal keeps the host", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
		f.sw.fail(errSwitchDown)

		err := f.handler.ForgetMAC(context.Background(), ovlL2VNI, ovlHostMAC)

		assertMACFailed(t, err, "forget")
		f.sw.fail(nil)
		_, err = f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		assert.NoError(t, err)
		assert.Empty(t, f.speaker.deletedTypes())
	})
}

func TestOverlayModeHandler_LookupMAC(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

	t.Run("returns a remote entry", func(t *testing.T) {
		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)

		require.NoError(t, err)
		assert.Equal(t, MACSourceRemote, entry.Source)
		assert.Equal(t, ovlVTEPB, entry.VTEPIP)
		assert.Equal(t, []netip.Addr{ovlRemoteIP}, entry.IPs)
		assert.False(t, entry.UpdatedAt.IsZero())
	})

	t.Run("refuses invalid and unknown MACs", func(t *testing.T) {
		_, err := f.handler.LookupMAC(ovlL2VNI, net.HardwareAddr{1})
		assert.ErrorIs(t, err, ErrMACInvalid)

		_, err = f.handler.LookupMAC(ovlL2VNI+1, ovlRemoteMAC)
		assert.ErrorIs(t, err, ErrMACNotFound)
	})
}

func TestOverlayModeHandler_GetStatus(t *testing.T) {
	t.Run("counts what the overlay forwards", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")))
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))

		status := f.handler.GetStatus()

		assert.Equal(t, 1, status.VNICount)
		assert.Equal(t, 2, status.RemoteVTEPCount)
		assert.Equal(t, 1, status.LocalMACCount)
		assert.Equal(t, 1, status.RemoteMACCount)
		assert.Equal(t, 1, status.PrefixCount)
		assert.Equal(t, ovlL3VNI, status.L3VNI)
		assert.True(t, status.ARPSuppressionEnabled)
		assert.True(t, status.AnycastGatewayConfigured)
		assert.Positive(t, status.Uptime)
	})

	t.Run("a stopped handler has no uptime", func(t *testing.T) {
		status := newStoppedOverlay(t, nil).handler.GetStatus()

		assert.False(t, status.Running)
		assert.Zero(t, status.Uptime)
		assert.True(t, status.StartedAt.IsZero())
	})
}

func TestMACEntrySource_String(t *testing.T) {
	assert.Equal(t, "local", MACSourceLocal.String())
	assert.Equal(t, "remote", MACSourceRemote.String())
}
