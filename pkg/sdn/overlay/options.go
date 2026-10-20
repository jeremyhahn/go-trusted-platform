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

package overlay

import (
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// Option configures the Controller.
type Option func(*Controller)

// WithLogger sets the logger for the controller.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Controller) {
		c.logger = logger
	}
}

// WithOVSClient sets the OVS client.
func WithOVSClient(client *ovs.Client) Option {
	return func(c *Controller) {
		c.ovsClient = client
	}
}

// WithOpenFlowClient sets the OpenFlow client.
func WithOpenFlowClient(client *openflow.Client) Option {
	return func(c *Controller) {
		c.ofClient = client
	}
}

// WithVTEPManager sets the VTEP manager.
func WithVTEPManager(manager *vxlan.VTEPManager) Option {
	return func(c *Controller) {
		c.vtepManager = manager
	}
}

// WithBGPSpeaker sets the BGP speaker.
func WithBGPSpeaker(speaker *bgp.Speaker) Option {
	return func(c *Controller) {
		c.bgpSpeaker = speaker
	}
}

// WithEVPNManager sets the EVPN manager.
func WithEVPNManager(manager *bgp.EVPNManager) Option {
	return func(c *Controller) {
		c.evpnManager = manager
	}
}

// WithGateway sets the gateway.
func WithGateway(gw *gateway.Gateway) Option {
	return func(c *Controller) {
		c.gateway = gw
	}
}

// WithIPAM sets the IPAM allocator.
func WithIPAM(allocator ipam.Allocator) Option {
	return func(c *Controller) {
		c.ipam = allocator
	}
}

// WithVTEPObserver sets the observer notified when remote VTEPs are learned.
func WithVTEPObserver(observer VTEPObserver) Option {
	return func(c *Controller) {
		c.vtepObserver = observer
	}
}

// WithStateManager sets the state manager.
func WithStateManager(state *StateManager) Option {
	return func(c *Controller) {
		c.state = state
	}
}
