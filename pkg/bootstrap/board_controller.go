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

package bootstrap

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// BoardController is the board-agnostic hardware-control contract the bootstrap
// orchestrator depends on to drive a node's install lifecycle: power control,
// boot-device selection, and (for virtual-media installs) mounting the install
// medium.
//
// It deliberately does NOT name a transport. Today the only implementation is
// the BMC client (IPMI + Redfish are two transports of the same board
// controller, selected by bmc_protocol), but any future out-of-band management
// system — vendor DC managers (iLO/iDRAC beyond Redfish), cloud instance
// metadata/hypervisor control planes, smart PDUs, or a custom controller — can
// satisfy this interface and plug into the orchestrator unchanged.
//
// A node without any management block in bootstrap.yaml has NO BoardController.
// The orchestrator performs ZERO hardware operations for such nodes: the ISO
// self-drives its own post-install boot (installer after-install=reboot) and
// the orchestrator only observes health. This is what lets the same automation
// provision a Raspberry Pi, an unmanaged mini-PC booted from USB, or a plain
// PXE node with no BMC, alongside fully managed servers — with no code changes.
type BoardController interface {
	PowerOn(ctx context.Context) error
	PowerOff(ctx context.Context) error
	PowerReset(ctx context.Context) error
	PowerCycle(ctx context.Context) error
	PowerStatus(ctx context.Context) (bmc.PowerState, error)
	SetBootDevice(ctx context.Context, device bmc.BootDevice, persistent bool) error
	MountVirtualMedia(ctx context.Context, spec *bmc.MediaSpec) error
	UnmountVirtualMedia(ctx context.Context) error
	ClearUEFIBootEntries(ctx context.Context) error
	Close() error
}

// Compile-time assertion that the BMC client satisfies the board-agnostic
// controller contract. If bmc.Client ever drops a method the orchestrator
// depends on, this fails the build rather than at runtime.
var _ BoardController = (bmc.Client)(nil)

// hasBoardManagement reports whether a node declares an out-of-band board
// management endpoint in its config. Today that is a BMC block (bmc_address);
// as new controller types are added, extend this predicate (and
// resolveBoardController) to recognize their config blocks. When this returns
// false the node is provisioned WITHOUT any hardware operations.
func hasBoardManagement(node *NodeConfig) bool {
	return node.BMCAddress != ""
}

// resolveBoardController returns a BoardController for the node together with
// the bmc.Config used to build it, or (nil, nil, false) when the node has no
// board management. The factory the orchestrator holds (bmc.ClientFactory) is
// the current transport registry; future controller types dispatch here on
// which management block the node declares.
//
// The controller is per-node so each endpoint gets its own trust material
// (e.g. per-node SPKI pin) — see nodeBMCTLSProvider.
func (o *Orchestrator) resolveBoardController(node *NodeConfig) (BoardController, *bmc.Config, bool) {
	if !hasBoardManagement(node) {
		return nil, nil, false
	}
	cfg := buildBMCConfig(node, o.nodeBMCTLSProvider(node))
	client, err := o.bmcFactory.NewClient(cfg)
	if err != nil {
		o.logger.Warn("bootstrap: failed to construct board controller for managed node",
			"hostname", node.Hostname, "error", err.Error())
		return nil, cfg, true
	}
	return client, cfg, true
}
