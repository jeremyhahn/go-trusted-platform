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

package daemon

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
)

// gatewayBackendOptions picks the gateway service's load-balancer, NAT64 and
// perf backends (#660). With a datapath socket configured, all three are the
// gatewayd datapath child, reached over live IPC on the #557 supervisor seam:
// every API read and control action goes to the process that owns the
// state, and a child that is not running reports unavailable. The IPC perf
// replaces localPerf. Without a socket only localPerf (OVS on this host, may
// be nil) is wired, and the load-balancer and NAT64 verbs stay unavailable.
//
// The returned client is nil when no socket is configured; the caller owns
// it and closes it on shutdown.
func gatewayBackendOptions(datapathSocket string, localPerf GatewayPerfInterface) ([]GatewayServiceOption, *ipc.Client, error) {
	if datapathSocket == "" {
		if localPerf == nil {
			return nil, nil, nil
		}
		return []GatewayServiceOption{WithPerf(localPerf)}, nil, nil
	}
	client, err := ipc.Dial(datapathSocket)
	if err != nil {
		return nil, nil, err
	}
	return []GatewayServiceOption{
		WithLoadBalancer(client),
		WithNAT64(client),
		WithPerf(client),
	}, client, nil
}

// closeGatewayIPC releases the gatewayd IPC client on shutdown. It is a
// no-op when no datapath socket is configured.
func (d *Daemon) closeGatewayIPC() {
	if d.gatewayIPC == nil {
		return
	}
	if err := d.gatewayIPC.Close(); err != nil {
		d.logger.Warn("Gateway IPC client close failed", "error", err)
	}
}
