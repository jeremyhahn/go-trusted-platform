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
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

var errServiceRootBlip = errors.New("redfish service root: 503 service unavailable")

// recoveringBMCClient models the Redfish client's discovery caching that
// #206 is about: a failed discovery is negative-cached for every gated call
// (GetSystemInfo among them), while HardwareIdentity re-runs discovery
// fresh. The first identityFailures identity reads fail; the next one
// recovers discovery, after which GetSystemInfo answers.
// TestRedfishClient_GetSystemInfo_RidesDiscoveryRecoveredByIdentity in
// pkg/bmc pins the real client to this behaviour.
type recoveringBMCClient struct {
	*bmc.MockClient
	identityFailures int
	identityCalls    int
	discovered       bool
}

func (c *recoveringBMCClient) HardwareIdentity(context.Context) (quirks.Identity, error) {
	c.identityCalls++
	if c.identityCalls <= c.identityFailures {
		return quirks.Identity{}, bmc.ErrInventory{Cause: errServiceRootBlip}
	}
	c.discovered = true
	return c.Identity, nil
}

func (c *recoveringBMCClient) GetSystemInfo(context.Context) (*bmc.SystemInfo, error) {
	if !c.discovered {
		return nil, bmc.ErrInventory{Cause: errServiceRootBlip}
	}
	return c.System, nil
}

// refusingTLSProvider fails every TLS request, so bmc.DiscoverMACs fails
// before dialling and discovery falls back to the operator's MACs. It keeps
// these tests off the network: everything else goes through the injected
// client factory, which never consults the provider.
type refusingTLSProvider struct{}

func (refusingTLSProvider) TLSConfig(context.Context, string) (*tls.Config, error) {
	return nil, errServiceRootBlip
}

func backfillTestNode() NodeConfig {
	return NodeConfig{
		Hostname:    "w-0",
		Role:        RoleWorker,
		MACs:        []string{"aa:bb:cc:dd:01:01"},
		BMCAddress:  "192.0.2.10",
		BMCUser:     "admin",
		BMCPassword: "pass",
		BMCProtocol: "redfish",
	}
}

// backfillTestOrchestrator builds an orchestrator whose bmcFactory hands out
// client, recording how many clients discovery asked it for.
func backfillTestOrchestrator(client bmc.Client, newClients *int) *Orchestrator {
	return &Orchestrator{
		logger:         orchTestLogger(),
		config:         &BootstrapConfig{Nodes: []NodeConfig{backfillTestNode()}},
		bmcTLSProvider: refusingTLSProvider{},
		bmcFactory: &bmc.MockClientFactory{ClientFn: func(*bmc.Config) (bmc.Client, error) {
			*newClients++
			return client, nil
		}},
	}
}

func noIdentityRetryDelay(t *testing.T) {
	t.Helper()
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })
}

// TestOrchestratorDiscover_SystemInfoRidesRecoveredDiscovery is #206: a
// discovery blip that the identity retry recovers from must not leave the
// node without system info. Before the fix, GetSystemInfo ran first, was
// served the failed discovery, and was never re-read after HardwareIdentity
// had recovered it.
func TestOrchestratorDiscover_SystemInfoRidesRecoveredDiscovery(t *testing.T) {
	noIdentityRetryDelay(t)

	mock := bmc.NewMockClient()
	mock.System = &bmc.SystemInfo{Manufacturer: "Supermicro", Product: "SYS-5018D-FN8T", SerialNumber: "S1"}
	mock.Identity = quirks.Identity{Manufacturer: "Supermicro", Model: "X10SDV-TP8F", PartNumber: "SYS-5018D-FN8T-AS001"}
	client := &recoveringBMCClient{MockClient: mock, identityFailures: 1}
	var newClients int
	o := backfillTestOrchestrator(client, &newClients)

	discovered, err := o.discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if newClients != 1 {
		t.Fatalf("orchestrator bmcFactory built %d clients, want 1 — discovery must use the injected factory", newClients)
	}
	if client.identityCalls != 2 {
		t.Fatalf("identity read %d times, want 2 (one failure, one recovery) — the fixture no longer exercises recovery", client.identityCalls)
	}
	node := discovered[0]
	if node.HardwareIdentity == nil || *node.HardwareIdentity != mock.Identity {
		t.Errorf("HardwareIdentity = %+v, want %+v", node.HardwareIdentity, mock.Identity)
	}
	if node.SystemInfo == nil {
		t.Fatal("SystemInfo is nil although the identity read recovered discovery (#206)")
	}
	if *node.SystemInfo != *mock.System {
		t.Errorf("SystemInfo = %+v, want %+v", *node.SystemInfo, *mock.System)
	}
	if mock.CloseCalls() != 1 {
		t.Errorf("client closed %d times, want 1", mock.CloseCalls())
	}
}

// TestOrchestratorDiscover_SystemInfoNilWhenDiscoveryNeverRecovers covers
// the other side: when every identity read fails, discovery is still best
// effort — the node is returned on its operator MACs with neither system
// info nor identity, and no error.
func TestOrchestratorDiscover_SystemInfoNilWhenDiscoveryNeverRecovers(t *testing.T) {
	noIdentityRetryDelay(t)

	mock := bmc.NewMockClient()
	mock.System = &bmc.SystemInfo{Manufacturer: "Supermicro"}
	client := &recoveringBMCClient{MockClient: mock, identityFailures: identityReadAttempts}
	var newClients int
	o := backfillTestOrchestrator(client, &newClients)

	discovered, err := o.discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	node := discovered[0]
	if node.SystemInfo != nil {
		t.Errorf("SystemInfo = %+v, want nil — discovery never recovered", *node.SystemInfo)
	}
	if node.HardwareIdentity != nil {
		t.Errorf("HardwareIdentity = %+v, want nil", *node.HardwareIdentity)
	}
	if len(node.DiscoveredMACs) != 1 || node.DiscoveredMACs[0] != "aa:bb:cc:dd:01:01" {
		t.Errorf("DiscoveredMACs = %v, want the operator MAC", node.DiscoveredMACs)
	}
}

// TestDiscoverNodes_ClientFactoryErrorIsBestEffort verifies a factory that
// cannot build a client costs the node its system info and identity, not its
// discovery.
func TestDiscoverNodes_ClientFactoryErrorIsBestEffort(t *testing.T) {
	factory := &bmc.MockClientFactory{Err: bmc.ErrNilConfig{}}

	discovered, err := DiscoverNodes(context.Background(), []NodeConfig{backfillTestNode()}, orchTestLogger(), DiscoveryOptions{
		TLSProvider:   refusingTLSProvider{},
		ClientFactory: factory,
	})
	if err != nil {
		t.Fatalf("DiscoverNodes: %v", err)
	}

	node := discovered[0]
	if node.SystemInfo != nil || node.HardwareIdentity != nil {
		t.Errorf("SystemInfo = %v, HardwareIdentity = %v, want both nil", node.SystemInfo, node.HardwareIdentity)
	}
	if !node.BMCManaged {
		t.Error("BMCManaged = false, want true")
	}
}
