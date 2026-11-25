// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

// Package vpn provides multi-protocol integration tests for the platformd
// management-VPN control plane. The suite drives the operator CLI plus all
// five SDK transports (REST, gRPC, QUIC, MCP, Unix) against a live daemon and
// asserts feature parity: every transport must answer the same eight
// operations with the same shape and the same failure classes.
//
// Run via:
//
//	make integration-test-vpn
package vpn

import (
	"context"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// testPolicyName prefixes the posture policy each scenario stores and deletes.
const testPolicyName = "integration-baseline"

// TestVPNMultiProtocol runs the shared scenario against every protocol.
func TestVPNMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []VPNCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "vpn", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runVPNScenario(t, ctx, adapter)
		})
	}
}

// runVPNScenario exercises the full VPN surface over one transport. The
// tenant-bound mTLS transports refuse a request that names a tenant other
// than the caller's, so every transport works in the harness tenant; the
// device and policy names are per run and per transport so the runs, which
// share that tenant with each other and with other tests, cannot collide.
func runVPNScenario(t *testing.T, ctx context.Context, cmd VPNCommands) {
	t.Helper()

	tenantID := helpers.HarnessTenantID
	deviceID := helpers.GenerateUniqueID("vpn-device")
	policyName := helpers.GenerateUniqueID(testPolicyName + "-" + cmd.Name())

	cctx, cancel := ShortContext(ctx)
	_, probeErr := cmd.ListPeers(cctx, tenantID)
	cancel()
	switch {
	case probeErr == nil:
		runConfiguredScenario(t, ctx, cmd, tenantID, deviceID, policyName)
	case IsNotConfigured(probeErr):
		assertFailsClosed(t, ctx, cmd, tenantID, deviceID, policyName)
	default:
		t.Fatalf("%s ListPeers: %v", cmd.Name(), probeErr)
	}
}

// runConfiguredScenario walks the peer and posture-policy lifecycles on a
// node whose vpn control plane is configured.
func runConfiguredScenario(t *testing.T, ctx context.Context, cmd VPNCommands, tenantID, deviceID, policyName string) {
	t.Helper()

	// The tenant is shared, so leave nothing behind if a step fails early.
	t.Cleanup(func() {
		cctx, cancel := ShortContext(ctx)
		defer cancel()
		_ = cmd.RevokePeer(cctx, tenantID, deviceID)
		_ = cmd.DeletePosturePolicy(cctx, tenantID, policyName)
	})

	t.Run("EnrolPeer", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		peer, err := cmd.EnrolPeer(cctx, tenantID, deviceID, []string{"mgmt"})
		if err != nil {
			t.Fatalf("%s EnrolPeer: %v", cmd.Name(), err)
		}
		if peer.GetTenantId() != tenantID || peer.GetDeviceId() != deviceID {
			t.Fatalf("%s: enrolled %s/%s, want %s/%s", cmd.Name(),
				peer.GetTenantId(), peer.GetDeviceId(), tenantID, deviceID)
		}
		if len(peer.GetZones()) != 1 || peer.GetZones()[0] != "mgmt" {
			t.Fatalf("%s: enrolled zones %v, want [mgmt]", cmd.Name(), peer.GetZones())
		}
		if peer.GetEnrolledAtUnix() <= 0 {
			t.Fatalf("%s: enrolled peer carries no enrolment time", cmd.Name())
		}

		// Re-enrolling replaces the zones but keeps the first enrolment time.
		again, err := cmd.EnrolPeer(cctx, tenantID, deviceID, nil)
		if err != nil {
			t.Fatalf("%s EnrolPeer (re-enrol): %v", cmd.Name(), err)
		}
		if len(again.GetZones()) != 0 {
			t.Fatalf("%s: re-enrolled zones %v, want none", cmd.Name(), again.GetZones())
		}
		if again.GetEnrolledAtUnix() != peer.GetEnrolledAtUnix() {
			t.Fatalf("%s: re-enrolment moved the enrolment time from %d to %d", cmd.Name(),
				peer.GetEnrolledAtUnix(), again.GetEnrolledAtUnix())
		}
	})

	t.Run("ListPeers", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		peers, err := cmd.ListPeers(cctx, tenantID)
		if err != nil {
			t.Fatalf("%s ListPeers: %v", cmd.Name(), err)
		}
		if !listsPeer(peers, deviceID) {
			t.Fatalf("%s: tenant %s lists %v, want %s among them", cmd.Name(), tenantID, peers, deviceID)
		}
	})

	t.Run("PosturePolicyLifecycle", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		stored, err := cmd.SetPosturePolicy(cctx, tenantID, policyName, testPostureModule)
		if err != nil {
			t.Fatalf("%s SetPosturePolicy: %v", cmd.Name(), err)
		}
		assertPolicy(t, cmd.Name(), stored, tenantID, policyName)

		fetched, err := cmd.GetPosturePolicy(cctx, tenantID, policyName)
		if err != nil {
			t.Fatalf("%s GetPosturePolicy: %v", cmd.Name(), err)
		}
		assertPolicy(t, cmd.Name(), fetched, tenantID, policyName)
		if fetched.GetModule() != testPostureModule {
			t.Fatalf("%s: fetched module differs from the stored one", cmd.Name())
		}

		policies, err := cmd.ListPosturePolicies(cctx, tenantID)
		if err != nil {
			t.Fatalf("%s ListPosturePolicies: %v", cmd.Name(), err)
		}
		listed := false
		for _, p := range policies {
			if p.GetName() == policyName {
				listed = true
				break
			}
		}
		if !listed {
			t.Fatalf("%s: tenant %s lists policies %v, want %s among them", cmd.Name(), tenantID, policies, policyName)
		}

		if err := cmd.DeletePosturePolicy(cctx, tenantID, policyName); err != nil {
			t.Fatalf("%s DeletePosturePolicy: %v", cmd.Name(), err)
		}
		if _, err := cmd.GetPosturePolicy(cctx, tenantID, policyName); !IsNotFound(err) {
			t.Fatalf("%s: GetPosturePolicy after delete returned %v, want not found", cmd.Name(), err)
		}
		if err := cmd.DeletePosturePolicy(cctx, tenantID, policyName); !IsNotFound(err) {
			t.Fatalf("%s: second DeletePosturePolicy returned %v, want not found", cmd.Name(), err)
		}
	})

	t.Run("SetPosturePolicyRefusesABrokenModule", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		_, err := cmd.SetPosturePolicy(cctx, tenantID, policyName, brokenPostureModule)
		if !IsInvalid(err) {
			t.Fatalf("%s: SetPosturePolicy with a broken module returned %v, want invalid", cmd.Name(), err)
		}
		if _, err := cmd.GetPosturePolicy(cctx, tenantID, policyName); !IsNotFound(err) {
			t.Fatalf("%s: a refused module was stored (%v)", cmd.Name(), err)
		}
	})

	t.Run("RevokePeer", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		if err := cmd.RevokePeer(cctx, tenantID, deviceID); err != nil {
			t.Fatalf("%s RevokePeer: %v", cmd.Name(), err)
		}
		peers, err := cmd.ListPeers(cctx, tenantID)
		if err != nil {
			t.Fatalf("%s ListPeers after revoke: %v", cmd.Name(), err)
		}
		if listsPeer(peers, deviceID) {
			t.Fatalf("%s: tenant %s still lists %s after revoke", cmd.Name(), tenantID, deviceID)
		}
		if err := cmd.RevokePeer(cctx, tenantID, deviceID); !IsNotFound(err) {
			t.Fatalf("%s: second RevokePeer returned %v, want not found", cmd.Name(), err)
		}
	})

	t.Run("Status", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		gateways, err := cmd.Status(cctx, "")
		if err != nil {
			// A daemon that runs no gateway has no session state to report;
			// that is the documented Unavailable answer, not a wiring fault.
			if IsNotConfigured(err) {
				return
			}
			t.Fatalf("%s Status: %v", cmd.Name(), err)
		}
		for _, gw := range gateways {
			if gw.GetGatewayId() == "" {
				t.Fatalf("%s: gateway status %+v has no gateway id", cmd.Name(), gw)
			}
			if gw.GetRunning() && !gw.GetReporting() {
				t.Fatalf("%s: gateway %s is running but not reporting", cmd.Name(), gw.GetGatewayId())
			}
		}
	})
}

// assertFailsClosed checks that a node without a vpn control plane refuses
// every operation the same way, rather than answering some of them.
func assertFailsClosed(t *testing.T, ctx context.Context, cmd VPNCommands, tenantID, deviceID, policyName string) {
	t.Helper()

	cctx, cancel := ShortContext(ctx)
	defer cancel()

	calls := map[string]func() error{
		"EnrolPeer": func() error {
			_, err := cmd.EnrolPeer(cctx, tenantID, deviceID, nil)
			return err
		},
		"RevokePeer": func() error { return cmd.RevokePeer(cctx, tenantID, deviceID) },
		"Status": func() error {
			_, err := cmd.Status(cctx, "")
			return err
		},
		"GetPosturePolicy": func() error {
			_, err := cmd.GetPosturePolicy(cctx, tenantID, policyName)
			return err
		},
		"SetPosturePolicy": func() error {
			_, err := cmd.SetPosturePolicy(cctx, tenantID, policyName, testPostureModule)
			return err
		},
		"DeletePosturePolicy": func() error { return cmd.DeletePosturePolicy(cctx, tenantID, policyName) },
		"ListPosturePolicies": func() error {
			_, err := cmd.ListPosturePolicies(cctx, tenantID)
			return err
		},
	}
	for name, call := range calls {
		if err := call(); !IsNotConfigured(err) {
			t.Errorf("%s %s on a node without a vpn control plane returned %v, want not configured",
				cmd.Name(), name, err)
		}
	}
}

// assertPolicy checks the invariants of a stored posture policy.
func assertPolicy(t *testing.T, transport string, policy *platformv1.VPNPosturePolicy, tenantID, policyName string) {
	t.Helper()

	if policy.GetTenantId() != tenantID || policy.GetName() != policyName {
		t.Fatalf("%s: policy %s/%s, want %s/%s", transport,
			policy.GetTenantId(), policy.GetName(), tenantID, policyName)
	}
	if policy.GetUpdatedAtUnix() <= 0 {
		t.Fatalf("%s: policy carries no update time", transport)
	}
}

// listsPeer reports whether peers holds the device. The harness tenant is
// shared, so a listing may carry peers other runs enrolled.
func listsPeer(peers []*platformv1.VPNPeer, deviceID string) bool {
	for _, p := range peers {
		if p.GetDeviceId() == deviceID {
			return true
		}
	}
	return false
}
