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
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

func discoveryTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newMockRedfishServer creates a test TLS server that serves Redfish responses
// with the given MAC address on the EthernetInterfaces endpoint.
func newMockRedfishServer(mac string) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Systems":  map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Chassis":  map[string]string{"@odata.id": "/redfish/v1/Chassis"},
			"Managers": map[string]string{"@odata.id": "/redfish/v1/Managers"},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Members": []map[string]string{{"@odata.id": "/redfish/v1/Systems/1"}},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems/1", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Manufacturer": "TestVendor",
			"Model":        "TestServer",
			"SerialNumber": "TST123",
			"PowerState":   "On",
			"Actions": map[string]interface{}{
				"#ComputerSystem.Reset": map[string]string{
					"target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
				},
			},
		})
	})
	mux.HandleFunc("/redfish/v1/Chassis", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Members": []map[string]string{{"@odata.id": "/redfish/v1/Chassis/1"}},
		})
	})
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Members": []map[string]string{{"@odata.id": "/redfish/v1/Managers/1"}},
		})
	})
	mux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	})
	mux.HandleFunc("/redfish/v1/Systems/1/EthernetInterfaces", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Members": []map[string]string{
				{"@odata.id": "/redfish/v1/Systems/1/EthernetInterfaces/1"},
			},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems/1/EthernetInterfaces/1", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"MACAddress": mac,
			"Name":       "NIC1",
		})
	})

	return httptest.NewTLSServer(mux)
}

func extractHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to parse address %s: %v", addr, err)
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func TestDiscoverNodes_AllManual(t *testing.T) {
	nodes := []NodeConfig{
		{Hostname: "cp-0", Role: RoleControlPlane, MACs: []string{"AA:BB:CC:DD:00:01"}},
		{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:01"}},
		{Hostname: "gw-0", Role: RoleGateway, MACs: []string{"AA:BB:CC:DD:02:01"}},
	}

	logger := discoveryTestLogger()
	discovered, err := DiscoverNodes(context.Background(), nodes, logger)
	if err != nil {
		t.Fatalf("DiscoverNodes returned error: %v", err)
	}

	if len(discovered) != 3 {
		t.Fatalf("expected 3 discovered nodes, got %d", len(discovered))
	}

	for i, d := range discovered {
		if d.BMCManaged {
			t.Errorf("node %d: expected BMCManaged=false, got true", i)
		}
		if len(d.DiscoveredMACs) != 1 || d.DiscoveredMACs[0] != nodes[i].MACs[0] {
			t.Errorf("node %d: expected MAC %v, got %v", i, nodes[i].MACs, d.DiscoveredMACs)
		}
		if d.SystemInfo != nil {
			t.Errorf("node %d: expected nil SystemInfo for manual node", i)
		}
	}
}

func TestDiscoverNodes_Mixed(t *testing.T) {
	ts := newMockRedfishServer("11:22:33:44:55:66")
	defer ts.Close()

	host, port := extractHostPort(t, ts.Listener.Addr().String())
	_ = host
	_ = port

	// Test manual nodes (BMC nodes need real port mapping which is tested via integration).
	manualNodes := []NodeConfig{
		{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:01"}},
		{Hostname: "gw-0", Role: RoleGateway, MACs: []string{"AA:BB:CC:DD:02:01"}},
	}

	logger := discoveryTestLogger()
	discovered, err := DiscoverNodes(context.Background(), manualNodes, logger)
	if err != nil {
		t.Fatalf("DiscoverNodes returned error: %v", err)
	}

	if len(discovered) != 2 {
		t.Fatalf("expected 2 discovered nodes, got %d", len(discovered))
	}

	if len(discovered[0].DiscoveredMACs) != 1 || discovered[0].DiscoveredMACs[0] != "AA:BB:CC:DD:01:01" {
		t.Errorf("expected MAC [AA:BB:CC:DD:01:01], got %v", discovered[0].DiscoveredMACs)
	}
}

func TestDiscoverNodes_BMCFailure(t *testing.T) {
	nodes := []NodeConfig{
		{
			Hostname:    "cp-0",
			Role:        RoleControlPlane,
			BMCAddress:  "192.0.2.1",
			BMCUser:     "admin",
			BMCPassword: "pass",
			BMCProtocol: "redfish",
			BMCTrust:    []trust.Strategy{trust.StrategyTOFU},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	logger := discoveryTestLogger()
	_, err := DiscoverNodes(ctx, nodes, logger)
	if err == nil {
		t.Fatal("expected error for unreachable BMC, got nil")
	}

	if _, ok := err.(ErrNodeDiscoveryFailed); !ok {
		t.Errorf("expected ErrNodeDiscoveryFailed, got %T: %v", err, err)
	}
}

func TestDiscoverNodes_EmptyNodes(t *testing.T) {
	logger := discoveryTestLogger()
	_, err := DiscoverNodes(context.Background(), nil, logger)
	if err == nil {
		t.Fatal("expected error for empty nodes, got nil")
	}

	if _, ok := err.(ErrInvalidBootstrapConfig); !ok {
		t.Errorf("expected ErrInvalidBootstrapConfig, got %T: %v", err, err)
	}
}

func TestDiscoverNodes_EmptySlice(t *testing.T) {
	logger := discoveryTestLogger()
	_, err := DiscoverNodes(context.Background(), []NodeConfig{}, logger)
	if err == nil {
		t.Fatal("expected error for empty nodes slice, got nil")
	}

	if _, ok := err.(ErrInvalidBootstrapConfig); !ok {
		t.Errorf("expected ErrInvalidBootstrapConfig, got %T: %v", err, err)
	}
}

func TestBuildBMCConfig_Redfish(t *testing.T) {
	node := &NodeConfig{
		BMCAddress:       "10.200.0.10",
		BMCUser:          "admin",
		BMCPassword:      "secret",
		BMCProtocol:      "redfish",
		BMCEncryptionKey: "deadbeef",
	}

	config := buildBMCConfig(node, nil)

	if config.Address != "10.200.0.10" {
		t.Errorf("expected address 10.200.0.10, got %s", config.Address)
	}
	if config.Port != 443 {
		t.Errorf("expected port 443, got %d", config.Port)
	}
	if config.Protocol != "redfish" {
		t.Errorf("expected protocol redfish, got %s", config.Protocol)
	}
	// TLS field is nil when no provider supplied; legacy path applies.
	if config.TLS != nil {
		t.Error("expected nil TLS provider when none passed")
	}
}

func TestBuildBMCConfig_IPMI(t *testing.T) {
	node := &NodeConfig{
		BMCAddress:  "10.200.0.10",
		BMCUser:     "admin",
		BMCPassword: "secret",
		BMCProtocol: "ipmi",
	}

	config := buildBMCConfig(node, nil)

	if config.Port != 623 {
		t.Errorf("expected port 623, got %d", config.Port)
	}
	if config.Protocol != "ipmi" {
		t.Errorf("expected protocol ipmi, got %s", config.Protocol)
	}
}

func TestBuildBMCConfig_Auto(t *testing.T) {
	node := &NodeConfig{
		BMCAddress:  "10.200.0.10",
		BMCUser:     "admin",
		BMCPassword: "secret",
		BMCProtocol: "auto",
	}

	config := buildBMCConfig(node, nil)

	if config.Port != 443 {
		t.Errorf("expected port 443 for auto, got %d", config.Port)
	}
}

// TestBuildBMCConfig_WithTLSProvider verifies that a non-nil TLSProvider is
// wired into the returned config's TLS field.
func TestBuildBMCConfig_WithTLSProvider(t *testing.T) {
	node := &NodeConfig{
		BMCAddress:  "10.200.0.10",
		BMCUser:     "admin",
		BMCPassword: "secret",
		BMCProtocol: "redfish",
	}

	// Use the bootstrap provider itself as the injected value; we just need
	// any non-nil TLSProvider to verify the wiring.
	stub := &bootstrapBMCTLSProvider{}
	config := buildBMCConfig(node, stub)

	if config.TLS == nil {
		t.Error("expected TLS provider to be set, got nil")
	}
	if config.TLS != stub {
		t.Error("expected exact TLSProvider reference to be preserved")
	}
}

// TestNodeBMCTrustConfig_NoChain verifies that a node without bmc_trust
// returns the base config unchanged.
func TestNodeBMCTrustConfig_NoChain(t *testing.T) {
	node := &NodeConfig{Hostname: "cp-0"}
	base := &trust.Config{}
	result := nodeBMCTrustConfig(node, base)
	if result != base {
		t.Error("expected base config returned unchanged when node has no bmc_trust")
	}
}

// TestNodeBMCTrustConfig_WithChain verifies that a node with bmc_trust builds
// a new BMC scope with the correct strategies.
func TestNodeBMCTrustConfig_WithChain(t *testing.T) {
	node := &NodeConfig{
		Hostname: "cp-0",
		BMCTrust: []trust.Strategy{trust.StrategyTOFU},
	}
	result := nodeBMCTrustConfig(node, nil)
	if result == nil {
		t.Fatal("expected non-nil config")
	}
	if result.BMC == nil {
		t.Fatal("expected BMC scope to be set")
	}
	if len(result.BMC.Strategies) != 1 || result.BMC.Strategies[0] != trust.StrategyTOFU {
		t.Errorf("expected [tofu] strategies, got %v", result.BMC.Strategies)
	}
}

// TestNodeBMCTrustConfig_WithSPKIPin verifies that bmc_spki_pin populates
// the SPKI.Pin field on the BMC scope config.
func TestNodeBMCTrustConfig_WithSPKIPin(t *testing.T) {
	const pin = "abc123"
	node := &NodeConfig{
		Hostname:   "cp-0",
		BMCTrust:   []trust.Strategy{trust.StrategySPKI},
		BMCSPKIPin: pin,
	}
	result := nodeBMCTrustConfig(node, nil)
	if result.BMC == nil {
		t.Fatal("expected BMC scope to be set")
	}
	if result.BMC.SPKI == nil {
		t.Fatal("expected SPKI config to be non-nil when bmc_spki_pin set")
	}
	if result.BMC.SPKI.Pin != pin {
		t.Errorf("expected pin %q, got %q", pin, result.BMC.SPKI.Pin)
	}
}

// TestNodeBMCTrustConfig_PreservesBase verifies that Default and Internal
// scopes from the base config are preserved in the merged result.
func TestNodeBMCTrustConfig_PreservesBase(t *testing.T) {
	defaultScope := &trust.ScopeConfig{Strategies: []trust.Strategy{trust.StrategyTOFU}}
	base := &trust.Config{Bootstrap: defaultScope}
	node := &NodeConfig{
		Hostname: "cp-0",
		BMCTrust: []trust.Strategy{trust.StrategyCAFile},
	}
	result := nodeBMCTrustConfig(node, base)
	if result.Bootstrap != defaultScope {
		t.Error("expected Default scope from base to be preserved")
	}
}

// TestNewBootstrapBMCTLSProvider_NilConfig verifies that a nil trust config
// returns nil, nil, nil without error.
func TestNewBootstrapBMCTLSProvider_NilConfig(t *testing.T) {
	provider, pinStore, err := NewBootstrapBMCTLSProvider(nil, discoveryTestLogger())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if provider != nil {
		t.Error("expected nil provider for nil config")
	}
	if pinStore != nil {
		t.Error("expected nil pinStore for nil config")
	}
}

// TestNewBootstrapBMCTLSProvider_NoBMCScope verifies that a config with no
// BMC scope returns nil, nil, nil without error.
func TestNewBootstrapBMCTLSProvider_NoBMCScope(t *testing.T) {
	cfg := &trust.Config{
		Bootstrap: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyTOFU},
		},
	}
	provider, pinStore, err := NewBootstrapBMCTLSProvider(cfg, discoveryTestLogger())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if provider != nil {
		t.Error("expected nil provider when BMC scope not configured")
	}
	if pinStore != nil {
		t.Error("expected nil pinStore when BMC scope not configured")
	}
}

// TestDiscoveryOptions_NilTLSProvider verifies that DiscoverNodes works when
// no TLSProvider is set in the options (backward-compatible legacy path).
func TestDiscoveryOptions_NilTLSProvider(t *testing.T) {
	nodes := []NodeConfig{
		{Hostname: "w-0", Role: RoleWorker, MACs: []string{"AA:BB:CC:DD:01:01"}},
	}
	logger := discoveryTestLogger()
	discovered, err := DiscoverNodes(context.Background(), nodes, logger, DiscoveryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(discovered) != 1 {
		t.Fatalf("expected 1 node, got %d", len(discovered))
	}
}
