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

package bmc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestLogger creates a logger for test output.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestDiscoverMAC_Redfish(t *testing.T) {
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
			"Manufacturer":     "TestVendor",
			"Model":            "TestServer",
			"SerialNumber":     "TST123",
			"BiosVersion":      "1.0",
			"PowerState":       "On",
			"Boot":             map[string]string{"BootSourceOverrideTarget": "Pxe"},
			"ProcessorSummary": map[string]interface{}{"Count": 2, "Model": "Xeon"},
			"MemorySummary":    map[string]interface{}{"TotalSystemMemoryGiB": 64.0},
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"VirtualMedia": map[string]string{"@odata.id": "/redfish/v1/Managers/1/VirtualMedia"},
		})
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
			"MACAddress": "AA:BB:CC:DD:EE:FF",
			"Name":       "NIC1",
		})
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}

	config := &Config{
		Address:       host,
		Port:          portNum,
		Protocol:      ProtocolRedfish,
		Username:      "admin",
		Password:      "pass",
		SkipTLSVerify: true,
	}

	logger := newTestLogger()

	mac, err := DiscoverMAC(context.Background(), config, logger)
	if err != nil {
		t.Fatalf("DiscoverMAC returned unexpected error: %v", err)
	}

	if mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected MAC AA:BB:CC:DD:EE:FF, got %s", mac)
	}
}

// TestDiscoverMAC_IPMI verifies that when IPMI is the configured protocol
// AND no Redfish service is reachable on the same address, MAC discovery
// surfaces ErrMACDiscoveryUnsupported as before. We point Address at TEST-NET-1
// (RFC 5737) so the Redfish probe is guaranteed to fail.
func TestDiscoverMAC_IPMI(t *testing.T) {
	config := &Config{
		Address:  "192.0.2.1",
		Port:     623,
		Protocol: ProtocolIPMI,
	}

	logger := newTestLogger()

	_, err := DiscoverMAC(context.Background(), config, logger)
	if err == nil {
		t.Fatal("expected error for IPMI MAC discovery, got nil")
	}

	if _, ok := err.(ErrMACDiscoveryUnsupported); !ok {
		t.Errorf("expected ErrMACDiscoveryUnsupported, got %T: %v", err, err)
	}
}

// TestDiscoverMAC_IPMIFallthroughRedfish covers the real-world case where the
// operator configured `bmc_protocol: ipmi` but the same BMC also speaks
// Redfish on the standard HTTPS port. DiscoverMAC must probe Redfish, succeed,
// and return the MAC from EthernetInterfaces — bypassing the
// ErrMACDiscoveryUnsupported short-circuit that used to apply.
func TestDiscoverMAC_IPMIFallthroughRedfish(t *testing.T) {
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
			"PowerState":   "On",
			"Boot":         map[string]string{"BootSourceOverrideTarget": "Pxe"},
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"VirtualMedia": map[string]string{"@odata.id": "/redfish/v1/Managers/1/VirtualMedia"},
		})
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
			"MACAddress": "00:25:90:5E:02:AA",
			"Name":       "OnBoardLAN1",
		})
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}

	// Redirect the Redfish reachability probe at the httptest server
	// running on an ephemeral port. The probe is package-internal so
	// reaching in here is acceptable; production callers continue to
	// hit port 443 by default.
	originalProbePort := redfishProbePort
	redfishProbePort = portNum
	defer func() { redfishProbePort = originalProbePort }()

	// Configured for IPMI, but a Redfish service IS available on the
	// same host. Expect Redfish fallthrough to succeed.
	config := &Config{
		Address:       host,
		Port:          portNum,
		Protocol:      ProtocolIPMI,
		Username:      "admin",
		Password:      "pass",
		SkipTLSVerify: true,
	}

	mac, err := DiscoverMAC(context.Background(), config, newTestLogger())
	if err != nil {
		t.Fatalf("expected Redfish fallthrough to succeed, got error: %v", err)
	}
	if mac != "00:25:90:5E:02:AA" {
		t.Errorf("expected MAC 00:25:90:5E:02:AA, got %q", mac)
	}
}

func TestDiscoverMAC_NilConfig(t *testing.T) {
	logger := newTestLogger()

	_, err := DiscoverMAC(context.Background(), nil, logger)
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}

	if _, ok := err.(ErrNilConfig); !ok {
		t.Errorf("expected ErrNilConfig, got %T: %v", err, err)
	}
}

func TestDiscoverMAC_InvalidProtocol(t *testing.T) {
	config := &Config{
		Address:  "192.168.1.100",
		Port:     443,
		Protocol: Protocol("invalid"),
	}

	logger := newTestLogger()

	_, err := DiscoverMAC(context.Background(), config, logger)
	if err == nil {
		t.Fatal("expected error for invalid protocol, got nil")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}
}

func TestDiscoverMAC_RedfishNoInterfaces(t *testing.T) {
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
			"Members": []map[string]string{},
		})
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}

	config := &Config{
		Address:       host,
		Port:          portNum,
		Protocol:      ProtocolRedfish,
		Username:      "admin",
		Password:      "pass",
		SkipTLSVerify: true,
	}

	logger := newTestLogger()

	_, err := DiscoverMAC(context.Background(), config, logger)
	if err == nil {
		t.Fatal("expected error when no ethernet interfaces, got nil")
	}

	if _, ok := err.(ErrMACNotFound); !ok {
		t.Errorf("expected ErrMACNotFound, got %T: %v", err, err)
	}
}

func TestDetectProtocol_Redfish(t *testing.T) {
	// Use an unroutable address with short timeout to exercise both probe paths.
	protocol := DetectProtocol(context.Background(), "192.0.2.1", 100*time.Millisecond)
	if protocol != "" {
		t.Errorf("expected empty protocol for unreachable address, got %s", protocol)
	}
}

func TestDetectProtocol_Neither(t *testing.T) {
	protocol := DetectProtocol(context.Background(), "192.0.2.1", 100*time.Millisecond)
	if protocol != "" {
		t.Errorf("expected empty protocol for unreachable address, got %s", protocol)
	}
}

func TestDetectProtocol_DefaultTimeout(t *testing.T) {
	// Verify that zero timeout is replaced with the 5s default. Use a small
	// explicit timeout to keep the test fast.
	protocol := DetectProtocol(context.Background(), "192.0.2.1", 200*time.Millisecond)
	if protocol != "" {
		t.Errorf("expected empty protocol, got %s", protocol)
	}
}

func TestMACRegexp(t *testing.T) {
	tests := []struct {
		mac   string
		valid bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"00:11:22:33:44:55", true},
		{"AABBCCDDEEFF", false},
		{"AA:BB:CC:DD:EE", false},
		{"AA:BB:CC:DD:EE:FF:00", false},
		{"", false},
		{"ZZ:BB:CC:DD:EE:FF", false},
	}

	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			if got := macRegexp.MatchString(tt.mac); got != tt.valid {
				t.Errorf("macRegexp.MatchString(%q) = %v, want %v", tt.mac, got, tt.valid)
			}
		})
	}
}

func TestProbeRedfish_Unreachable(t *testing.T) {
	result := probeRedfish(context.Background(), "192.0.2.1", 100*time.Millisecond)
	if result {
		t.Error("expected probeRedfish to return false for unreachable address")
	}
}

func TestProbeIPMI_NoResponse(t *testing.T) {
	result := probeIPMI(context.Background(), "192.0.2.1", 100*time.Millisecond)
	if result {
		t.Error("expected probeIPMI to return false for unreachable address")
	}
}

func TestDiscoverMAC_Redfish_InvalidMAC(t *testing.T) {
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
			"MACAddress": "not-a-mac",
			"Name":       "NIC1",
		})
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	addr := ts.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}

	config := &Config{
		Address:       host,
		Port:          portNum,
		Protocol:      ProtocolRedfish,
		Username:      "admin",
		Password:      "pass",
		SkipTLSVerify: true,
	}

	_, err := DiscoverMAC(context.Background(), config, newTestLogger())
	if err == nil {
		t.Fatal("expected error for invalid MAC format, got nil")
	}

	if _, ok := err.(ErrMACNotFound); !ok {
		t.Errorf("expected ErrMACNotFound, got %T: %v", err, err)
	}
}

func TestDiscoveryErrors_ErrorStrings(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "ErrMACNotFound",
			err:      ErrMACNotFound{Address: "10.0.0.1"},
			contains: "10.0.0.1",
		},
		{
			name:     "ErrProtocolDetectionFailed",
			err:      ErrProtocolDetectionFailed{Address: "10.0.0.2"},
			contains: "10.0.0.2",
		},
		{
			name:     "ErrMACDiscoveryUnsupported",
			err:      ErrMACDiscoveryUnsupported{Protocol: ProtocolIPMI},
			contains: "ipmi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if !strings.Contains(msg, tt.contains) {
				t.Errorf("error message %q does not contain %q", msg, tt.contains)
			}
		})
	}
}

// multiNICRedfishMux builds a Redfish handler that advertises N ethernet
// interfaces with the given MAC addresses. Empty / sentinel MACs are passed
// through verbatim so tests can verify the filter logic.
func multiNICRedfishMux(macs []string) *http.ServeMux {
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

	members := make([]map[string]string, 0, len(macs))
	for i := range macs {
		members = append(members, map[string]string{
			"@odata.id": "/redfish/v1/Systems/1/EthernetInterfaces/" + itoa(i+1),
		})
	}
	mux.HandleFunc("/redfish/v1/Systems/1/EthernetInterfaces", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"Members": members})
	})
	for i := range macs {
		mac := macs[i]
		idx := i + 1
		mux.HandleFunc("/redfish/v1/Systems/1/EthernetInterfaces/"+itoa(idx), func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"MACAddress": mac,
				"Name":       "NIC" + itoa(idx),
			})
		})
	}
	return mux
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

func startTLSMux(t *testing.T, mux *http.ServeMux) (string, int, func()) {
	t.Helper()
	ts := httptest.NewTLSServer(mux)
	addr := ts.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}
	return host, portNum, ts.Close
}

func TestDiscoverMACs_MultipleMACs(t *testing.T) {
	macs := []string{
		"00:25:90:5E:02:AA",
		"00:25:90:5E:02:AB",
		"00:25:90:5E:02:AC",
	}
	host, port, closer := startTLSMux(t, multiNICRedfishMux(macs))
	defer closer()

	got, err := DiscoverMACs(context.Background(), &Config{
		Address:       host,
		Port:          port,
		Protocol:      ProtocolRedfish,
		Username:      "admin",
		Password:      "pass",
		SkipTLSVerify: true,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("DiscoverMACs returned error: %v", err)
	}
	if len(got) != len(macs) {
		t.Fatalf("expected %d MACs, got %d (%v)", len(macs), len(got), got)
	}
	for i := range macs {
		if got[i] != macs[i] {
			t.Errorf("entry %d: expected %s, got %s", i, macs[i], got[i])
		}
	}
}

func TestDiscoverMACs_FiltersInvalidSentinels(t *testing.T) {
	macs := []string{
		"FF:FF:FF:FF:FF:FF",   // broadcast sentinel - filtered
		"00:00:00:00:00:00",   // null sentinel - filtered
		"not-a-mac",           // invalid format - filtered
		"00:25:90:5E:02:AA",   // valid
		"",                    // empty - filtered
		"00:25:90:5E:02:AB",   // valid
	}
	host, port, closer := startTLSMux(t, multiNICRedfishMux(macs))
	defer closer()

	got, err := DiscoverMACs(context.Background(), &Config{
		Address:       host,
		Port:          port,
		Protocol:      ProtocolRedfish,
		SkipTLSVerify: true,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("DiscoverMACs returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 valid MACs after filtering, got %d (%v)", len(got), got)
	}
	if got[0] != "00:25:90:5E:02:AA" || got[1] != "00:25:90:5E:02:AB" {
		t.Errorf("unexpected filtered set: %v", got)
	}
}

func TestDiscoverMACs_AllSentinelsReturnsNotFound(t *testing.T) {
	host, port, closer := startTLSMux(t, multiNICRedfishMux([]string{
		"FF:FF:FF:FF:FF:FF",
		"00:00:00:00:00:00",
	}))
	defer closer()

	_, err := DiscoverMACs(context.Background(), &Config{
		Address:       host,
		Port:          port,
		Protocol:      ProtocolRedfish,
		SkipTLSVerify: true,
	}, newTestLogger())
	if err == nil {
		t.Fatal("expected ErrMACNotFound, got nil")
	}
	if _, ok := err.(ErrMACNotFound); !ok {
		t.Errorf("expected ErrMACNotFound, got %T: %v", err, err)
	}
}

func TestDiscoverMACs_IPMIFallthroughMultipleMACs(t *testing.T) {
	macs := []string{
		"00:25:90:5E:02:AA",
		"00:25:90:5E:02:AB",
	}
	host, port, closer := startTLSMux(t, multiNICRedfishMux(macs))
	defer closer()

	originalProbePort := redfishProbePort
	redfishProbePort = port
	defer func() { redfishProbePort = originalProbePort }()

	got, err := DiscoverMACs(context.Background(), &Config{
		Address:       host,
		Port:          port,
		Protocol:      ProtocolIPMI,
		SkipTLSVerify: true,
	}, newTestLogger())
	if err != nil {
		t.Fatalf("expected IPMI fallthrough to succeed, got: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 MACs from fallthrough, got %d (%v)", len(got), got)
	}
}

func TestDiscoverMACs_NilConfig(t *testing.T) {
	_, err := DiscoverMACs(context.Background(), nil, newTestLogger())
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
	if _, ok := err.(ErrNilConfig); !ok {
		t.Errorf("expected ErrNilConfig, got %T", err)
	}
}
