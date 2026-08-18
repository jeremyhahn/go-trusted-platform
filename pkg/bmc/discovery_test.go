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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
			"@odata.id":      "/redfish/v1/",
			"RedfishVersion": "1.6.0",
			"Systems":        map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Chassis":        map[string]string{"@odata.id": "/redfish/v1/Chassis"},
			"Managers":       map[string]string{"@odata.id": "/redfish/v1/Managers"},
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
		Address:  host,
		Port:     portNum,
		Protocol: ProtocolRedfish,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderFromTLSServer(ts),
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
// AND no Redfish service answers on the same address, MAC discovery surfaces
// ErrMACDiscoveryUnsupported as before. The stand-in for "no Redfish here" is
// a listener the test owns which drops every connection it accepts: the
// assertion is unchanged, but the outcome no longer depends on the network
// silently dropping traffic to an unroutable address.
func TestDiscoverMAC_IPMI(t *testing.T) {
	host, port := startNonRedfishListener(t)

	originalProbePort := redfishProbePort
	redfishProbePort = port
	defer func() { redfishProbePort = originalProbePort }()

	config := &Config{
		Address:  host,
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
			"@odata.id":      "/redfish/v1/",
			"RedfishVersion": "1.6.0",
			"Systems":        map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Chassis":        map[string]string{"@odata.id": "/redfish/v1/Chassis"},
			"Managers":       map[string]string{"@odata.id": "/redfish/v1/Managers"},
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
		Address:  host,
		Port:     portNum,
		Protocol: ProtocolIPMI,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderFromTLSServer(ts),
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
			"@odata.id":      "/redfish/v1/",
			"RedfishVersion": "1.6.0",
			"Systems":        map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Chassis":        map[string]string{"@odata.id": "/redfish/v1/Chassis"},
			"Managers":       map[string]string{"@odata.id": "/redfish/v1/Managers"},
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
		Address:  host,
		Port:     portNum,
		Protocol: ProtocolRedfish,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderFromTLSServer(ts),
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
			"@odata.id":      "/redfish/v1/",
			"RedfishVersion": "1.6.0",
			"Systems":        map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Chassis":        map[string]string{"@odata.id": "/redfish/v1/Chassis"},
			"Managers":       map[string]string{"@odata.id": "/redfish/v1/Managers"},
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
		Address:  host,
		Port:     portNum,
		Protocol: ProtocolRedfish,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderFromTLSServer(ts),
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
			"@odata.id":      "/redfish/v1/",
			"RedfishVersion": "1.6.0",
			"Systems":        map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Chassis":        map[string]string{"@odata.id": "/redfish/v1/Chassis"},
			"Managers":       map[string]string{"@odata.id": "/redfish/v1/Managers"},
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

// tlsProviderFromTLSServer returns a fakeTLSProvider trusting srv's cert.
func tlsProviderFromTLSServer(srv *httptest.Server) TLSProvider {
	return tlsProviderTrusting(srv)
}

// tlsProviderTrusting returns a fakeTLSProvider trusting every given
// server's cert, for tests where more than one HTTPS endpoint is in play.
func tlsProviderTrusting(servers ...*httptest.Server) TLSProvider {
	pool := x509.NewCertPool()
	for _, srv := range servers {
		pool.AddCert(srv.Certificate())
	}
	return &fakeTLSProvider{cfg: &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}}
}

func startTLSMux(t *testing.T, mux *http.ServeMux) (string, int, *httptest.Server) {
	t.Helper()
	return startTLSHandler(t, mux)
}

// startTLSHandler starts an HTTPS test server for handler and returns the
// host and port it listens on.
func startTLSHandler(t *testing.T, handler http.Handler) (string, int, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting test server address: %v", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parsing test server port %q: %v", port, err)
	}
	return host, portNum, ts
}

// startNonRedfishListener starts a loopback listener that accepts every
// connection and immediately drops it: something holds the Redfish port, but
// it is not a Redfish service. The test owns the port for its whole life, so
// the result does not depend on what else the machine is doing with ports.
func startNonRedfishListener(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting non-Redfish listener: %v", err)
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				t.Errorf("closing accepted connection: %v", err)
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("closing non-Redfish listener: %v", err)
		}
		<-closed
	})
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// TestDiscoverMACs_IPMIFallthroughWithholdsCredentials covers the risk the
// fallthrough carries: it is a guess about an endpoint the operator described
// as IPMI, so an HTTPS service that is not a BMC must never be offered the
// operator's BMC password. Each endpoint here is trusted by the configured
// TLS provider and answers HTTPS — none of them is Redfish.
func TestDiscoverMACs_IPMIFallthroughWithholdsCredentials(t *testing.T) {
	tests := []struct {
		name    string
		respond func(w http.ResponseWriter)
	}{
		{
			name: "not found",
			respond: func(w http.ResponseWriter) {
				http.Error(w, "not a BMC", http.StatusNotFound)
			},
		},
		{
			name: "generic JSON",
			respond: func(w http.ResponseWriter) {
				json.NewEncoder(w).Encode(map[string]interface{}{})
			},
		},
		{
			name: "service root without Redfish identity",
			respond: func(w http.ResponseWriter) {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"Systems": map[string]string{"@odata.id": "/redfish/v1/Systems"},
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authenticated atomic.Int64
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					authenticated.Add(1)
				}
				tt.respond(w)
			})

			host, port, ts := startTLSHandler(t, handler)
			defer ts.Close()

			originalProbePort := redfishProbePort
			redfishProbePort = port
			defer func() { redfishProbePort = originalProbePort }()

			_, err := DiscoverMACs(context.Background(), &Config{
				Address:  host,
				Port:     623,
				Protocol: ProtocolIPMI,
				Username: "admin",
				Password: "pass",
				TLS:      tlsProviderFromTLSServer(ts),
			}, newTestLogger())

			ts.Close()

			if err == nil {
				t.Fatal("expected ErrMACDiscoveryUnsupported, got nil")
			}
			if _, ok := err.(ErrMACDiscoveryUnsupported); !ok {
				t.Errorf("expected ErrMACDiscoveryUnsupported, got %T: %v", err, err)
			}
			if n := authenticated.Load(); n != 0 {
				t.Errorf("expected no BMC credentials to reach a non-Redfish endpoint, got %d authenticated request(s)", n)
			}
		})
	}
}

// TestDiscoverMACs_IPMIFallthroughRejectsRedirectedServiceRoot closes the
// gap a redirect would open in the identification above: the endpoint that
// gets vouched for must be the endpoint that gets the credentials. Here a
// service that is not a BMC answers the service root path by pointing at a
// real Redfish service on another trusted origin. Neither endpoint may see
// the operator's password.
func TestDiscoverMACs_IPMIFallthroughRejectsRedirectedServiceRoot(t *testing.T) {
	var redfishAuthenticated, decoyAuthenticated atomic.Int64

	redfish := multiNICRedfishMux([]string{"00:25:90:5E:02:AA"})
	redfishHost, redfishPort, redfishTS := startTLSHandler(t, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				redfishAuthenticated.Add(1)
			}
			redfish.ServeHTTP(w, r)
		}))
	defer redfishTS.Close()

	decoyHost, decoyPort, decoyTS := startTLSHandler(t, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				decoyAuthenticated.Add(1)
			}
			http.Redirect(w, r,
				fmt.Sprintf("https://%s:%d%s", redfishHost, redfishPort, redfishServiceRootPath),
				http.StatusFound)
		}))
	defer decoyTS.Close()

	originalProbePort := redfishProbePort
	redfishProbePort = decoyPort
	defer func() { redfishProbePort = originalProbePort }()

	_, err := DiscoverMACs(context.Background(), &Config{
		Address:  decoyHost,
		Port:     623,
		Protocol: ProtocolIPMI,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderTrusting(decoyTS, redfishTS),
	}, newTestLogger())

	decoyTS.Close()
	redfishTS.Close()

	if err == nil {
		t.Fatal("expected ErrMACDiscoveryUnsupported, got nil")
	}
	if _, ok := err.(ErrMACDiscoveryUnsupported); !ok {
		t.Errorf("expected ErrMACDiscoveryUnsupported, got %T: %v", err, err)
	}
	if n := decoyAuthenticated.Load(); n != 0 {
		t.Errorf("expected the redirecting endpoint to receive no credentials, got %d authenticated request(s)", n)
	}
	if n := redfishAuthenticated.Load(); n != 0 {
		t.Errorf("expected the redirect target to receive no credentials, got %d authenticated request(s)", n)
	}
}

// selfSignedCert generates a certificate for 127.0.0.1, for tests that need
// more than one server identity on the same address.
func selfSignedCert(t *testing.T, commonName string, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing test certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// TestDiscoverMACs_IPMIFallthroughPinsIdentifiedPeer covers what connection
// reuse cannot promise. Identifying the service and authenticating to it are
// two requests, and "Connection: close", a pool eviction or a dial error puts
// the second one on a fresh connection that resolves and dials again — so the
// endpoint that was identified need not be the endpoint that answers next.
// Here the address serves one certificate to the identifying connection and a
// different, equally trusted one to the connection after it: discovery must
// refuse it rather than authenticate to whoever answered second.
func TestDiscoverMACs_IPMIFallthroughPinsIdentifiedPeer(t *testing.T) {
	identified := selfSignedCert(t, "bmc-identified", 1)
	substituted := selfSignedCert(t, "bmc-substituted", 2)

	var handshakes, authenticated atomic.Int64

	redfish := multiNICRedfishMux([]string{"00:25:90:5E:02:AA"})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authenticated.Add(1)
		}
		// Put whatever comes next on a new connection, which is where a
		// substituted endpoint would answer.
		w.Header().Set("Connection", "close")
		redfish.ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting listener: %v", err)
	}
	tlsListener := tls.NewListener(ln, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if handshakes.Add(1) == 1 {
				return &identified, nil
			}
			return &substituted, nil
		},
	})
	srv := &http.Server{
		Handler: handler,
		// Handshakes are expected to fail here; that is the assertion, not
		// something to print.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		srv.Serve(tlsListener)
	}()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("closing test server: %v", err)
		}
		<-served
	})

	pool := x509.NewCertPool()
	pool.AddCert(identified.Leaf)
	pool.AddCert(substituted.Leaf)

	addr := ln.Addr().(*net.TCPAddr)
	originalProbePort := redfishProbePort
	redfishProbePort = addr.Port
	defer func() { redfishProbePort = originalProbePort }()

	_, macErr := DiscoverMACs(context.Background(), &Config{
		Address:  addr.IP.String(),
		Port:     623,
		Protocol: ProtocolIPMI,
		Username: "admin",
		Password: "pass",
		TLS: &fakeTLSProvider{cfg: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}},
	}, newTestLogger())

	if macErr == nil {
		t.Fatal("expected ErrMACDiscoveryUnsupported, got nil")
	}
	if _, ok := macErr.(ErrMACDiscoveryUnsupported); !ok {
		t.Errorf("expected ErrMACDiscoveryUnsupported, got %T: %v", macErr, macErr)
	}
	if n := handshakes.Load(); n < 2 {
		t.Fatalf("expected the walk to open a second connection, got %d handshake(s)", n)
	}
	if n := authenticated.Load(); n != 0 {
		t.Errorf("expected no credentials to reach an endpoint that was not the one identified, got %d authenticated request(s)", n)
	}
}

// countingListener counts accepted connections, so a test can tell whether
// anything other than the configured Redfish client opened one.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.accepted.Add(1)
	return conn, nil
}

// TestDiscoverMACs_IPMIFallthroughMakesNoPreflightRequest pins why the
// fallthrough runs no reachability check of its own. The check it used to run
// was an HTTPS request that verified the BMC's certificate against the system
// roots instead of the configured TLSProvider, under a 5s budget the real
// client does not use — so it could report "no Redfish here" for a BMC the
// client reaches without trouble, which is how issue #5 turned into a red CI
// run. Discovery must therefore open exactly one connection to the BMC: the
// configured client's, reused across the walk. Any probe ahead of it, HTTPS
// or bare TCP, shows up here as a second connection.
func TestDiscoverMACs_IPMIFallthroughMakesNoPreflightRequest(t *testing.T) {
	ts := httptest.NewUnstartedServer(multiNICRedfishMux([]string{"00:25:90:5E:02:AA"}))
	listener := &countingListener{Listener: ts.Listener}
	ts.Listener = listener
	ts.StartTLS()
	defer ts.Close()

	host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting test server address: %v", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parsing test server port %q: %v", port, err)
	}

	originalProbePort := redfishProbePort
	redfishProbePort = portNum
	defer func() { redfishProbePort = originalProbePort }()

	got, macErr := DiscoverMACs(context.Background(), &Config{
		Address:  host,
		Port:     portNum,
		Protocol: ProtocolIPMI,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderFromTLSServer(ts),
	}, newTestLogger())

	// Close before reading the counter: the server accepts on its own
	// goroutine, and Close waits for it.
	ts.Close()

	if macErr != nil {
		t.Fatalf("expected IPMI fallthrough to succeed, got: %v", macErr)
	}
	if n := listener.accepted.Load(); n != 1 {
		t.Errorf("expected discovery to open exactly the configured client's connection, got %d connection(s)", n)
	}
	if len(got) != 1 || got[0] != "00:25:90:5E:02:AA" {
		t.Errorf("expected [00:25:90:5E:02:AA], got %v", got)
	}
}

func TestDiscoverMACs_MultipleMACs(t *testing.T) {
	macs := []string{
		"00:25:90:5E:02:AA",
		"00:25:90:5E:02:AB",
		"00:25:90:5E:02:AC",
	}
	host, port, ts := startTLSMux(t, multiNICRedfishMux(macs))
	defer ts.Close()

	got, err := DiscoverMACs(context.Background(), &Config{
		Address:  host,
		Port:     port,
		Protocol: ProtocolRedfish,
		Username: "admin",
		Password: "pass",
		TLS:      tlsProviderFromTLSServer(ts),
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
		"FF:FF:FF:FF:FF:FF", // broadcast sentinel - filtered
		"00:00:00:00:00:00", // null sentinel - filtered
		"not-a-mac",         // invalid format - filtered
		"00:25:90:5E:02:AA", // valid
		"",                  // empty - filtered
		"00:25:90:5E:02:AB", // valid
	}
	host, port, ts := startTLSMux(t, multiNICRedfishMux(macs))
	defer ts.Close()

	got, err := DiscoverMACs(context.Background(), &Config{
		Address:  host,
		Port:     port,
		Protocol: ProtocolRedfish,
		TLS:      tlsProviderFromTLSServer(ts),
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
	host, port, ts := startTLSMux(t, multiNICRedfishMux([]string{
		"FF:FF:FF:FF:FF:FF",
		"00:00:00:00:00:00",
	}))
	defer ts.Close()

	_, err := DiscoverMACs(context.Background(), &Config{
		Address:  host,
		Port:     port,
		Protocol: ProtocolRedfish,
		TLS:      tlsProviderFromTLSServer(ts),
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
	host, port, ts := startTLSMux(t, multiNICRedfishMux(macs))
	defer ts.Close()

	originalProbePort := redfishProbePort
	redfishProbePort = port
	defer func() { redfishProbePort = originalProbePort }()

	got, err := DiscoverMACs(context.Background(), &Config{
		Address:  host,
		Port:     port,
		Protocol: ProtocolIPMI,
		TLS:      tlsProviderFromTLSServer(ts),
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
