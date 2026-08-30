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
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// TestSeeder_MergedConfig_SentInProfile verifies that the profile request
// contains the MERGED template + override config, not just the overrides.
func TestSeeder_MergedConfig_SentInProfile(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "worker-template.yaml")
	templateContent := `
os:
  hostname: default-host
  timezone: UTC
  packages:
    - base
    - systemd
tpm:
  idevid:
    serial: default-serial
network:
  cidr: "10.0.0.0/24"
`
	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	var receivedProfileConfig map[string]interface{}
	templateUploaded := false
	profileCreated := false

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			templateUploaded = true
			resp := templateResponse{ID: "tmpl-w1"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost:
			profileCreated = true
			var req profileRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode profile request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Parse the merged config from the profile request.
			if req.Config != nil {
				if err := json.Unmarshal(req.Config, &receivedProfileConfig); err != nil {
					t.Errorf("config should be valid JSON: %v", err)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 201, "success": true, "payload": map[string]interface{}{"id": "1"}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleWorker: templatePath,
	}
	cfg.Platform = PlatformGlobalConfig{
		Domain:      "test.io",
		Hostmaster:  "host@test.io",
		TenantID:    "default",
		Environment: "production",
	}

	discovered := []DiscoveredNode{
		{
			NodeConfig: NodeConfig{
				Hostname: "lab-node-3",
				Role:     RoleWorker,
				MACs:     []string{"ac:1f:6b:76:f3:4c"},
				Overrides: map[string]interface{}{
					"tpm": map[string]interface{}{
						"idevid": map[string]interface{}{
							"serial": "lab-node-3-compute-01",
						},
					},
				},
			},
			DiscoveredMACs: []string{"ac:1f:6b:76:f3:4c"},
		},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: server.Listener.Addr().String(),
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	s.client = server.Client()

	err := s.Seed(context.Background())
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	if !templateUploaded {
		t.Error("template should have been uploaded")
	}
	if !profileCreated {
		t.Error("profile should have been created")
	}
	if receivedProfileConfig == nil {
		t.Fatal("profile config should not be nil")
	}

	// Verify the merged config has BOTH base template values and overrides.
	osMap, ok := receivedProfileConfig["os"].(map[string]interface{})
	if !ok {
		t.Fatal("os should be a map in merged config")
	}
	// Node identity injection should win over the template placeholder.
	if osMap["hostname"] != "lab-node-3" {
		t.Errorf("os.hostname = %v, want lab-node-3 (injected from NodeConfig.Hostname)", osMap["hostname"])
	}
	// Base template value should be preserved.
	if osMap["timezone"] != "UTC" {
		t.Errorf("os.timezone = %v, want UTC (from base template)", osMap["timezone"])
	}
	// Packages from base template should be preserved.
	if _, ok := osMap["packages"]; !ok {
		t.Error("os.packages should be preserved from base template")
	}

	// Verify TPM override merged correctly.
	tpmMap, ok := receivedProfileConfig["tpm"].(map[string]interface{})
	if !ok {
		t.Fatal("tpm should be a map in merged config")
	}
	idevidMap, ok := tpmMap["idevid"].(map[string]interface{})
	if !ok {
		t.Fatal("tpm.idevid should be a map")
	}
	if idevidMap["serial"] != "lab-node-3-compute-01" {
		t.Errorf("tpm.idevid.serial = %v, want lab-node-3-compute-01", idevidMap["serial"])
	}

	// Network from base template should be preserved (no override).
	networkMap, ok := receivedProfileConfig["network"].(map[string]interface{})
	if !ok {
		t.Fatal("network should be preserved from base template")
	}
	if networkMap["cidr"] != "10.0.0.0/24" {
		t.Errorf("network.cidr = %v, want 10.0.0.0/24", networkMap["cidr"])
	}
}

// TestSeeder_MergedConfig_NoOverrides verifies that when a node has no
// overrides, the full template is sent as the profile config.
func TestSeeder_MergedConfig_NoOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	templateContent := `
os:
  hostname: default-cp
  timezone: UTC
`
	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	var receivedConfig map[string]interface{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			resp := templateResponse{ID: "tmpl-cp"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost:
			var req profileRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode profile request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if req.Config != nil {
				json.Unmarshal(req.Config, &receivedConfig)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 201, "success": true, "payload": map[string]interface{}{"id": "1"}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, MACs: []string{"aa:01"}},
			DiscoveredMACs: []string{"aa:01"},
			// No Overrides
		},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: server.Listener.Addr().String(),
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	s.client = server.Client()

	err := s.Seed(context.Background())
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	if receivedConfig == nil {
		t.Fatal("profile should contain the full template config even without overrides")
	}
	osMap, ok := receivedConfig["os"].(map[string]interface{})
	if !ok {
		t.Fatal("os should be a map")
	}
	// Node identity injection replaces the template placeholder hostname.
	if osMap["hostname"] != "cp1" {
		t.Errorf("os.hostname = %v, want cp1 (injected from NodeConfig.Hostname)", osMap["hostname"])
	}
	if osMap["timezone"] != "UTC" {
		t.Errorf("os.timezone = %v, want UTC (from base template)", osMap["timezone"])
	}
}

// TestSeeder_MergedConfig_TemplateNotFoundForRole verifies that when no
// template exists for a node's role, the profile config is nil (the
// control plane uses its default).
func TestSeeder_MergedConfig_MissingTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	cpPath := filepath.Join(tmpDir, "cp.yaml")
	if err := os.WriteFile(cpPath, []byte(`{"name":"cp"}`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var profileConfigs []json.RawMessage

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			resp := templateResponse{ID: "tmpl-cp"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost:
			var req profileRequest
			json.NewDecoder(r.Body).Decode(&req)
			profileConfigs = append(profileConfigs, req.Config)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 201, "success": true, "payload": map[string]interface{}{"id": "1"}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: cpPath,
		// No worker template
	}

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
		{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker}, DiscoveredMACs: []string{"aa:02"}},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: server.Listener.Addr().String(),
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	s.client = server.Client()

	err := s.Seed(context.Background())
	if err != nil {
		t.Fatalf("seed should succeed with missing worker template: %v", err)
	}

	// Only cp1 should have created a profile (w1 skipped).
	if len(profileConfigs) != 1 {
		t.Errorf("expected 1 profile, got %d (worker should be skipped)", len(profileConfigs))
	}
}

// TestBuildMergedConfig_InjectsNodeIdentity verifies that buildMergedConfig
// injects the node's authoritative first-class fields (hostname, BMC block,
// static interfaces) into the merged JSON, that the injected tenant key uses
// the device-schema spelling "tenant-id", and that the platform globals
// replace non-empty template placeholders.
func TestBuildMergedConfig_InjectsNodeIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	templateContent := `domain: placeholder.example.com
hostmaster: hostmaster@placeholder.example.com
tenant-id: placeholder-tenant
os:
  hostname: template-host
  timezone: UTC
bmc:
  port: 623
`
	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleControlPlane: templatePath}
	cfg.Platform = PlatformGlobalConfig{
		Domain:      "prod.example.com",
		Hostmaster:  "ops@prod.example.com",
		TenantID:    "tenant-42",
		Environment: "production",
	}

	node := &DiscoveredNode{
		NodeConfig: NodeConfig{
			Hostname:    "cp-01",
			Role:        RoleControlPlane,
			BMCAddress:  "10.200.0.10",
			BMCUser:     "admin",
			BMCPassword: "secret",
			BMCProtocol: "redfish",
			Interfaces: []installer.InterfaceConfig{
				{
					Name:        "eth0",
					Type:        installer.InterfaceTypeStatic,
					IPv4Address: "198.18.1.140/24",
					IPv4Gateway: "198.18.1.1",
				},
			},
		},
	}

	s := NewSeeder(SeederParams{Config: cfg, Logger: orchTestLogger()})
	merged, err := s.buildMergedConfig(node)
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("merged config should be valid JSON: %v", err)
	}

	osMap, ok := got["os"].(map[string]interface{})
	if !ok {
		t.Fatal("os should be a map")
	}
	if osMap["hostname"] != "cp-01" {
		t.Errorf("os.hostname = %v, want cp-01 (injected)", osMap["hostname"])
	}
	if osMap["timezone"] != "UTC" {
		t.Errorf("os.timezone = %v, want UTC (from template)", osMap["timezone"])
	}

	bmcMap, ok := got["bmc"].(map[string]interface{})
	if !ok {
		t.Fatal("bmc should be a map")
	}
	if bmcMap["address"] != "10.200.0.10" {
		t.Errorf("bmc.address = %v, want 10.200.0.10", bmcMap["address"])
	}
	if bmcMap["username"] != "admin" {
		t.Errorf("bmc.username = %v, want admin", bmcMap["username"])
	}
	if bmcMap["password"] != "secret" {
		t.Errorf("bmc.password = %v, want secret", bmcMap["password"])
	}
	if bmcMap["protocol"] != "redfish" {
		t.Errorf("bmc.protocol = %v, want redfish", bmcMap["protocol"])
	}
	// Other bmc keys must be left untouched.
	if bmcMap["port"] != float64(623) {
		t.Errorf("bmc.port = %v, want 623 (untouched template value)", bmcMap["port"])
	}

	netMap, ok := got["network"].(map[string]interface{})
	if !ok {
		t.Fatal("network should be a map after interface injection")
	}
	ifaces, ok := netMap["interfaces"].([]interface{})
	if !ok || len(ifaces) != 1 {
		t.Fatalf("network.interfaces = %v, want 1 injected interface", netMap["interfaces"])
	}
	iface, ok := ifaces[0].(map[string]interface{})
	if !ok {
		t.Fatal("injected interface should be a map")
	}
	if iface["name"] != "eth0" {
		t.Errorf("interface name = %v, want eth0", iface["name"])
	}
	if iface["type"] != "static" {
		t.Errorf("interface type = %v, want static", iface["type"])
	}
	if iface["ipv4-address"] != "198.18.1.140/24" {
		t.Errorf("interface ipv4-address = %v, want 198.18.1.140/24 (YAML-tag key)", iface["ipv4-address"])
	}
	if iface["ipv4-gateway"] != "198.18.1.1" {
		t.Errorf("interface ipv4-gateway = %v, want 198.18.1.1", iface["ipv4-gateway"])
	}

	// The injected tenant key must use the device-schema spelling.
	if got["tenant-id"] != "tenant-42" {
		t.Errorf("tenant-id = %v, want tenant-42", got["tenant-id"])
	}
	if _, exists := got["tenant_id"]; exists {
		t.Error("merged config must not contain the legacy tenant_id key")
	}
	// Platform globals replace non-empty template placeholders.
	if got["domain"] != "prod.example.com" {
		t.Errorf("domain = %v, want prod.example.com (platform global overwrites placeholder)", got["domain"])
	}
	if got["hostmaster"] != "ops@prod.example.com" {
		t.Errorf("hostmaster = %v, want ops@prod.example.com", got["hostmaster"])
	}
	if got["environment"] != "production" {
		t.Errorf("environment = %v, want production", got["environment"])
	}
}

// TestBuildMergedConfig_OverrideBeatsGlobalIdentity locks the precedence
// chain template -> platform global -> per-node override: an identity
// override differing from the platform global must survive the merge.
func TestBuildMergedConfig_OverrideBeatsGlobalIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "gw-template.yaml")
	if err := os.WriteFile(templatePath, []byte("domain: placeholder.example.com\n"), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleGateway: templatePath}
	cfg.Platform = PlatformGlobalConfig{Domain: "prod.example.com"}

	node := &DiscoveredNode{
		NodeConfig: NodeConfig{
			Hostname: "gw-01",
			Role:     RoleGateway,
			Overrides: map[string]interface{}{
				"domain": "gw.trusted-platform.io",
			},
		},
	}

	s := NewSeeder(SeederParams{Config: cfg, Logger: orchTestLogger()})
	merged, err := s.buildMergedConfig(node)
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("merged config should be valid JSON: %v", err)
	}
	if got["domain"] != "gw.trusted-platform.io" {
		t.Errorf("domain = %v, want gw.trusted-platform.io (per-node override wins)", got["domain"])
	}
}

// TestBuildMergedConfig_IdentityCollision verifies that a non-map value
// under an injected key surfaces as ErrTemplateMergeFailed wrapping the
// typed collision error rather than being silently clobbered.
func TestBuildMergedConfig_IdentityCollision(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte("os: not-a-map\n"), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleControlPlane: templatePath}

	node := &DiscoveredNode{
		NodeConfig: NodeConfig{Hostname: "cp-01", Role: RoleControlPlane},
	}

	s := NewSeeder(SeederParams{Config: cfg, Logger: orchTestLogger()})
	_, err := s.buildMergedConfig(node)
	if err == nil {
		t.Fatal("expected error for non-map os value")
	}
	var mergeErr ErrTemplateMergeFailed
	if !errors.As(err, &mergeErr) {
		t.Fatalf("expected ErrTemplateMergeFailed, got %T: %v", err, err)
	}
	var collision ErrConfigKeyNotMap
	if !errors.As(err, &collision) {
		t.Fatalf("expected wrapped ErrConfigKeyNotMap, got %v", err)
	}
	if collision.Key != "os" {
		t.Errorf("collision key = %q, want os", collision.Key)
	}
}
