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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
			w.WriteHeader(http.StatusCreated)

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
					"os": map[string]interface{}{
						"hostname": "lab-node-3",
					},
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
	// Override should win.
	if osMap["hostname"] != "lab-node-3" {
		t.Errorf("os.hostname = %v, want lab-node-3 (from override)", osMap["hostname"])
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
			w.WriteHeader(http.StatusCreated)

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
	if osMap["hostname"] != "default-cp" {
		t.Errorf("os.hostname = %v, want default-cp", osMap["hostname"])
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
			w.WriteHeader(http.StatusCreated)

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
