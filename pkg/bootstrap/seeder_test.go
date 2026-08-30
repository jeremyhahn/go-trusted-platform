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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- NewSeeder tests ---

func TestNewSeeder_Valid(t *testing.T) {
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:8443",
		Config:           minimalConfig(),
		Discovered:       []DiscoveredNode{},
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	if s == nil {
		t.Fatal("seeder should not be nil")
	}
	if s.controlPlaneAddr != "127.0.0.1:8443" {
		t.Errorf("expected addr 127.0.0.1:8443, got %s", s.controlPlaneAddr)
	}
	if s.client == nil {
		t.Error("HTTP client should be initialized")
	}
}

func TestNewSeeder_DefaultLogger(t *testing.T) {
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:8443",
		Config:           minimalConfig(),
		Logger:           nil,
		CPCAPool:         x509.NewCertPool(),
	})
	if s.logger == nil {
		t.Fatal("logger should default when nil")
	}
}

func TestNewSeeder_MissingAddr(t *testing.T) {
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "",
		Config:           minimalConfig(),
		Discovered:       []DiscoveredNode{},
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})

	ctx := context.Background()
	err := s.Seed(ctx)
	if err == nil {
		t.Fatal("expected error for empty address")
	}
	var target ErrMissingSeederAddr
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrMissingSeederAddr, got %T: %v", err, err)
	}
}

// --- Seed tests ---

func TestSeeder_Seed(t *testing.T) {
	// Create a temp template file.
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	templateContent := `{"name": "control-plane-template", "version": "1.0"}`
	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	// Track server calls.
	templateCalls := 0
	profileCalls := 0

	// Mock control plane server.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			templateCalls++
			resp := templateResponse{ID: "tmpl-001"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && len(r.URL.Path) > len("/api/v1/devices/templates/"):
			profileCalls++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 201, "success": true, "payload": map[string]interface{}{"id": "1"}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := server.Listener.Addr().String()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, MACs: []string{"aa:bb:cc:dd:ee:01"}},
			DiscoveredMACs: []string{"aa:bb:cc:dd:ee:01"},
		},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: addr,
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	// Use the test server's TLS client.
	s.client = server.Client()

	ctx := context.Background()
	err := s.Seed(ctx)
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	if templateCalls != 1 {
		t.Errorf("expected 1 template upload, got %d", templateCalls)
	}
	if profileCalls != 1 {
		t.Errorf("expected 1 profile create, got %d", profileCalls)
	}
}

func TestSeeder_Seed_YAMLWithComments(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")

	// Write a real YAML template with comments -- this is the exact scenario
	// that triggered the original bug (json.RawMessage rejecting '#').
	yamlContent := `# Control-plane device template
name: control-plane-template
version: "2.0"
# Network configuration
network:
  cidr: "10.0.0.0/24"  # management network
  gateway: "10.0.0.1"
`
	if err := os.WriteFile(templatePath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	var receivedTemplate map[string]interface{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			var req templateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Verify the template is valid JSON without comments.
			if err := json.Unmarshal(req.Template, &receivedTemplate); err != nil {
				t.Errorf("template should be valid JSON: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resp := templateResponse{ID: "tmpl-yaml-001"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost:
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
		t.Fatalf("seed with YAML comments should succeed, got: %v", err)
	}

	// Verify the parsed content is correct (comments stripped, values preserved).
	if receivedTemplate == nil {
		t.Fatal("server should have received a valid template")
	}
	if receivedTemplate["name"] != "control-plane-template" {
		t.Errorf("expected name 'control-plane-template', got %v", receivedTemplate["name"])
	}
	if receivedTemplate["version"] != "2.0" {
		t.Errorf("expected version '2.0', got %v", receivedTemplate["version"])
	}
	network, ok := receivedTemplate["network"].(map[string]interface{})
	if !ok {
		t.Fatal("expected network to be a map")
	}
	if network["cidr"] != "10.0.0.0/24" {
		t.Errorf("expected cidr '10.0.0.0/24', got %v", network["cidr"])
	}
}

func TestSeeder_Seed_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "bad-template.yaml")

	// Write invalid YAML (tabs in wrong places, unbalanced quotes).
	invalidYAML := `name: "unclosed
  - broken: [
`
	if err := os.WriteFile(templatePath, []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, MACs: []string{"aa:01"}},
			DiscoveredMACs: []string{"aa:01"},
		},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:9999",
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})

	err := s.Seed(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid YAML template")
	}

	var seedErr ErrSeedFailed
	if !errors.As(err, &seedErr) {
		t.Fatalf("expected ErrSeedFailed, got %T: %v", err, err)
	}

	var yamlErr ErrTemplateYAMLParseFailed
	if !errors.As(seedErr.Cause, &yamlErr) {
		t.Fatalf("expected ErrTemplateYAMLParseFailed in cause, got %T: %v", seedErr.Cause, seedErr.Cause)
	}
	if yamlErr.Role != RoleControlPlane {
		t.Errorf("expected role control-plane, got %s", yamlErr.Role)
	}
}

func TestSeeder_Seed_MultipleRoles(t *testing.T) {
	tmpDir := t.TempDir()

	roles := []string{RoleControlPlane, RoleGateway, RoleWorker}
	templates := make(map[string]string)
	for _, role := range roles {
		path := filepath.Join(tmpDir, role+"-template.yaml")
		content := `{"name": "` + role + `-template"}`
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write template: %v", err)
		}
		templates[role] = path
	}

	templateIDs := map[string]string{
		RoleControlPlane: "tmpl-cp",
		RoleGateway:      "tmpl-gw",
		RoleWorker:       "tmpl-wk",
	}

	templateCalls := 0
	profileCalls := 0

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			var req templateRequest
			json.NewDecoder(r.Body).Decode(&req)
			templateCalls++
			resp := templateResponse{ID: templateIDs[req.Role]}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost:
			profileCalls++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 201, "success": true, "payload": map[string]interface{}{"id": "1"}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = templates

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
		{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}, DiscoveredMACs: []string{"aa:02"}},
		{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker}, DiscoveredMACs: []string{"aa:03"}},
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
	if templateCalls != 3 {
		t.Errorf("expected 3 template uploads, got %d", templateCalls)
	}
	if profileCalls != 3 {
		t.Errorf("expected 3 profile creates, got %d", profileCalls)
	}
}

func TestSeeder_Seed_TemplateNotFound(t *testing.T) {
	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: "/nonexistent/template.yaml",
	}

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:9999",
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})

	err := s.Seed(context.Background())
	if err == nil {
		t.Fatal("expected error for missing template file")
	}

	var seedErr ErrSeedFailed
	if !errors.As(err, &seedErr) {
		t.Fatalf("expected ErrSeedFailed, got %T: %v", err, err)
	}

	var fileErr ErrTemplateFileNotFound
	if !errors.As(seedErr.Cause, &fileErr) {
		t.Fatalf("expected ErrTemplateFileNotFound in cause, got %T: %v", seedErr.Cause, seedErr.Cause)
	}
	if fileErr.Role != RoleControlPlane {
		t.Errorf("expected role control-plane, got %s", fileErr.Role)
	}
}

func TestSeeder_Seed_ControlPlaneUnreachable(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
	}

	// Use an unreachable address.
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:1",
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})

	err := s.Seed(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable control plane")
	}

	var seedErr ErrSeedFailed
	if !errors.As(err, &seedErr) {
		t.Fatalf("expected ErrSeedFailed, got %T: %v", err, err)
	}

	var uploadErr ErrTemplateUploadFailed
	if !errors.As(seedErr.Cause, &uploadErr) {
		t.Fatalf("expected ErrTemplateUploadFailed in cause, got %T: %v", seedErr.Cause, seedErr.Cause)
	}
}

func TestSeeder_Seed_TemplateUploadServerError(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
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
	if err == nil {
		t.Fatal("expected error for server error response")
	}

	var seedErr ErrSeedFailed
	if !errors.As(err, &seedErr) {
		t.Fatalf("expected ErrSeedFailed, got %T: %v", err, err)
	}

	var uploadErr ErrTemplateUploadFailed
	if !errors.As(seedErr.Cause, &uploadErr) {
		t.Fatalf("expected ErrTemplateUploadFailed in cause, got %T: %v", seedErr.Cause, seedErr.Cause)
	}
	if uploadErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", uploadErr.StatusCode)
	}
}

func TestSeeder_Seed_ProfileCreateServerError(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			resp := templateResponse{ID: "tmpl-001"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)
		default:
			// Profile create returns 500.
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
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
	if err == nil {
		t.Fatal("expected error for profile create failure")
	}

	var seedErr ErrSeedFailed
	if !errors.As(err, &seedErr) {
		t.Fatalf("expected ErrSeedFailed, got %T: %v", err, err)
	}

	var profileErr ErrProfileCreateFailed
	if !errors.As(seedErr.Cause, &profileErr) {
		t.Fatalf("expected ErrProfileCreateFailed in cause, got %T: %v", seedErr.Cause, seedErr.Cause)
	}
	if profileErr.Hostname != "cp1" {
		t.Errorf("expected hostname cp1, got %s", profileErr.Hostname)
	}
}

func TestSeeder_Seed_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write template: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: templatePath,
	}

	discovered := []DiscoveredNode{
		{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}, DiscoveredMACs: []string{"aa:01"}},
	}

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: server.Listener.Addr().String(),
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	s.client = server.Client()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := s.Seed(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// --- Seeder error type tests ---

func TestSeederErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrSeedFailed with cause",
			err:  ErrSeedFailed{Cause: errors.New("boom")},
			want: "bootstrap: template seeding failed: boom",
		},
		{
			name: "ErrSeedFailed without cause",
			err:  ErrSeedFailed{},
			want: "bootstrap: template seeding failed",
		},
		{
			name: "ErrMissingSeederAddr",
			err:  ErrMissingSeederAddr{},
			want: "bootstrap: seeder control plane address cannot be empty",
		},
		{
			name: "ErrTemplateFileNotFound",
			err:  ErrTemplateFileNotFound{Role: "worker", Path: "/tmp/missing.yaml"},
			want: "bootstrap: template file not found for role worker: /tmp/missing.yaml",
		},
		{
			name: "ErrTemplateUploadFailed with status",
			err:  ErrTemplateUploadFailed{Role: "worker", StatusCode: 500},
			want: "bootstrap: template upload failed for role worker (status=500)",
		},
		{
			name: "ErrTemplateUploadFailed with cause",
			err:  ErrTemplateUploadFailed{Role: "worker", Cause: errors.New("conn refused")},
			want: "bootstrap: template upload failed for role worker (status=0): conn refused",
		},
		{
			name: "ErrProfileCreateFailed with status",
			err:  ErrProfileCreateFailed{Hostname: "cp1", StatusCode: 409},
			want: "bootstrap: profile creation failed for cp1 (status=409)",
		},
		{
			name: "ErrProfileCreateFailed with cause",
			err:  ErrProfileCreateFailed{Hostname: "cp1", Cause: errors.New("timeout")},
			want: "bootstrap: profile creation failed for cp1 (status=0): timeout",
		},
		{
			name: "ErrTemplateYAMLParseFailed with cause",
			err:  ErrTemplateYAMLParseFailed{Role: "worker", Path: "/tmp/bad.yaml", Cause: errors.New("yaml: line 5: found character that cannot start any token")},
			want: "bootstrap: failed to parse template YAML for role worker at /tmp/bad.yaml: yaml: line 5: found character that cannot start any token",
		},
		{
			name: "ErrTemplateYAMLParseFailed without cause",
			err:  ErrTemplateYAMLParseFailed{Role: "worker", Path: "/tmp/bad.yaml"},
			want: "bootstrap: failed to parse template YAML for role worker at /tmp/bad.yaml",
		},
		{
			name: "ErrTemplateJSONConvertFailed with cause",
			err:  ErrTemplateJSONConvertFailed{Role: "gateway", Cause: errors.New("unsupported type")},
			want: "bootstrap: failed to convert template to JSON for role gateway: unsupported type",
		},
		{
			name: "ErrTemplateJSONConvertFailed without cause",
			err:  ErrTemplateJSONConvertFailed{Role: "gateway"},
			want: "bootstrap: failed to convert template to JSON for role gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeederErrors_Unwrap(t *testing.T) {
	cause := errors.New("root cause")

	tests := []struct {
		name string
		err  error
	}{
		{"ErrSeedFailed", ErrSeedFailed{Cause: cause}},
		{"ErrTemplateUploadFailed", ErrTemplateUploadFailed{Cause: cause}},
		{"ErrProfileCreateFailed", ErrProfileCreateFailed{Cause: cause}},
		{"ErrTemplateYAMLParseFailed", ErrTemplateYAMLParseFailed{Cause: cause}},
		{"ErrTemplateJSONConvertFailed", ErrTemplateJSONConvertFailed{Cause: cause}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, cause) {
				t.Error("Unwrap should return root cause")
			}
		})
	}
}

func TestSeeder_Seed_NoTemplatesNoDiscoveredNodes(t *testing.T) {
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:8443",
		Config: &BootstrapConfig{
			Templates: map[string]string{},
		},
		Discovered: []DiscoveredNode{},
		Logger:     slog.Default(),
		CPCAPool:   x509.NewCertPool(),
	})

	err := s.Seed(context.Background())
	if err != nil {
		t.Fatalf("seed with empty data should succeed, got: %v", err)
	}
}

func TestSeeder_Seed_SkipsNodeWithNoTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	cpPath := filepath.Join(tmpDir, "cp.yaml")
	if err := os.WriteFile(cpPath, []byte(`{"name":"cp"}`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			resp := templateResponse{ID: "tmpl-cp"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost:
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
		t.Fatalf("seed should succeed (skip unmatched nodes), got: %v", err)
	}
}

// --- yamlToJSON unit tests ---

func TestYamlToJSON_ValidYAML(t *testing.T) {
	input := []byte("name: test\nversion: \"1.0\"\n")
	result, err := yamlToJSON(input, "test-role", "/tmp/test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result should be valid JSON: %v", err)
	}
	if parsed["name"] != "test" {
		t.Errorf("expected name 'test', got %v", parsed["name"])
	}
}

func TestYamlToJSON_WithComments(t *testing.T) {
	input := []byte("# top comment\nname: test # inline comment\n# trailing comment\n")
	result, err := yamlToJSON(input, "test-role", "/tmp/test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result should be valid JSON: %v", err)
	}
	if parsed["name"] != "test" {
		t.Errorf("expected name 'test', got %v", parsed["name"])
	}
}

func TestYamlToJSON_InvalidYAML(t *testing.T) {
	input := []byte("name: \"unclosed\n  - broken: [\n")
	_, err := yamlToJSON(input, "bad-role", "/tmp/bad.yaml")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}

	var yamlErr ErrTemplateYAMLParseFailed
	if !errors.As(err, &yamlErr) {
		t.Fatalf("expected ErrTemplateYAMLParseFailed, got %T: %v", err, err)
	}
	if yamlErr.Role != "bad-role" {
		t.Errorf("expected role 'bad-role', got %s", yamlErr.Role)
	}
}

func TestYamlToJSON_JSONInput(t *testing.T) {
	// Valid JSON is also valid YAML, so this should pass through cleanly.
	input := []byte(`{"name": "test", "count": 42}`)
	result, err := yamlToJSON(input, "json-role", "/tmp/test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result should be valid JSON: %v", err)
	}
	if parsed["name"] != "test" {
		t.Errorf("expected name 'test', got %v", parsed["name"])
	}
}
