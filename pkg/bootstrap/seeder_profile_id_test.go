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
)

// --- parseProfileIDFromResponse unit tests ---

func TestParseProfileIDFromResponse_EnvelopedString(t *testing.T) {
	// Standard REST envelope: {code, success, payload: {id: "1234567890123456"}}
	body := []byte(`{"code":201,"success":true,"payload":{"id":"1234567890123456"}}`)
	id, err := parseProfileIDFromResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 1234567890123456 {
		t.Errorf("expected id 1234567890123456, got %d", id)
	}
}

func TestParseProfileIDFromResponse_DirectString(t *testing.T) {
	// Direct (non-enveloped) shape: {id: "42"}
	body := []byte(`{"id":"42"}`)
	id, err := parseProfileIDFromResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 42 {
		t.Errorf("expected id 42, got %d", id)
	}
}

func TestParseProfileIDFromResponse_LargeUint64(t *testing.T) {
	// Verify that uint64 values above 2^53 round-trip correctly via string.
	const maxSafe = uint64(1<<63 - 1)
	body := []byte(`{"code":201,"success":true,"payload":{"id":"9223372036854775807"}}`)
	id, err := parseProfileIDFromResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != maxSafe {
		t.Errorf("expected %d, got %d", maxSafe, id)
	}
}

func TestParseProfileIDFromResponse_MalformedJSON(t *testing.T) {
	body := []byte(`not valid json`)
	_, err := parseProfileIDFromResponse(body)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseProfileIDFromResponse_EmptyIDField(t *testing.T) {
	// The envelope parses OK but both payload.id and direct id are missing.
	body := []byte(`{"code":201,"success":true,"payload":{}}`)
	_, err := parseProfileIDFromResponse(body)
	if err == nil {
		t.Fatal("expected error for empty id field")
	}
}

func TestParseProfileIDFromResponse_InvalidIDString(t *testing.T) {
	// id is present but not a valid uint64.
	body := []byte(`{"code":201,"success":true,"payload":{"id":"not-a-number"}}`)
	_, err := parseProfileIDFromResponse(body)
	if err == nil {
		t.Fatal("expected error for non-numeric id string")
	}
}

// --- Seeder.ProfileIDs accessor tests ---

func TestSeeder_ProfileIDs_EmptyBeforeSeed(t *testing.T) {
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:8443",
		Config:           minimalConfig(),
		Discovered:       []DiscoveredNode{},
		Logger:           orchTestLogger(),
		CPCAPool:         x509.NewCertPool(),
	})
	ids := s.ProfileIDs()
	if len(ids) != 0 {
		t.Errorf("expected empty map before seed, got %v", ids)
	}
}

func TestSeeder_ProfileIDs_PopulatedAfterSeed(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte(`{"name":"cp"}`), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	const assignedID = uint64(999000111222333)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			resp := templateResponse{ID: "tmpl-001"}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"payload": resp,
			})

		case r.Method == http.MethodPost:
			// create-profile: return enveloped ProfileFullResponse with id as string.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    201,
				"success": true,
				"payload": map[string]interface{}{
					"id": "999000111222333",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleControlPlane: templatePath}

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

	if err := s.Seed(context.Background()); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	ids := s.ProfileIDs()
	if len(ids) != 1 {
		t.Fatalf("expected 1 profile ID, got %d", len(ids))
	}
	if ids["cp1"] != assignedID {
		t.Errorf("expected profile ID %d for cp1, got %d", assignedID, ids["cp1"])
	}
}

func TestSeeder_ProfileIDs_MalformedResponseIsError(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte(`{"name":"cp"}`), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/devices/templates" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"payload": templateResponse{ID: "tmpl-001"},
			})

		case r.Method == http.MethodPost:
			// Return 201 but a body where id is missing entirely.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"code":201,"success":true,"payload":{"name":"cp1-profile"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleControlPlane: templatePath}

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
	if err == nil {
		t.Fatal("expected error for missing profile ID in response")
	}

	var seedErr ErrSeedFailed
	if !errors.As(err, &seedErr) {
		t.Fatalf("expected ErrSeedFailed, got %T: %v", err, err)
	}

	var idErr ErrProfileIDParseFailed
	if !errors.As(seedErr.Cause, &idErr) {
		t.Fatalf("expected ErrProfileIDParseFailed in cause chain, got %T: %v", seedErr.Cause, seedErr.Cause)
	}
	if idErr.Hostname != "cp1" {
		t.Errorf("expected hostname cp1, got %s", idErr.Hostname)
	}
}
