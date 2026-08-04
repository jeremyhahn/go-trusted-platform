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

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// --- hasBMCEnrollNodes tests ---

func TestOrchestrator_HasBMCEnrollNodes_None(t *testing.T) {
	o := &Orchestrator{
		discovered: []DiscoveredNode{
			{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane}},
			{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}},
		},
	}
	if o.hasBMCEnrollNodes() {
		t.Error("expected hasBMCEnrollNodes to return false when no nodes have BMCEnroll=true")
	}
}

func TestOrchestrator_HasBMCEnrollNodes_Some(t *testing.T) {
	o := &Orchestrator{
		discovered: []DiscoveredNode{
			{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true}},
			{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway, BMCEnroll: false}},
		},
	}
	if !o.hasBMCEnrollNodes() {
		t.Error("expected hasBMCEnrollNodes to return true when at least one node has BMCEnroll=true")
	}
}

// --- doEnrollRequest tests ---

func TestOrchestrator_DoEnrollRequest_Success(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    200,
			"success": true,
			"payload": map[string]interface{}{
				"device_id":         "123456",
				"factory_cert_pem":  "-----BEGIN CERTIFICATE-----\nMIIBIjANBg==\n-----END CERTIFICATE-----\n",
				"factory_cert_meta": json.RawMessage(`{"subject":"CN=BMC","issuer":"CN=Factory CA"}`),
			},
		})
	}))
	defer server.Close()

	o := &Orchestrator{
		logger: orchTestLogger(),
		config: minimalConfig(),
	}

	resp, err := o.doEnrollRequest(context.Background(), server.Client(), server.Listener.Addr().String(), 999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.FactoryCertPEM == "" {
		t.Error("expected factory_cert_pem in response")
	}
}

func TestOrchestrator_DoEnrollRequest_NonSuccessStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`profile not found`))
	}))
	defer server.Close()

	o := &Orchestrator{
		logger: orchTestLogger(),
		config: minimalConfig(),
	}

	_, err := o.doEnrollRequest(context.Background(), server.Client(), server.Listener.Addr().String(), 42)
	if err == nil {
		t.Fatal("expected error for non-2xx status")
	}
}

// --- writeBMCEnrollBackups tests ---

func TestWriteBMCEnrollBackups_FullResponse(t *testing.T) {
	dir := t.TempDir()

	resp := &enrollResponse{
		DeviceID:        12345,
		FactoryCertPEM:  "-----BEGIN CERTIFICATE-----\nMIIBIjANBg==\n-----END CERTIFICATE-----\n",
		FactoryCertMeta: json.RawMessage(`{"subject":"CN=BMC","issuer":"CN=Factory CA"}`),
	}

	if err := writeBMCEnrollBackups(dir, "lab-node-1", resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	backupDir := filepath.Join(dir, "lab-node-1", "bmc")

	// Verify factory-cert.pem.
	pemData, err := os.ReadFile(filepath.Join(backupDir, "factory-cert.pem"))
	if err != nil {
		t.Fatalf("factory-cert.pem not written: %v", err)
	}
	if string(pemData) != resp.FactoryCertPEM {
		t.Errorf("factory-cert.pem content mismatch")
	}

	// Verify factory-cert.json.
	metaData, err := os.ReadFile(filepath.Join(backupDir, "factory-cert.json"))
	if err != nil {
		t.Fatalf("factory-cert.json not written: %v", err)
	}
	if string(metaData) != string(resp.FactoryCertMeta) {
		t.Errorf("factory-cert.json content mismatch")
	}

	// Verify enrollment.json exists.
	enrollData, err := os.ReadFile(filepath.Join(backupDir, "enrollment.json"))
	if err != nil {
		t.Fatalf("enrollment.json not written: %v", err)
	}
	var roundTrip enrollResponse
	if err := json.Unmarshal(enrollData, &roundTrip); err != nil {
		t.Fatalf("enrollment.json is not valid JSON: %v", err)
	}

	// Verify file permissions.
	for _, name := range []string{"factory-cert.pem", "factory-cert.json", "enrollment.json"} {
		info, err := os.Stat(filepath.Join(backupDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != bmcBackupFileMode {
			t.Errorf("%s: expected permissions %o, got %o", name, bmcBackupFileMode, perm)
		}
	}

	// Verify directory permissions.
	info, err := os.Stat(backupDir)
	if err != nil {
		t.Fatalf("stat backup dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != bmcBackupDirMode {
		t.Errorf("backup dir: expected permissions %o, got %o", bmcBackupDirMode, perm)
	}
}

func TestWriteBMCEnrollBackups_NilResponse(t *testing.T) {
	dir := t.TempDir()
	// Should be a no-op.
	if err := writeBMCEnrollBackups(dir, "lab-node-1", nil); err != nil {
		t.Fatalf("nil response should be a no-op, got: %v", err)
	}
}

func TestWriteBMCEnrollBackups_NoPEM(t *testing.T) {
	dir := t.TempDir()
	resp := &enrollResponse{
		DeviceID: 1,
		// FactoryCertPEM is empty — no pem file should be written.
	}
	if err := writeBMCEnrollBackups(dir, "lab-node-2", resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	backupDir := filepath.Join(dir, "lab-node-2", "bmc")
	if _, err := os.Stat(filepath.Join(backupDir, "factory-cert.pem")); !os.IsNotExist(err) {
		t.Error("factory-cert.pem should not exist when FactoryCertPEM is empty")
	}
	// enrollment.json should still be written.
	if _, err := os.Stat(filepath.Join(backupDir, "enrollment.json")); err != nil {
		t.Errorf("enrollment.json should be written: %v", err)
	}
}

// --- runBMCEnroll integration-style tests (httptest, no real CP) ---

func TestOrchestrator_RunBMCEnroll_Success(t *testing.T) {
	// Set up a fake control-plane server that handles enroll.
	enrolled := make([]uint64, 0)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Record whatever profile ID was in the path.
			var pathID uint64
			// path is /api/v1/bmc/<id>/enroll
			parts := []byte(r.URL.Path)
			_ = parts
			enrolled = append(enrolled, pathID)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    200,
				"success": true,
				"payload": map[string]interface{}{
					"device_id":         "999",
					"factory_cert_pem":  "PEM",
					"factory_cert_meta": json.RawMessage(`{"subject":"CN=BMC"}`),
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	o := &Orchestrator{
		logger: orchTestLogger(),
		config: &BootstrapConfig{
			Deployer:   DeployerConfig{Host: server.Listener.Addr().String()},
			BackupsDir: tmpDir,
			Nodes: []NodeConfig{
				{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true},
			},
		},
		discovered: []DiscoveredNode{
			{
				NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true},
				DiscoveredMACs: []string{"aa:01"},
			},
		},
	}

	// Build a seeder with the test server's client, pre-populate profile IDs.
	// Use the server's address as the seeder's controlPlaneAddr so runBMCEnroll
	// sends the enroll POST to the test server instead of trying to reach "cp1:8443".
	seeder := &Seeder{
		client:           server.Client(),
		controlPlaneAddr: server.Listener.Addr().String(),
		profileIDs:       map[string]uint64{"cp1": 77777},
	}

	result := &BootstrapResult{}
	o.runBMCEnroll(context.Background(), result, seeder)

	if len(result.BMCEnrollments) != 1 {
		t.Fatalf("expected 1 enrollment outcome, got %d", len(result.BMCEnrollments))
	}
	out := result.BMCEnrollments[0]
	if out.Hostname != "cp1" {
		t.Errorf("expected hostname cp1, got %s", out.Hostname)
	}
	if out.ProfileID != 77777 {
		t.Errorf("expected profile ID 77777, got %d", out.ProfileID)
	}
	if !out.OK {
		t.Errorf("expected OK=true, got detail: %s", out.Detail)
	}

	// Verify backup artifacts were written.
	backupDir := filepath.Join(tmpDir, "cp1", "bmc")
	if _, err := os.Stat(filepath.Join(backupDir, "enrollment.json")); err != nil {
		t.Errorf("enrollment.json should be written: %v", err)
	}
}

func TestOrchestrator_RunBMCEnroll_PerNodeFailureNonFatal(t *testing.T) {
	// Server returns 500 for the enroll endpoint.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	o := &Orchestrator{
		logger: orchTestLogger(),
		config: &BootstrapConfig{
			Deployer: DeployerConfig{Host: server.Listener.Addr().String()},
			Nodes: []NodeConfig{
				{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true},
			},
		},
		discovered: []DiscoveredNode{
			{
				NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true},
				DiscoveredMACs: []string{"aa:01"},
			},
		},
	}

	seeder := &Seeder{
		client:           server.Client(),
		controlPlaneAddr: server.Listener.Addr().String(),
		profileIDs:       map[string]uint64{"cp1": 42},
	}

	result := &BootstrapResult{}
	// runBMCEnroll must not panic or return an error — it's non-fatal.
	o.runBMCEnroll(context.Background(), result, seeder)

	if len(result.BMCEnrollments) != 1 {
		t.Fatalf("expected 1 enrollment outcome, got %d", len(result.BMCEnrollments))
	}
	out := result.BMCEnrollments[0]
	if out.OK {
		t.Error("expected OK=false for 500 response")
	}
	if out.Detail == "" {
		t.Error("expected non-empty Detail for failed enrollment")
	}
}

func TestOrchestrator_RunBMCEnroll_SkipWhenNoneFlagged(t *testing.T) {
	// No node has BMCEnroll=true: runBMCEnroll should add zero outcomes.
	o := &Orchestrator{
		logger: orchTestLogger(),
		config: minimalConfig(),
		discovered: []DiscoveredNode{
			{NodeConfig: NodeConfig{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: false}},
		},
	}

	result := &BootstrapResult{}
	// Call runBMCEnroll directly: hasBMCEnrollNodes would be false so Run()
	// never calls this, but if somehow called it should be a no-op.
	seeder := &Seeder{
		controlPlaneAddr: "127.0.0.1:8443",
		profileIDs:       map[string]uint64{},
	}
	o.runBMCEnroll(context.Background(), result, seeder)

	// No outcomes added because BMCEnroll is false on the only node.
	if len(result.BMCEnrollments) != 0 {
		t.Errorf("expected 0 enrollment outcomes, got %d", len(result.BMCEnrollments))
	}
}

func TestOrchestrator_RunBMCEnroll_MissingProfileID(t *testing.T) {
	// Profile ID not in seeder map (e.g. seed phase skipped the node).
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &Orchestrator{
		logger: orchTestLogger(),
		config: &BootstrapConfig{
			Deployer: DeployerConfig{Host: server.Listener.Addr().String()},
			Nodes: []NodeConfig{
				{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true},
			},
		},
		discovered: []DiscoveredNode{
			{
				NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, BMCEnroll: true},
				DiscoveredMACs: []string{"aa:01"},
			},
		},
	}

	// Empty profile map: cp1 has no ID.
	seeder := &Seeder{
		client:           server.Client(),
		controlPlaneAddr: server.Listener.Addr().String(),
		profileIDs:       map[string]uint64{},
	}

	result := &BootstrapResult{}
	o.runBMCEnroll(context.Background(), result, seeder)

	if len(result.BMCEnrollments) != 1 {
		t.Fatalf("expected 1 outcome, got %d", len(result.BMCEnrollments))
	}
	out := result.BMCEnrollments[0]
	if out.OK {
		t.Error("expected OK=false when profile ID is missing")
	}
	if out.ProfileID != 0 {
		t.Errorf("expected ProfileID 0 for missing entry, got %d", out.ProfileID)
	}
}

// --- End-to-end Run with bmc-enroll phase (no-op when no bmc_enroll flags) ---

func TestOrchestrator_Run_BMCEnrollPhase_Skipped(t *testing.T) {
	// When no node has bmc_enroll: true, the bmc-enroll phase should be skipped
	// and BMCEnrollments should be nil/empty.
	cfg := minimalConfig()
	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := o.Run(context.Background())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if len(result.BMCEnrollments) != 0 {
		t.Errorf("expected empty BMCEnrollments when no nodes have bmc_enroll, got %d", len(result.BMCEnrollments))
	}
}

// --- ErrBMCEnrollFailed tests ---

func TestErrBMCEnrollFailed_WithCause(t *testing.T) {
	cause := &ErrBMCEnrollFailed{Cause: errEmptyProfileID{}}
	want := "bootstrap: bmc enrollment failed: profile ID is empty in create-profile response"
	if got := cause.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if cause.Unwrap() == nil {
		t.Error("Unwrap should return non-nil cause")
	}
}

func TestErrBMCEnrollFailed_NoCause(t *testing.T) {
	e := ErrBMCEnrollFailed{}
	want := "bootstrap: bmc enrollment failed"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// --- ErrProfileIDParseFailed tests ---

func TestErrProfileIDParseFailed_WithCause(t *testing.T) {
	e := ErrProfileIDParseFailed{Hostname: "cp1", Cause: errEmptyProfileID{}}
	want := "bootstrap: failed to parse profile ID for node cp1: profile ID is empty in create-profile response"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if e.Unwrap() == nil {
		t.Error("Unwrap should return non-nil cause")
	}
}

func TestErrProfileIDParseFailed_NoCause(t *testing.T) {
	e := ErrProfileIDParseFailed{Hostname: "gw1"}
	want := "bootstrap: failed to parse profile ID for node gw1"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
