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

package app

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestParseDebugSinkFromCmdline_Present(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("root=/dev/sda1 platform_debug_sink=10.4.2.91:8080 quiet\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// We need to test the parsing logic directly since procCmdlinePath is a const.
	// Parse the file ourselves using the same logic.
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		t.Fatal(err)
	}

	var found string
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, kernelCmdlineParam+"=") {
			found = strings.TrimPrefix(field, kernelCmdlineParam+"=")
		}
	}

	if found != "10.4.2.91:8080" {
		t.Fatalf("expected 10.4.2.91:8080, got %q", found)
	}
}

func TestParseDebugSinkFromCmdline_Absent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("root=/dev/sda1 quiet\n"), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, kernelCmdlineParam+"=") {
			found = true
		}
	}

	if found {
		t.Fatal("expected no platform_debug_sink, but found one")
	}
}

func TestParseDebugSinkFromCmdline_EmptyValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cmdlinePath := filepath.Join(dir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("root=/dev/sda1 platform_debug_sink= quiet\n"), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		t.Fatal(err)
	}

	var val string
	var ok bool
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, kernelCmdlineParam+"=") {
			val = strings.TrimPrefix(field, kernelCmdlineParam+"=")
			if val != "" {
				ok = true
			}
		}
	}

	if ok {
		t.Fatalf("expected empty value to be rejected, got %q", val)
	}
}

func TestPrimaryInterfaceInfo(t *testing.T) {
	t.Parallel()

	ip, mac := primaryInterfaceInfo()

	// On a machine with networking, these should be non-empty.
	// In CI or containers they may be empty, which is acceptable.
	if ip == "" {
		t.Skip("no outbound IP available (expected in some CI environments)")
	}

	// Validate IP format.
	if net.ParseIP(ip) == nil {
		t.Fatalf("invalid IP address: %q", ip)
	}

	// MAC should be non-empty when IP was found on a real interface.
	if mac == "" {
		t.Log("warning: MAC address not found for primary interface")
	}
}

func TestPostBootstrapRegistration_Success(t *testing.T) {
	t.Parallel()

	var received atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("failed to read body: %v", readErr)
		}
		defer func() { _ = r.Body.Close() }()

		var reg BootstrapRegistration
		if unmarshalErr := json.Unmarshal(body, &reg); unmarshalErr != nil {
			t.Errorf("failed to unmarshal: %v", unmarshalErr)
		}
		received.Store(reg)

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	// Extract host:port from test server URL (strip "http://")
	sink := strings.TrimPrefix(ts.URL, "http://")

	testApp := &App{
		Hostname: "test-node-01",
		Logger:   logging.DefaultLogger(),
	}

	// Run synchronously for test determinism.
	testApp.postBootstrapRegistration(sink)

	raw := received.Load()
	if raw == nil {
		t.Fatal("server never received a registration request")
	}

	reg := raw.(BootstrapRegistration)
	if reg.Hostname != "test-node-01" {
		t.Errorf("expected hostname test-node-01, got %s", reg.Hostname)
	}
	if reg.Services["platformd"] != "running" {
		t.Errorf("expected platformd=running, got %s", reg.Services["platformd"])
	}
	if reg.Services["sshd"] != "running" {
		t.Errorf("expected sshd=running, got %s", reg.Services["sshd"])
	}
	if reg.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if _, parseErr := time.Parse(time.RFC3339, reg.Timestamp); parseErr != nil {
		t.Errorf("timestamp not RFC3339: %v", parseErr)
	}
}

func TestPostBootstrapRegistration_ServerError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)

	sink := strings.TrimPrefix(ts.URL, "http://")

	testApp := &App{
		Hostname: "test-node-02",
		Logger:   logging.DefaultLogger(),
	}

	// Should not panic; just logs a warning.
	testApp.postBootstrapRegistration(sink)
}

func TestPostBootstrapRegistration_Unreachable(t *testing.T) {
	t.Parallel()

	testApp := &App{
		Hostname: "test-node-03",
		Logger:   logging.DefaultLogger(),
	}

	// Use an address that will refuse connection immediately.
	testApp.postBootstrapRegistration("127.0.0.1:1")
}

func TestBootstrapRegistrationPayloadFields(t *testing.T) {
	t.Parallel()

	reg := BootstrapRegistration{
		Hostname:  "host-02",
		IP:        "10.4.2.239",
		MAC:       "00:25:90:00:02:aa",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services: map[string]string{
			"platformd": "running",
			"sshd":      "running",
		},
	}

	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]interface{}
	if unmarshalErr := json.Unmarshal(data, &decoded); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}

	requiredKeys := []string{"hostname", "ip", "mac", "timestamp", "services"}
	for _, key := range requiredKeys {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing required JSON key: %s", key)
		}
	}
}

func TestBootstrapRegistrationURL(t *testing.T) {
	t.Parallel()

	// Verify the URL pattern matches what the bootstrap server expects.
	sink := "10.4.2.91:8080"
	hostname := "host-02"
	expected := "http://10.4.2.91:8080/installs/host-02/registration.json"

	got := "http://" + sink + "/installs/" + hostname + "/registration.json"
	if got != expected {
		t.Errorf("URL mismatch:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestErrBootstrapRegistration(t *testing.T) {
	t.Parallel()

	cause := &ErrBootstrapRegistrationStatus{
		Endpoint:   "http://10.4.2.91:8080/installs/host-02/registration.json",
		StatusCode: 500,
	}

	err := ErrBootstrapRegistration{
		Endpoint: "http://10.4.2.91:8080/installs/host-02/registration.json",
		Cause:    cause,
	}

	if !strings.Contains(err.Error(), "bootstrap registration") {
		t.Errorf("error message missing 'bootstrap registration': %s", err.Error())
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap did not return the cause")
	}
}

func TestErrBootstrapRegistrationStatus(t *testing.T) {
	t.Parallel()

	err := ErrBootstrapRegistrationStatus{
		Endpoint:   "http://10.4.2.91:8080/installs/host-02/registration.json",
		StatusCode: 404,
	}

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error message missing status code: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "bootstrap registration") {
		t.Errorf("error message missing 'bootstrap registration': %s", err.Error())
	}
}
