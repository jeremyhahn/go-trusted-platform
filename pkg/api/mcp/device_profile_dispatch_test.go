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

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// deviceProfileToolNames is the authoritative list of profile CRUD and
// assignment tool names routed through the device profile dispatcher.
var deviceProfileToolNames = []string{
	"profile_create",
	"profile_get_by_id",
	"profile_list_all",
	"profile_update_by_id",
	"profile_delete_by_id",
	"profile_assign_to_device",
	"profile_unassign_from_device",
}

// newMCPTestEKCertPEM generates a self-signed ECDSA certificate PEM used
// to exercise the profile EK-cert prestage path over MCP.
func newMCPTestEKCertPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// deviceProfileStubProvider satisfies DeviceProfileProvider for tests,
// storing profiles in memory.
type deviceProfileStubProvider struct {
	profiles           map[uint64]*entities.DeviceProfile
	nextID             uint64
	lastAssignDeviceID uint64
}

func newDeviceProfileStubProvider() *deviceProfileStubProvider {
	return &deviceProfileStubProvider{
		profiles: make(map[uint64]*entities.DeviceProfile),
		nextID:   1000,
	}
}

func (s *deviceProfileStubProvider) DeviceProfileCreate(ctx context.Context, profile *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	if profile.ID == 0 {
		s.nextID++
		profile.ID = s.nextID
	}
	s.profiles[profile.ID] = profile
	return profile, nil
}

func (s *deviceProfileStubProvider) DeviceProfileGet(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	profile, ok := s.profiles[id]
	if !ok {
		return nil, errors.New("profile not found")
	}
	return profile, nil
}

func (s *deviceProfileStubProvider) DeviceProfileList(ctx context.Context, page, pageSize int) ([]*entities.DeviceProfile, int, error) {
	profiles := make([]*entities.DeviceProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		profiles = append(profiles, p)
	}
	return profiles, len(profiles), nil
}

func (s *deviceProfileStubProvider) DeviceProfileUpdate(ctx context.Context, profile *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	if _, ok := s.profiles[profile.ID]; !ok {
		return nil, errors.New("profile not found")
	}
	s.profiles[profile.ID] = profile
	return profile, nil
}

func (s *deviceProfileStubProvider) DeviceProfileDelete(ctx context.Context, id uint64) error {
	if _, ok := s.profiles[id]; !ok {
		return errors.New("profile not found")
	}
	delete(s.profiles, id)
	return nil
}

func (s *deviceProfileStubProvider) DeviceProfileAssign(ctx context.Context, profileID, deviceID uint64, ekSerial, macAddress, ekCertPEM string) (*entities.DeviceProfile, error) {
	s.lastAssignDeviceID = deviceID
	profile, ok := s.profiles[profileID]
	if !ok {
		return nil, errors.New("profile not found")
	}
	if ekSerial != "" {
		profile.EKSerial = ekSerial
	}
	if macAddress != "" {
		profile.MACAddress = macAddress
	}
	if ekCertPEM != "" {
		profile.EKCert = ekCertPEM
	}
	profile.Assigned = true
	profile.AssignedAt = time.Now().UTC()
	return profile, nil
}

func (s *deviceProfileStubProvider) DeviceProfileUnassign(ctx context.Context, profileID uint64) (*entities.DeviceProfile, error) {
	profile, ok := s.profiles[profileID]
	if !ok {
		return nil, errors.New("profile not found")
	}
	profile.EKSerial = ""
	profile.MACAddress = ""
	profile.EKCert = ""
	profile.Assigned = false
	profile.AssignedAt = time.Time{}
	return profile, nil
}

// deviceProfileCombinedProvider embeds both mockServiceProvider (satisfies
// the full ServiceProvider interface) and deviceProfileStubProvider
// (satisfies DeviceProfileProvider) so the registry routes profile_* CRUD
// tools through the optional-interface path.
type deviceProfileCombinedProvider struct {
	*mockServiceProvider
	*deviceProfileStubProvider
}

// Compile-time assertions.
var (
	_ ServiceProvider       = (*deviceProfileCombinedProvider)(nil)
	_ DeviceProfileProvider = (*deviceProfileCombinedProvider)(nil)
	_ DeviceProfileProvider = (*deviceProfileStubProvider)(nil)
)

func newDeviceProfileRegistry() (*ToolRegistry, *deviceProfileStubProvider) {
	stub := newDeviceProfileStubProvider()
	svc := &deviceProfileCombinedProvider{
		mockServiceProvider:       newMockServiceProvider(),
		deviceProfileStubProvider: stub,
	}
	return NewToolRegistry(svc, newTestLogger()), stub
}

// TestDeviceProfileToolRegistrationAndRoutingParity guards against the
// registered-but-unroutable bug class. It asserts that every profile CRUD
// tool is registered, that the dispatch map and the registered set agree,
// and that ExecuteTool routes each tool to the device profile executor (a
// provider without DeviceProfileProvider yields
// ErrDeviceProfileNotConfigured, never "unknown tool").
func TestDeviceProfileToolRegistrationAndRoutingParity(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = true
	}

	for _, name := range deviceProfileToolNames {
		if !registered[name] {
			t.Errorf("expected tool %q is not registered", name)
		}
		if _, ok := deviceProfileToolDispatch[name]; !ok {
			t.Errorf("tool %q has no executor in deviceProfileToolDispatch", name)
		}
	}
	for name := range deviceProfileToolDispatch {
		if !registered[name] {
			t.Errorf("dispatch map routes %q but the tool is not registered", name)
		}
	}

	for _, name := range deviceProfileToolNames {
		args := map[string]interface{}{"id": 1, "name": "x"}
		if _, err := registry.ExecuteTool(ctx, name, args); !errors.Is(err, ErrDeviceProfileNotConfigured) {
			t.Errorf("ExecuteTool(%q) without provider: err = %v, want ErrDeviceProfileNotConfigured", name, err)
		}
	}
}

// TestDeviceProfileCreate_EKPrestageFields verifies profile_create binds
// the EK prestage fields, validates the certificate, and returns the
// stored profile with a string ID.
func TestDeviceProfileCreate_EKPrestageFields(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	certPEM := newMCPTestEKCertPEM(t)

	result, err := registry.ExecuteTool(context.Background(), "profile_create", map[string]interface{}{
		"name":        "ek-profile",
		"model":       "X10SDV",
		"role":        "server",
		"ek_serial":   "EK-MCP-1",
		"ek_cert":     certPEM,
		"mac_address": "aa:bb:cc:dd:ee:41",
		"config":      map[string]interface{}{"hostname": "node-02"},
		"assigned":    true,
		"assigned_at": "2026-08-01T09:00:00Z",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obj, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want map", result)
	}
	if _, isString := obj["id"].(string); !isString {
		t.Fatalf("id must be a string per the uint64-on-the-wire convention, got %T", obj["id"])
	}
	if obj["ek_cert"] != certPEM {
		t.Error("ek_cert must be echoed for auditability")
	}
	if obj["ek_serial"] != "EK-MCP-1" {
		t.Errorf("ek_serial = %v", obj["ek_serial"])
	}

	if len(stub.profiles) != 1 {
		t.Fatalf("stored %d profiles, want 1", len(stub.profiles))
	}
	for _, stored := range stub.profiles {
		if stored.EKCert != certPEM {
			t.Error("stored profile missing prestaged EK certificate")
		}
		if stored.MACAddress != "aa:bb:cc:dd:ee:41" {
			t.Errorf("stored mac_address = %q", stored.MACAddress)
		}
		if !stored.Assigned || stored.AssignedAt.IsZero() {
			t.Error("stored assignment state missing")
		}
	}
}

// TestDeviceProfileCreate_Errors verifies the create error paths: missing
// name and invalid EK certificate.
func TestDeviceProfileCreate_Errors(t *testing.T) {
	t.Run("missing name", func(t *testing.T) {
		registry, _ := newDeviceProfileRegistry()
		_, err := registry.ExecuteTool(context.Background(), "profile_create", map[string]interface{}{})
		if !errors.Is(err, ErrProfileNameRequired) {
			t.Fatalf("err = %v, want ErrProfileNameRequired", err)
		}
	})

	t.Run("invalid ek cert", func(t *testing.T) {
		registry, stub := newDeviceProfileRegistry()
		_, err := registry.ExecuteTool(context.Background(), "profile_create", map[string]interface{}{
			"name":    "bad-ek",
			"ek_cert": "not a pem certificate",
		})
		var notPEM entities.ErrEKCertNotPEM
		if !errors.As(err, &notPEM) {
			t.Fatalf("err = %v, want entities.ErrEKCertNotPEM", err)
		}
		if len(stub.profiles) != 0 {
			t.Fatal("no profile must be stored on validation failure")
		}
	})
}

// TestDeviceProfileUpdate_EKPrestageFields verifies profile_update_by_id
// applies a partial EK prestage update onto an existing profile.
func TestDeviceProfileUpdate_EKPrestageFields(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	stub.profiles[42] = &entities.DeviceProfile{ID: 42, Name: "prestage-target", Model: "X10SDV"}
	certPEM := newMCPTestEKCertPEM(t)

	result, err := registry.ExecuteTool(context.Background(), "profile_update_by_id", map[string]interface{}{
		"id":          42,
		"ek_serial":   "EK-MCP-2",
		"ek_cert":     certPEM,
		"mac_address": "aa:bb:cc:dd:ee:42",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	obj := result.(map[string]interface{})
	if obj["name"] != "prestage-target" {
		t.Errorf("unset fields must keep their values: name = %v", obj["name"])
	}
	if obj["ek_cert"] != certPEM {
		t.Error("ek_cert missing from update result")
	}

	stored := stub.profiles[42]
	if stored.EKCert != certPEM || stored.EKSerial != "EK-MCP-2" || stored.MACAddress != "aa:bb:cc:dd:ee:42" {
		t.Errorf("stored profile missing prestage fields: %+v", stored)
	}
	if stored.Model != "X10SDV" {
		t.Errorf("unset model must be preserved, got %q", stored.Model)
	}
}

// TestDeviceProfileUpdate_Errors verifies the update error paths: missing
// id and invalid EK certificate.
func TestDeviceProfileUpdate_Errors(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		registry, _ := newDeviceProfileRegistry()
		_, err := registry.ExecuteTool(context.Background(), "profile_update_by_id", map[string]interface{}{})
		if !errors.Is(err, ErrProfileIDRequired) {
			t.Fatalf("err = %v, want ErrProfileIDRequired", err)
		}
	})

	t.Run("invalid ek cert leaves profile untouched", func(t *testing.T) {
		registry, stub := newDeviceProfileRegistry()
		stub.profiles[7] = &entities.DeviceProfile{ID: 7, Name: "keep-clean"}
		_, err := registry.ExecuteTool(context.Background(), "profile_update_by_id", map[string]interface{}{
			"id":      7,
			"ek_cert": "garbage",
		})
		var notPEM entities.ErrEKCertNotPEM
		if !errors.As(err, &notPEM) {
			t.Fatalf("err = %v, want entities.ErrEKCertNotPEM", err)
		}
		if stub.profiles[7].EKCert != "" {
			t.Fatal("stored profile must stay untouched on validation failure")
		}
	})
}

// TestDeviceProfileGetListDelete verifies the read and delete executors.
func TestDeviceProfileGetListDelete(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	certPEM := newMCPTestEKCertPEM(t)
	stub.profiles[42] = &entities.DeviceProfile{ID: 42, Name: "full", EKCert: certPEM}

	t.Run("get returns ek_cert and string id", func(t *testing.T) {
		result, err := registry.ExecuteTool(context.Background(), "profile_get_by_id", map[string]interface{}{"id": 42})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		obj := result.(map[string]interface{})
		if obj["id"] != "42" {
			t.Errorf("id = %v, want string \"42\"", obj["id"])
		}
		if obj["ek_cert"] != certPEM {
			t.Error("ek_cert missing from get result")
		}
	})

	t.Run("get requires id", func(t *testing.T) {
		if _, err := registry.ExecuteTool(context.Background(), "profile_get_by_id", map[string]interface{}{}); !errors.Is(err, ErrProfileIDRequired) {
			t.Fatalf("err = %v, want ErrProfileIDRequired", err)
		}
	})

	t.Run("list returns profiles and total", func(t *testing.T) {
		result, err := registry.ExecuteTool(context.Background(), "profile_list_all", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		obj := result.(map[string]interface{})
		profiles := obj["profiles"].([]interface{})
		if len(profiles) != 1 || obj["total"] != 1 {
			t.Fatalf("list = %v", obj)
		}
	})

	t.Run("delete removes profile", func(t *testing.T) {
		result, err := registry.ExecuteTool(context.Background(), "profile_delete_by_id", map[string]interface{}{"id": 42})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		obj := result.(map[string]interface{})
		if obj["success"] != true || obj["id"] != "42" {
			t.Fatalf("delete result = %v", obj)
		}
		if len(stub.profiles) != 0 {
			t.Fatal("profile must be deleted")
		}
	})

	t.Run("delete requires id", func(t *testing.T) {
		if _, err := registry.ExecuteTool(context.Background(), "profile_delete_by_id", map[string]interface{}{}); !errors.Is(err, ErrProfileIDRequired) {
			t.Fatalf("err = %v, want ErrProfileIDRequired", err)
		}
	})
}

// TestDeviceProfileSchemas_PrestageFields verifies the profile_create and
// profile_update_by_id tool schemas advertise the prestage field set so
// MCP clients can discover them.
func TestDeviceProfileSchemas_PrestageFields(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	wantFields := []string{"ek_serial", "ek_cert", "mac_address", "config", "assigned", "assigned_at"}
	for _, toolName := range []string{"profile_create", "profile_update_by_id"} {
		var schema map[string]interface{}
		for _, tool := range registry.ListTools() {
			if tool.Name == toolName {
				schema = tool.InputSchema
			}
		}
		if schema == nil {
			t.Fatalf("tool %q not registered", toolName)
		}
		properties, ok := schema["properties"].(map[string]interface{})
		if !ok {
			t.Fatalf("tool %q schema has no properties", toolName)
		}
		for _, field := range wantFields {
			if _, ok := properties[field]; !ok {
				t.Errorf("tool %q schema missing field %q", toolName, field)
			}
		}
	}
}

// TestDeviceProfileAssign verifies profile_assign_to_device binds the EK
// identity, prestages the EK certificate, and returns the updated
// profile with a string ID.
func TestDeviceProfileAssign(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	ctx := context.Background()
	ekCert := newMCPTestEKCertPEM(t)

	stub.profiles[500] = &entities.DeviceProfile{ID: 500, Name: "assign-me"}

	result, err := registry.ExecuteTool(ctx, "profile_assign_to_device", map[string]interface{}{
		"profile_id":  500,
		"ek_serial":   "EK-5005",
		"mac_address": "00:25:90:aa:bb:cc",
		"ek_cert":     ekCert,
	})
	if err != nil {
		t.Fatalf("profile_assign_to_device: %v", err)
	}

	out, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	if out["id"] != "500" {
		t.Errorf("id = %v, want \"500\" (string uint64)", out["id"])
	}

	stored := stub.profiles[500]
	if !stored.Assigned {
		t.Error("profile not marked assigned")
	}
	if stored.EKSerial != "EK-5005" || stored.MACAddress != "00:25:90:aa:bb:cc" {
		t.Errorf("identity = %q/%q, want EK-5005/00:25:90:aa:bb:cc", stored.EKSerial, stored.MACAddress)
	}
	if stored.EKCert != ekCert {
		t.Error("EK certificate not prestaged on profile")
	}
}

// TestDeviceProfileAssign_Errors verifies boundary validation on
// profile_assign_to_device.
func TestDeviceProfileAssign_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("MissingProfileID", func(t *testing.T) {
		registry, _ := newDeviceProfileRegistry()
		_, err := registry.ExecuteTool(ctx, "profile_assign_to_device", map[string]interface{}{
			"ek_serial": "EK-1",
		})
		if !errors.Is(err, ErrProfileIDRequired) {
			t.Errorf("err = %v, want ErrProfileIDRequired", err)
		}
	})

	t.Run("MissingIdentity", func(t *testing.T) {
		registry, stub := newDeviceProfileRegistry()
		stub.profiles[501] = &entities.DeviceProfile{ID: 501}
		_, err := registry.ExecuteTool(ctx, "profile_assign_to_device", map[string]interface{}{
			"profile_id": 501,
		})
		if !errors.Is(err, ErrDeviceProfileIdentityRequired) {
			t.Errorf("err = %v, want ErrDeviceProfileIdentityRequired", err)
		}
	})

	t.Run("InvalidEKCert", func(t *testing.T) {
		registry, stub := newDeviceProfileRegistry()
		stub.profiles[502] = &entities.DeviceProfile{ID: 502}
		_, err := registry.ExecuteTool(ctx, "profile_assign_to_device", map[string]interface{}{
			"profile_id": 502,
			"ek_serial":  "EK-1",
			"ek_cert":    "not-a-pem",
		})
		if err == nil {
			t.Fatal("expected EK cert validation error")
		}
		var notPEM entities.ErrEKCertNotPEM
		if !errors.As(err, &notPEM) {
			t.Errorf("err = %v, want ErrEKCertNotPEM", err)
		}
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		registry, _ := newDeviceProfileRegistry()
		_, err := registry.ExecuteTool(ctx, "profile_assign_to_device", map[string]interface{}{
			"profile_id": 999999,
			"ek_serial":  "EK-1",
		})
		if err == nil {
			t.Fatal("expected not-found error")
		}
	})
}

// TestDeviceProfileUnassign verifies profile_unassign_from_device clears
// the device binding, and validates its error paths.
func TestDeviceProfileUnassign(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	ctx := context.Background()

	stub.profiles[600] = &entities.DeviceProfile{
		ID:       600,
		Name:     "bound",
		EKSerial: "EK-6006",
		EKCert:   newMCPTestEKCertPEM(t),
		Assigned: true,
	}

	result, err := registry.ExecuteTool(ctx, "profile_unassign_from_device", map[string]interface{}{
		"profile_id": 600,
	})
	if err != nil {
		t.Fatalf("profile_unassign_from_device: %v", err)
	}
	if _, ok := result.(map[string]interface{}); !ok {
		t.Fatalf("result type = %T, want map", result)
	}

	stored := stub.profiles[600]
	if stored.Assigned {
		t.Error("profile still marked assigned")
	}
	if stored.EKSerial != "" || stored.EKCert != "" {
		t.Errorf("binding not cleared: ek_serial=%q ek_cert set=%t", stored.EKSerial, stored.EKCert != "")
	}

	t.Run("MissingProfileID", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "profile_unassign_from_device", map[string]interface{}{})
		if !errors.Is(err, ErrProfileIDRequired) {
			t.Errorf("err = %v, want ErrProfileIDRequired", err)
		}
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "profile_unassign_from_device", map[string]interface{}{
			"profile_id": 424242,
		})
		if err == nil {
			t.Fatal("expected not-found error")
		}
	})
}
