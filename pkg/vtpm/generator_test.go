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

package vtpm

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// mockVTPMService implements VTPMService for testing.
type mockVTPMService struct {
	bundles     map[string]*Bundle
	running     map[string]bool
	mu          sync.RWMutex
	createErr   error
	getErr      error
	deleteErr   error
	startErr    error
	stopErr     error
	listErr     error
	storagePath string
	// ekCertDER, when set, is written to each new bundle's tpm/ek.crt.
	ekCertDER []byte
}

func newMockVTPMService() *mockVTPMService {
	return &mockVTPMService{
		bundles:     make(map[string]*Bundle),
		running:     make(map[string]bool),
		storagePath: "/tmp/vtpm/bundles",
	}
}

func (m *mockVTPMService) CreateBundle(ctx context.Context, opts *CreateBundleOptions) (*Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createErr != nil {
		return nil, m.createErr
	}

	id := opts.Hostname + "-" + time.Now().Format("20060102150405")
	if opts.Hostname == "" {
		id = "vtpm-" + time.Now().Format("20060102150405")
	}

	if len(m.ekCertDER) > 0 {
		tpmDir := filepath.Join(m.storagePath, id, "tpm")
		if err := os.MkdirAll(tpmDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(tpmDir, "ek.crt"), m.ekCertDER, 0o600); err != nil {
			return nil, err
		}
	}

	bundle := &Bundle{
		ID:   id,
		Mode: opts.Mode,
		Manifest: &Manifest{
			ID:              id,
			Mode:            opts.Mode,
			Hostname:        opts.Hostname,
			EKAlgorithm:     opts.EKAlgorithm,
			CreatedAt:       time.Now(),
			DeviceProfileID: opts.DeviceProfileID,
			EKCertificate: &EKCertInfo{
				Fingerprint:  "sha256:abcdef1234567890",
				Subject:      "CN=" + opts.Hostname,
				Issuer:       "CN=Test CA",
				SerialNumber: "1234567890",
			},
		},
		CreatedAt: time.Now(),
	}

	m.bundles[id] = bundle
	return bundle, nil
}

func (m *mockVTPMService) GetBundle(ctx context.Context, id string) (*Bundle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getErr != nil {
		return nil, m.getErr
	}

	bundle, exists := m.bundles[id]
	if !exists {
		return nil, ErrBundleNotFound{ID: id}
	}
	return bundle, nil
}

func (m *mockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteErr != nil {
		return m.deleteErr
	}

	if _, exists := m.bundles[id]; !exists {
		return ErrBundleNotFound{ID: id}
	}

	delete(m.bundles, id)
	delete(m.running, id)
	return nil
}

func (m *mockVTPMService) ListBundles(ctx context.Context, opts *ListOptions) ([]*Bundle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listErr != nil {
		return nil, m.listErr
	}

	bundles := make([]*Bundle, 0, len(m.bundles))
	for _, bundle := range m.bundles {
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

func (m *mockVTPMService) CreateTemplate(ctx context.Context, opts *CreateTemplateOptions) (*Template, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) CloneTemplate(ctx context.Context, opts *CloneOptions) (*Bundle, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) GetTemplate(ctx context.Context, id string) (*Template, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	return errors.New("not implemented")
}

func (m *mockVTPMService) ListTemplates(ctx context.Context) ([]*Template, error) {
	return nil, nil
}

func (m *mockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	return errors.New("not implemented")
}

func (m *mockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*Bundle, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	return nil
}

func (m *mockVTPMService) GetBundlePath(id string) string {
	return filepath.Join(m.storagePath, id)
}

func (m *mockVTPMService) GetTPMSocketPath(id string) string {
	return filepath.Join(m.storagePath, id, "tpm", "swtpm.sock")
}

func (m *mockVTPMService) GetNVRAMPath(id string) string {
	return filepath.Join(m.storagePath, id, "ovmf", "OVMF_VARS.fd")
}

func (m *mockVTPMService) Start(ctx context.Context, bundleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.startErr != nil {
		return m.startErr
	}

	if _, exists := m.bundles[bundleID]; !exists {
		return ErrBundleNotFound{ID: bundleID}
	}

	m.running[bundleID] = true
	return nil
}

func (m *mockVTPMService) Stop(ctx context.Context, bundleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopErr != nil {
		return m.stopErr
	}

	if _, exists := m.bundles[bundleID]; !exists {
		return ErrBundleNotFound{ID: bundleID}
	}

	m.running[bundleID] = false
	return nil
}

func (m *mockVTPMService) IsRunning(bundleID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running[bundleID]
}

func (m *mockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*QuoteResult, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *SealOptions) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	return errors.New("not implemented")
}

func (m *mockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Close() error {
	return nil
}

// mockProfileAssigner implements ProfileAssigner for testing.
type mockProfileAssigner struct {
	assignedProfileID uint64
	assignedEKSerial  string
	assignedMAC       string
	assignedEKCert    string
	assignErr         error
	callCount         int
}

func (m *mockProfileAssigner) AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error {
	m.callCount++
	if m.assignErr != nil {
		return m.assignErr
	}
	m.assignedProfileID = profileID
	m.assignedEKSerial = ekSerial
	m.assignedMAC = mac
	m.assignedEKCert = ekCertPEM
	return nil
}

func TestNewGenerator(t *testing.T) {
	t.Run("creates generator with valid config", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
			EKAlgorithm: EKAlgorithmRSA,
		}
		mockService := newMockVTPMService()

		gen, err := NewGenerator(config, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		if gen == nil {
			t.Fatal("NewGenerator returned nil")
		}
	})

	t.Run("applies defaults for nil config", func(t *testing.T) {
		mockService := newMockVTPMService()

		gen, err := NewGenerator(nil, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		if gen.config.Version != TPMVersion20 {
			t.Errorf("expected version %s, got %s", TPMVersion20, gen.config.Version)
		}
		if gen.config.EKAlgorithm != EKAlgorithmRSA {
			t.Errorf("expected algorithm %s, got %s", EKAlgorithmRSA, gen.config.EKAlgorithm)
		}
	})

	t.Run("fails with nil vtpmService", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
		}

		_, err := NewGenerator(config, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil vtpmService")
		}

		var configErr ErrInvalidConfig
		if !errors.As(err, &configErr) {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("fails with invalid EKAlgorithm", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
			EKAlgorithm: EKAlgorithm("INVALID"), // Invalid algorithm that cannot be fixed by defaults
		}
		mockService := newMockVTPMService()

		_, err := NewGenerator(config, mockService, nil)
		if err == nil {
			t.Fatal("expected error for invalid EKAlgorithm")
		}

		var configErr ErrInvalidConfig
		if !errors.As(err, &configErr) {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("fails with invalid TPMVersion", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
			Version:     TPMVersion("1.2"), // Invalid version
		}
		mockService := newMockVTPMService()

		_, err := NewGenerator(config, mockService, nil)
		if err == nil {
			t.Fatal("expected error for invalid TPMVersion")
		}
	})

	t.Run("loads profile index from existing bundles", func(t *testing.T) {
		mockService := newMockVTPMService()

		// Pre-populate bundles with profile associations
		mockService.bundles["bundle-1"] = &Bundle{
			ID: "bundle-1",
			Manifest: &Manifest{
				ID:              "bundle-1",
				DeviceProfileID: 100,
			},
		}
		mockService.bundles["bundle-2"] = &Bundle{
			ID: "bundle-2",
			Manifest: &Manifest{
				ID:              "bundle-2",
				DeviceProfileID: 200,
			},
		}
		// Bundle without profile association
		mockService.bundles["bundle-3"] = &Bundle{
			ID:       "bundle-3",
			Manifest: &Manifest{ID: "bundle-3"},
		}

		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		gen, err := NewGenerator(config, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		// Verify profile index was loaded
		ctx := context.Background()

		instance, err := gen.GetByProfile(ctx, 100)
		if err != nil {
			t.Fatalf("GetByProfile failed for profile 100: %v", err)
		}
		if instance.ID != "bundle-1" {
			t.Errorf("expected bundle-1, got %s", instance.ID)
		}

		instance, err = gen.GetByProfile(ctx, 200)
		if err != nil {
			t.Fatalf("GetByProfile failed for profile 200: %v", err)
		}
		if instance.ID != "bundle-2" {
			t.Errorf("expected bundle-2, got %s", instance.ID)
		}

		// Profile 300 should not exist
		_, err = gen.GetByProfile(ctx, 300)
		if err == nil {
			t.Error("expected error for non-existent profile")
		}
	})

	t.Run("handles list error during profile index load", func(t *testing.T) {
		mockService := newMockVTPMService()
		mockService.listErr = errors.New("list failed")

		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		// Should still succeed - error is only logged as warning
		gen, err := NewGenerator(config, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}
		if gen == nil {
			t.Fatal("expected generator to be created")
		}
	})
}

func TestGenerator_Generate(t *testing.T) {
	t.Run("generates vTPM instance with defaults", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, err := gen.Generate(ctx, nil)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		if instance.ID == "" {
			t.Error("expected non-empty ID")
		}
		if instance.Version != TPMVersion20 {
			t.Errorf("expected version %s, got %s", TPMVersion20, instance.Version)
		}
		if instance.SRKHandle != SRKHandle {
			t.Errorf("expected SRK handle 0x%X, got 0x%X", SRKHandle, instance.SRKHandle)
		}
	})

	t.Run("generates vTPM instance with options", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		opts := &GenerateOptions{
			Hostname:          "test-vm",
			EKAlgorithm:       EKAlgorithmECC,
			SecureBootEnabled: true,
			Labels:            map[string]string{"env": "test"},
		}

		instance, err := gen.Generate(ctx, opts)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		if instance.EKFingerprint == "" {
			t.Error("expected non-empty EK fingerprint")
		}
	})

	t.Run("fails when bundle creation fails", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		mockService.createErr = errors.New("creation failed")
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.Generate(ctx, nil)
		if err == nil {
			t.Fatal("expected error when creation fails")
		}

		var genErr ErrGenerationFailed
		if !errors.As(err, &genErr) {
			t.Errorf("expected ErrGenerationFailed, got %T", err)
		}
	})
}

func TestGenerator_GenerateForProfile(t *testing.T) {
	t.Run("generates vTPM for device profile", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		profile := &entities.DeviceProfile{
			ID:   123,
			Name: "test-profile",
		}

		instance, err := gen.GenerateForProfile(ctx, profile, &GenerateOptions{
			Hostname: "profile-vm",
		})
		if err != nil {
			t.Fatalf("GenerateForProfile failed: %v", err)
		}

		if instance.DeviceProfileID != profile.ID {
			t.Errorf("expected profile ID %d, got %d", profile.ID, instance.DeviceProfileID)
		}
		if instance.DeviceProfile != profile {
			t.Error("expected profile reference to be set")
		}
	})

	t.Run("fails with nil profile", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.GenerateForProfile(ctx, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil profile")
		}
	})

	t.Run("fails when profile already has vTPM", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		profile := &entities.DeviceProfile{ID: 456}

		// First generation should succeed
		_, err := gen.GenerateForProfile(ctx, profile, nil)
		if err != nil {
			t.Fatalf("first generation failed: %v", err)
		}

		// Second generation should fail
		_, err = gen.GenerateForProfile(ctx, profile, nil)
		if err == nil {
			t.Fatal("expected error for duplicate profile")
		}

		var existsErr ErrVTPMAlreadyExists
		if !errors.As(err, &existsErr) {
			t.Errorf("expected ErrVTPMAlreadyExists, got %T", err)
		}
	})

	t.Run("fails when bundle creation fails", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		profile := &entities.DeviceProfile{ID: 789}

		// Set error after initial setup
		mockService.createErr = errors.New("bundle creation failed")

		_, err := gen.GenerateForProfile(ctx, profile, nil)
		if err == nil {
			t.Fatal("expected error when bundle creation fails")
		}

		var genErr ErrGenerationFailed
		if !errors.As(err, &genErr) {
			t.Errorf("expected ErrGenerationFailed, got %T", err)
		}
	})
}

func TestGenerateForProfile_AssignsEKSerial(t *testing.T) {
	t.Run("assigns EK serial to profile when assigner is set", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, err := NewGenerator(config, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		assigner := &mockProfileAssigner{}
		gen.SetProfileAssigner(assigner)

		ctx := context.Background()
		profile := &entities.DeviceProfile{
			ID:   500,
			Name: "ek-serial-test",
		}

		instance, err := gen.GenerateForProfile(ctx, profile, &GenerateOptions{
			Hostname: "ek-serial-vm",
		})
		if err != nil {
			t.Fatalf("GenerateForProfile failed: %v", err)
		}

		if instance.DeviceProfileID != profile.ID {
			t.Errorf("expected profile ID %d, got %d", profile.ID, instance.DeviceProfileID)
		}

		if assigner.callCount != 1 {
			t.Errorf("expected assigner to be called once, got %d", assigner.callCount)
		}

		if assigner.assignedProfileID != profile.ID {
			t.Errorf("expected assigned profile ID %d, got %d", profile.ID, assigner.assignedProfileID)
		}

		if assigner.assignedEKSerial != "1234567890" {
			t.Errorf("expected EK serial 1234567890, got %s", assigner.assignedEKSerial)
		}

		if assigner.assignedMAC != "" {
			t.Errorf("expected empty MAC, got %s", assigner.assignedMAC)
		}

		if assigner.assignedEKCert != "" {
			t.Errorf("expected no EK certificate when the bundle has none, got %q", assigner.assignedEKCert)
		}
	})

	t.Run("prestages the bundle EK certificate as PEM", func(t *testing.T) {
		ekCert, err := newSelfSignedTestCert()
		if err != nil {
			t.Fatalf("newSelfSignedTestCert failed: %v", err)
		}
		mockService := newMockVTPMService()
		mockService.storagePath = t.TempDir()
		mockService.ekCertDER = ekCert.Raw
		gen, err := NewGenerator(&VTPMConfig{StoragePath: mockService.storagePath}, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}
		assigner := &mockProfileAssigner{}
		gen.SetProfileAssigner(assigner)

		profile := &entities.DeviceProfile{ID: 501, Name: "ek-cert-test"}
		if _, err := gen.GenerateForProfile(context.Background(), profile, &GenerateOptions{Hostname: "ek-cert-vm"}); err != nil {
			t.Fatalf("GenerateForProfile failed: %v", err)
		}

		want := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekCert.Raw}))
		if assigner.assignedEKCert != want {
			t.Errorf("expected the bundle EK certificate as PEM, got %q", assigner.assignedEKCert)
		}
	})
}

func TestGenerateForProfile_NoAssigner(t *testing.T) {
	t.Run("generates vTPM without assigner (backward compat)", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, err := NewGenerator(config, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		// No SetProfileAssigner call - assigner is nil

		ctx := context.Background()
		profile := &entities.DeviceProfile{
			ID:   600,
			Name: "no-assigner-test",
		}

		instance, err := gen.GenerateForProfile(ctx, profile, &GenerateOptions{
			Hostname: "no-assigner-vm",
		})
		if err != nil {
			t.Fatalf("GenerateForProfile failed: %v", err)
		}

		if instance.DeviceProfileID != profile.ID {
			t.Errorf("expected profile ID %d, got %d", profile.ID, instance.DeviceProfileID)
		}

		if instance.DeviceProfile != profile {
			t.Error("expected profile reference to be set")
		}
	})
}

func TestGenerateForProfile_AssignerError(t *testing.T) {
	t.Run("propagates assigner error", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, err := NewGenerator(config, mockService, nil)
		if err != nil {
			t.Fatalf("NewGenerator failed: %v", err)
		}

		assigner := &mockProfileAssigner{
			assignErr: errors.New("profile service unavailable"),
		}
		gen.SetProfileAssigner(assigner)

		ctx := context.Background()
		profile := &entities.DeviceProfile{
			ID:   700,
			Name: "assigner-error-test",
		}

		_, err = gen.GenerateForProfile(ctx, profile, &GenerateOptions{
			Hostname: "assigner-err-vm",
		})
		if err == nil {
			t.Fatal("expected error when assigner fails")
		}

		var assignErr ErrProfileAssignmentFailed
		if !errors.As(err, &assignErr) {
			t.Errorf("expected ErrProfileAssignmentFailed, got %T: %v", err, err)
		}

		if assignErr.ProfileID != profile.ID {
			t.Errorf("expected profile ID %d in error, got %d", profile.ID, assignErr.ProfileID)
		}

		if assignErr.Cause == nil {
			t.Error("expected non-nil cause in ErrProfileAssignmentFailed")
		}

		if assignErr.Unwrap().Error() != "profile service unavailable" {
			t.Errorf("expected unwrapped cause 'profile service unavailable', got %s", assignErr.Unwrap().Error())
		}
	})
}

func TestGenerator_Get(t *testing.T) {
	t.Run("retrieves existing instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()

		// Create an instance first
		created, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "get-test"})

		// Retrieve it
		retrieved, err := gen.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if retrieved.ID != created.ID {
			t.Errorf("expected ID %s, got %s", created.ID, retrieved.ID)
		}
	})

	t.Run("fails for non-existent instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.Get(ctx, "non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent instance")
		}

		var notFoundErr ErrVTPMNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("expected ErrVTPMNotFound, got %T", err)
		}
	})

	t.Run("returns other errors as-is", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		// Set a non-BundleNotFound error
		mockService.getErr = errors.New("database connection failed")

		ctx := context.Background()
		_, err := gen.Get(ctx, "some-id")
		if err == nil {
			t.Fatal("expected error")
		}

		// Should not be ErrVTPMNotFound
		var notFoundErr ErrVTPMNotFound
		if errors.As(err, &notFoundErr) {
			t.Error("should not be ErrVTPMNotFound")
		}

		if err.Error() != "database connection failed" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestGenerator_GetByProfile(t *testing.T) {
	t.Run("retrieves instance by profile ID", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		profile := &entities.DeviceProfile{ID: 789}

		created, _ := gen.GenerateForProfile(ctx, profile, nil)

		retrieved, err := gen.GetByProfile(ctx, profile.ID)
		if err != nil {
			t.Fatalf("GetByProfile failed: %v", err)
		}

		if retrieved.ID != created.ID {
			t.Errorf("expected ID %s, got %s", created.ID, retrieved.ID)
		}
	})

	t.Run("fails for unassociated profile", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.GetByProfile(ctx, 999)
		if err == nil {
			t.Fatal("expected error for unassociated profile")
		}

		var notAssocErr ErrProfileNotAssociated
		if !errors.As(err, &notAssocErr) {
			t.Errorf("expected ErrProfileNotAssociated, got %T", err)
		}
	})
}

func TestGenerator_Delete(t *testing.T) {
	t.Run("deletes existing instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		created, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "delete-test"})

		err := gen.Delete(ctx, created.ID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Verify it's deleted
		_, err = gen.Get(ctx, created.ID)
		if err == nil {
			t.Error("expected error after deletion")
		}
	})

	t.Run("removes profile association on delete", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		profile := &entities.DeviceProfile{ID: 1000}

		created, _ := gen.GenerateForProfile(ctx, profile, nil)

		err := gen.Delete(ctx, created.ID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Profile should no longer be associated
		_, err = gen.GetByProfile(ctx, profile.ID)
		if err == nil {
			t.Error("expected error after profile association removed")
		}
	})

	t.Run("fails for non-existent instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		err := gen.Delete(ctx, "non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent instance")
		}
	})

	t.Run("returns other errors from GetBundle", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		// Set a non-BundleNotFound error
		mockService.getErr = errors.New("storage error")

		ctx := context.Background()
		err := gen.Delete(ctx, "some-id")
		if err == nil {
			t.Fatal("expected error")
		}

		if err.Error() != "storage error" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("returns error from DeleteBundle", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		created, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "delete-err-test"})

		// Set delete error after creation
		mockService.deleteErr = errors.New("delete failed")

		err := gen.Delete(ctx, created.ID)
		if err == nil {
			t.Fatal("expected error from DeleteBundle")
		}

		if err.Error() != "delete failed" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestGenerator_List(t *testing.T) {
	t.Run("lists all instances", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()

		// Create multiple instances
		gen.Generate(ctx, &GenerateOptions{Hostname: "list-1"})
		gen.Generate(ctx, &GenerateOptions{Hostname: "list-2"})
		gen.Generate(ctx, &GenerateOptions{Hostname: "list-3"})

		instances, err := gen.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(instances) != 3 {
			t.Errorf("expected 3 instances, got %d", len(instances))
		}
	})

	t.Run("returns empty list when no instances", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instances, err := gen.List(ctx)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(instances) != 0 {
			t.Errorf("expected 0 instances, got %d", len(instances))
		}
	})

	t.Run("returns error from ListBundles", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		mockService.listErr = errors.New("list bundles failed")
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.List(ctx)
		if err == nil {
			t.Fatal("expected error from ListBundles")
		}

		if err.Error() != "list bundles failed" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestGenerator_StartStop(t *testing.T) {
	t.Run("starts and stops instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "lifecycle-test"})

		// Start
		err := gen.Start(ctx, instance.ID)
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}

		if !gen.IsRunning(instance.ID) {
			t.Error("expected instance to be running after Start")
		}

		// Stop
		err = gen.Stop(ctx, instance.ID)
		if err != nil {
			t.Fatalf("Stop failed: %v", err)
		}

		if gen.IsRunning(instance.ID) {
			t.Error("expected instance to be stopped after Stop")
		}
	})

	t.Run("IsRunning returns false for non-existent", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		if gen.IsRunning("non-existent") {
			t.Error("expected IsRunning to return false for non-existent")
		}
	})

	t.Run("Start returns error on failure", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "start-err-test"})

		mockService.startErr = errors.New("start failed")

		err := gen.Start(ctx, instance.ID)
		if err == nil {
			t.Fatal("expected error from Start")
		}

		if err.Error() != "start failed" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Stop returns error on failure", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "stop-err-test"})

		// Start first
		gen.Start(ctx, instance.ID)

		mockService.stopErr = errors.New("stop failed")

		err := gen.Stop(ctx, instance.ID)
		if err == nil {
			t.Fatal("expected error from Stop")
		}

		if err.Error() != "stop failed" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestGenerator_GetEKFingerprint(t *testing.T) {
	t.Run("returns fingerprint from manifest", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "fingerprint-test"})

		fingerprint, err := gen.GetEKFingerprint(ctx, instance.ID)
		if err != nil {
			t.Fatalf("GetEKFingerprint failed: %v", err)
		}

		if fingerprint == "" {
			t.Error("expected non-empty fingerprint")
		}
	})

	t.Run("fails for non-existent instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.GetEKFingerprint(ctx, "non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent instance")
		}
	})

	t.Run("returns other errors from GetBundle", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		mockService.getErr = errors.New("storage unavailable")

		ctx := context.Background()
		_, err := gen.GetEKFingerprint(ctx, "some-id")
		if err == nil {
			t.Fatal("expected error")
		}

		if err.Error() != "storage unavailable" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("handles missing manifest and EK certificate", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		// Create bundle with no EK certificate in manifest
		mockService.bundles["no-ek"] = &Bundle{
			ID:       "no-ek",
			Manifest: &Manifest{ID: "no-ek"},
		}

		ctx := context.Background()
		// This will try to export EK certificate which will fail
		_, err := gen.GetEKFingerprint(ctx, "no-ek")
		// Expected to fail since no EK cert file exists and vTPM isn't running
		if err == nil {
			t.Fatal("expected error when no EK certificate available")
		}
	})
}

func TestGenerator_ExportEKCertificate(t *testing.T) {
	t.Run("fails for non-existent instance", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		_, err := gen.ExportEKCertificate(ctx, "non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent instance")
		}

		var notFoundErr ErrVTPMNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("expected ErrVTPMNotFound, got %T: %v", err, err)
		}
	})

	t.Run("returns other errors from GetBundle", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		mockService.getErr = errors.New("storage error")

		ctx := context.Background()
		_, err := gen.ExportEKCertificate(ctx, "some-id")
		if err == nil {
			t.Fatal("expected error")
		}

		if err.Error() != "storage error" {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("fails when certificate file does not exist and vTPM not running", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &VTPMConfig{StoragePath: tmpDir}
		mockService := newMockVTPMService()
		mockService.storagePath = tmpDir
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "export-test"})

		// vTPM is not running, certificate file doesn't exist
		_, err := gen.ExportEKCertificate(ctx, instance.ID)
		if err == nil {
			t.Fatal("expected error when certificate file doesn't exist")
		}

		var ekErr ErrEKGenerationFailed
		if !errors.As(err, &ekErr) {
			t.Errorf("expected ErrEKGenerationFailed, got %T: %v", err, err)
		}
	})
}

func TestGenerator_SaveLoadMetadata(t *testing.T) {
	t.Run("saves and loads metadata", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &VTPMConfig{StoragePath: tmpDir}
		mockService := newMockVTPMService()
		mockService.storagePath = tmpDir
		gen, _ := NewGenerator(config, mockService, nil)

		ctx := context.Background()
		instance, _ := gen.Generate(ctx, &GenerateOptions{Hostname: "metadata-test"})

		// Create the storage directory for the instance
		instanceDir := filepath.Join(tmpDir, instance.ID)
		if err := os.MkdirAll(instanceDir, 0755); err != nil {
			t.Fatalf("failed to create instance dir: %v", err)
		}

		// Update instance storage path to the actual temp dir
		instance.StoragePath = instanceDir
		instance.DeviceProfileID = 555

		// Save metadata
		err := gen.SaveMetadata(instance)
		if err != nil {
			t.Fatalf("SaveMetadata failed: %v", err)
		}

		// Verify file exists
		metadataPath := filepath.Join(instanceDir, "instance.json")
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			t.Fatal("metadata file was not created")
		}

		// Load metadata
		metadata, err := gen.LoadMetadata(instance.ID)
		if err != nil {
			t.Fatalf("LoadMetadata failed: %v", err)
		}

		if metadata.ID != instance.ID {
			t.Errorf("expected ID %s, got %s", instance.ID, metadata.ID)
		}
		if metadata.DeviceProfileID != 555 {
			t.Errorf("expected DeviceProfileID 555, got %d", metadata.DeviceProfileID)
		}
		if metadata.SRKHandle != instance.SRKHandle {
			t.Errorf("expected SRKHandle 0x%X, got 0x%X", instance.SRKHandle, metadata.SRKHandle)
		}
	})

	t.Run("LoadMetadata fails for non-existent instance", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &VTPMConfig{StoragePath: tmpDir}
		mockService := newMockVTPMService()
		mockService.storagePath = tmpDir
		gen, _ := NewGenerator(config, mockService, nil)

		_, err := gen.LoadMetadata("non-existent")
		if err == nil {
			t.Fatal("expected error for non-existent metadata")
		}

		var notFoundErr ErrVTPMNotFound
		if !errors.As(err, &notFoundErr) {
			t.Errorf("expected ErrVTPMNotFound, got %T: %v", err, err)
		}
	})

	t.Run("LoadMetadata fails for invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &VTPMConfig{StoragePath: tmpDir}
		mockService := newMockVTPMService()
		mockService.storagePath = tmpDir
		gen, _ := NewGenerator(config, mockService, nil)

		// Create directory and invalid metadata file
		instanceDir := filepath.Join(tmpDir, "invalid-json")
		if err := os.MkdirAll(instanceDir, 0755); err != nil {
			t.Fatalf("failed to create instance dir: %v", err)
		}

		metadataPath := filepath.Join(instanceDir, "instance.json")
		if err := os.WriteFile(metadataPath, []byte("invalid json{"), 0600); err != nil {
			t.Fatalf("failed to write invalid metadata: %v", err)
		}

		_, err := gen.LoadMetadata("invalid-json")
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}

		var manifestErr ErrInvalidManifest
		if !errors.As(err, &manifestErr) {
			t.Errorf("expected ErrInvalidManifest, got %T: %v", err, err)
		}
	})

	t.Run("SaveMetadata fails on write error", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		instance := &VTPMInstance{
			ID:          "test-instance",
			StoragePath: "/nonexistent/path/that/cannot/exist",
			SRKHandle:   SRKHandle,
		}

		err := gen.SaveMetadata(instance)
		if err == nil {
			t.Fatal("expected error when writing to non-existent path")
		}

		var genErr ErrGenerationFailed
		if !errors.As(err, &genErr) {
			t.Errorf("expected ErrGenerationFailed, got %T: %v", err, err)
		}
	})
}

func TestGenerator_Close(t *testing.T) {
	t.Run("closes without error", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		err := gen.Close()
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})
}

func TestVTPMConfig(t *testing.T) {
	t.Run("Validate succeeds with valid config", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
			Version:     TPMVersion20,
			EKAlgorithm: EKAlgorithmRSA,
		}

		err := config.Validate()
		if err != nil {
			t.Fatalf("Validate failed: %v", err)
		}
	})

	t.Run("Validate fails with empty StoragePath", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "",
		}

		err := config.Validate()
		if err == nil {
			t.Fatal("expected error for empty StoragePath")
		}
	})

	t.Run("Validate fails with invalid Version", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
			Version:     TPMVersion("invalid"),
		}

		err := config.Validate()
		if err == nil {
			t.Fatal("expected error for invalid Version")
		}
	})

	t.Run("Validate fails with invalid EKAlgorithm", func(t *testing.T) {
		config := &VTPMConfig{
			StoragePath: "/tmp/vtpm",
			EKAlgorithm: EKAlgorithm("invalid"),
		}

		err := config.Validate()
		if err == nil {
			t.Fatal("expected error for invalid EKAlgorithm")
		}
	})

	t.Run("ApplyDefaults sets all defaults", func(t *testing.T) {
		config := &VTPMConfig{}
		config.ApplyDefaults()

		if config.Version != TPMVersion20 {
			t.Errorf("expected default version %s, got %s", TPMVersion20, config.Version)
		}
		if config.EKAlgorithm != EKAlgorithmRSA {
			t.Errorf("expected default algorithm %s, got %s", EKAlgorithmRSA, config.EKAlgorithm)
		}
		if len(config.PCRBanks) == 0 {
			t.Error("expected default PCR banks")
		}
	})
}

func TestTPMVersion(t *testing.T) {
	t.Run("String returns version string", func(t *testing.T) {
		if TPMVersion20.String() != "2.0" {
			t.Errorf("unexpected string: %s", TPMVersion20.String())
		}
	})

	t.Run("IsValid returns true for valid versions", func(t *testing.T) {
		if !TPMVersion20.IsValid() {
			t.Error("TPMVersion20 should be valid")
		}
	})

	t.Run("IsValid returns false for invalid versions", func(t *testing.T) {
		invalid := TPMVersion("1.2")
		if invalid.IsValid() {
			t.Error("invalid version should not be valid")
		}
	})
}

func TestEKAlgorithm(t *testing.T) {
	t.Run("NVIndex returns correct indices", func(t *testing.T) {
		if EKAlgorithmRSA.NVIndex() != 0x01C00002 {
			t.Errorf("unexpected RSA NV index: 0x%X", EKAlgorithmRSA.NVIndex())
		}
		if EKAlgorithmECC.NVIndex() != 0x01C0000A {
			t.Errorf("unexpected ECC NV index: 0x%X", EKAlgorithmECC.NVIndex())
		}
	})

	t.Run("IsValid validates algorithms", func(t *testing.T) {
		if !EKAlgorithmRSA.IsValid() {
			t.Error("RSA should be valid")
		}
		if !EKAlgorithmECC.IsValid() {
			t.Error("ECC should be valid")
		}

		invalid := EKAlgorithm("DSA")
		if invalid.IsValid() {
			t.Error("DSA should not be valid")
		}
	})
}

func TestGeneratorErrors(t *testing.T) {
	t.Run("ErrVTPMNotFound", func(t *testing.T) {
		err := ErrVTPMNotFound{ID: "test-id"}
		expected := "vtpm: instance not found: test-id"
		if err.Error() != expected {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrVTPMAlreadyExists", func(t *testing.T) {
		err := ErrVTPMAlreadyExists{ID: "test-id"}
		expected := "vtpm: instance already exists: test-id"
		if err.Error() != expected {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrGenerationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrGenerationFailed{Reason: "test reason", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
		if !errors.Is(err, cause) {
			t.Error("errors.Is should match cause")
		}
	})

	t.Run("ErrGenerationFailed without cause", func(t *testing.T) {
		err := ErrGenerationFailed{Reason: "test reason"}
		expected := "vtpm: generation failed: test reason"
		if err.Error() != expected {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrProfileNotAssociated", func(t *testing.T) {
		err := ErrProfileNotAssociated{ProfileID: 456}
		expected := "vtpm: no instance associated with profile ID: 456"
		if err.Error() != expected {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrEKGenerationFailed", func(t *testing.T) {
		cause := errors.New("key generation error")
		err := ErrEKGenerationFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
		expected := "vtpm: EK generation failed: key generation error"
		if err.Error() != expected {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrSRKGenerationFailed", func(t *testing.T) {
		cause := errors.New("srk error")
		err := ErrSRKGenerationFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
		expected := "vtpm: SRK generation failed: srk error"
		if err.Error() != expected {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestBundleToInstance(t *testing.T) {
	t.Run("converts bundle without manifest", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		now := time.Now()
		bundle := &Bundle{
			ID:        "test-bundle",
			CreatedAt: now,
		}

		instance := gen.bundleToInstance(bundle)

		if instance.ID != "test-bundle" {
			t.Errorf("expected ID test-bundle, got %s", instance.ID)
		}
		if instance.Version != TPMVersion20 {
			t.Errorf("expected version %s, got %s", TPMVersion20, instance.Version)
		}
		if instance.EKFingerprint != "" {
			t.Errorf("expected empty EK fingerprint, got %s", instance.EKFingerprint)
		}
		if instance.DeviceProfileID != 0 {
			t.Errorf("expected DeviceProfileID 0, got %d", instance.DeviceProfileID)
		}
	})

	t.Run("converts bundle with manifest but no EK cert", func(t *testing.T) {
		config := &VTPMConfig{StoragePath: "/tmp/vtpm"}
		mockService := newMockVTPMService()
		gen, _ := NewGenerator(config, mockService, nil)

		now := time.Now()
		bundle := &Bundle{
			ID:        "test-bundle",
			CreatedAt: now,
			Manifest: &Manifest{
				ID:              "test-bundle",
				DeviceProfileID: 999,
			},
		}

		instance := gen.bundleToInstance(bundle)

		if instance.DeviceProfileID != 999 {
			t.Errorf("expected DeviceProfileID 999, got %d", instance.DeviceProfileID)
		}
		if instance.EKFingerprint != "" {
			t.Errorf("expected empty EK fingerprint, got %s", instance.EKFingerprint)
		}
	})
}

func TestInstanceMetadata(t *testing.T) {
	t.Run("InstanceMetadata struct has correct fields", func(t *testing.T) {
		now := time.Now()
		metadata := &InstanceMetadata{
			ID:              "test-id",
			Version:         TPMVersion20,
			EKFingerprint:   "sha256:fingerprint",
			SRKHandle:       SRKHandle,
			DeviceProfileID: 100,
			Labels:          map[string]string{"env": "test"},
			CreatedAt:       now,
		}

		if metadata.ID != "test-id" {
			t.Errorf("unexpected ID: %s", metadata.ID)
		}
		if metadata.Version != TPMVersion20 {
			t.Errorf("unexpected version: %s", metadata.Version)
		}
		if metadata.EKFingerprint != "sha256:fingerprint" {
			t.Errorf("unexpected fingerprint: %s", metadata.EKFingerprint)
		}
		if metadata.SRKHandle != SRKHandle {
			t.Errorf("unexpected SRK handle: 0x%X", metadata.SRKHandle)
		}
		if metadata.DeviceProfileID != 100 {
			t.Errorf("unexpected profile ID: %d", metadata.DeviceProfileID)
		}
		if metadata.Labels["env"] != "test" {
			t.Errorf("unexpected labels: %v", metadata.Labels)
		}
	})
}
