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
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Standard TPM handle constants for generated keys.
const (
	// SRKHandle is the standard handle for the Storage Root Key.
	SRKHandle uint32 = 0x81000001
)

// ProfileAssigner assigns device identity metadata to a profile.
// This decouples the vTPM generator from the device package to avoid
// import cycles. Implementations bind the EK serial and/or MAC address
// to a device profile so it becomes discoverable via FindConfigForDevice.
type ProfileAssigner interface {
	AssignToDevice(ctx context.Context, profileID uint64, ekSerial, mac string) error
}

// GeneratorService implements the Generator interface for vTPM instance generation.
// It wraps the VTPMService to provide a simplified API focused on generation
// and device profile association.
type GeneratorService struct {
	config          *VTPMConfig
	vtpmService     VTPMService
	logger          *logging.Logger
	profileAssigner ProfileAssigner
	profileIndex    map[uint64]string // profileID -> bundleID
	profileIndexMu  sync.RWMutex
}

// Ensure GeneratorService implements Generator.
var _ Generator = (*GeneratorService)(nil)

// NewGenerator creates a new vTPM generator service.
func NewGenerator(config *VTPMConfig, vtpmService VTPMService, logger *logging.Logger) (*GeneratorService, error) {
	if config == nil {
		config = DefaultVTPMConfig()
	}

	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if vtpmService == nil {
		return nil, ErrInvalidConfig{Field: "vtpmService", Reason: "cannot be nil"}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	gen := &GeneratorService{
		config:       config,
		vtpmService:  vtpmService,
		logger:       logger,
		profileIndex: make(map[uint64]string),
	}

	// Load profile index from existing bundles
	if err := gen.loadProfileIndex(); err != nil {
		logger.Warn("Failed to load profile index", "error", err)
	}

	return gen, nil
}

// SetProfileAssigner sets the optional ProfileAssigner used to bind
// the EK serial number to the device profile after vTPM generation.
// If not set, profile assignment is skipped (backward compatible).
func (g *GeneratorService) SetProfileAssigner(assigner ProfileAssigner) {
	g.profileAssigner = assigner
}

// loadProfileIndex scans existing bundles and builds the profile-to-bundle index.
func (g *GeneratorService) loadProfileIndex() error {
	ctx := context.Background()
	bundles, err := g.vtpmService.ListBundles(ctx, nil)
	if err != nil {
		return err
	}

	g.profileIndexMu.Lock()
	defer g.profileIndexMu.Unlock()

	for _, bundle := range bundles {
		if bundle.Manifest != nil && bundle.Manifest.DeviceProfileID != 0 {
			g.profileIndex[bundle.Manifest.DeviceProfileID] = bundle.ID
		}
	}

	return nil
}

// Generate creates a new vTPM instance with the specified options.
func (g *GeneratorService) Generate(ctx context.Context, opts *GenerateOptions) (*VTPMInstance, error) {
	return g.generateInternal(ctx, opts, 0)
}

// GenerateForProfile creates a vTPM instance associated with a device profile.
func (g *GeneratorService) GenerateForProfile(ctx context.Context, profile *entities.DeviceProfile, opts *GenerateOptions) (*VTPMInstance, error) {
	if profile == nil {
		return nil, ErrInvalidConfig{Field: "profile", Reason: "cannot be nil"}
	}

	// Check if profile already has an associated vTPM
	g.profileIndexMu.RLock()
	existingID, exists := g.profileIndex[profile.ID]
	g.profileIndexMu.RUnlock()

	if exists {
		return nil, ErrVTPMAlreadyExists{ID: existingID}
	}

	instance, err := g.generateInternal(ctx, opts, profile.ID)
	if err != nil {
		return nil, err
	}

	instance.DeviceProfileID = profile.ID
	instance.DeviceProfile = profile

	// Assign EK serial to the profile if a ProfileAssigner is configured
	if g.profileAssigner != nil {
		ekSerial := g.extractEKSerial(instance)
		if ekSerial != "" {
			if err := g.profileAssigner.AssignToDevice(ctx, profile.ID, ekSerial, ""); err != nil {
				return nil, ErrProfileAssignmentFailed{
					ProfileID: profile.ID,
					EKSerial:  ekSerial,
					Cause:     err,
				}
			}

			g.logger.Info("Assigned EK serial to device profile",
				"profileID", profile.ID,
				"ekSerial", ekSerial,
				"bundleID", instance.ID)
		}
	}

	// Update profile index
	g.profileIndexMu.Lock()
	g.profileIndex[profile.ID] = instance.ID
	g.profileIndexMu.Unlock()

	return instance, nil
}

// extractEKSerial extracts the EK certificate serial number from a vTPM instance.
// It checks the bundle manifest for the serial number stored during bundle creation.
func (g *GeneratorService) extractEKSerial(instance *VTPMInstance) string {
	ctx := context.Background()
	bundle, err := g.vtpmService.GetBundle(ctx, instance.ID)
	if err != nil {
		g.logger.Warn("Failed to get bundle for EK serial extraction",
			"bundleID", instance.ID, "error", err)
		return ""
	}

	if bundle.Manifest != nil && bundle.Manifest.EKCertificate != nil {
		return bundle.Manifest.EKCertificate.SerialNumber
	}

	return ""
}

// generateInternal performs the actual vTPM generation.
func (g *GeneratorService) generateInternal(ctx context.Context, opts *GenerateOptions, profileID uint64) (*VTPMInstance, error) {
	if opts == nil {
		opts = &GenerateOptions{}
	}

	// Apply defaults
	ekAlgorithm := opts.EKAlgorithm
	if ekAlgorithm == "" {
		ekAlgorithm = g.config.EKAlgorithm
	}

	hostname := opts.Hostname
	if hostname == "" {
		hostname = "vtpm-instance"
	}

	g.logger.Info("Generating vTPM instance",
		"hostname", hostname,
		"algorithm", ekAlgorithm,
		"secureBoot", opts.SecureBootEnabled,
		"profileID", profileID)

	// Create bundle options
	bundleOpts := &CreateBundleOptions{
		Mode:              BundleModePreAssigned,
		Hostname:          hostname,
		EKAlgorithm:       ekAlgorithm,
		SecureBootEnabled: opts.SecureBootEnabled,
		Labels:            opts.Labels,
		DeviceProfileID:   profileID,
	}

	// Create the bundle using VTPMService
	bundle, err := g.vtpmService.CreateBundle(ctx, bundleOpts)
	if err != nil {
		return nil, ErrGenerationFailed{Reason: "failed to create bundle", Cause: err}
	}

	// Build VTPMInstance from bundle
	instance := g.bundleToInstance(bundle)

	g.logger.Info("vTPM instance generated successfully",
		"id", instance.ID,
		"ekFingerprint", instance.EKFingerprint,
		"storagePath", instance.StoragePath)

	return instance, nil
}

// bundleToInstance converts a Bundle to a VTPMInstance.
func (g *GeneratorService) bundleToInstance(bundle *Bundle) *VTPMInstance {
	instance := &VTPMInstance{
		ID:          bundle.ID,
		Version:     g.config.Version,
		StoragePath: g.vtpmService.GetBundlePath(bundle.ID),
		SRKHandle:   SRKHandle,
		SocketPath:  g.vtpmService.GetTPMSocketPath(bundle.ID),
		NVRAMPath:   g.vtpmService.GetNVRAMPath(bundle.ID),
		CreatedAt:   bundle.CreatedAt,
		Running:     g.vtpmService.IsRunning(bundle.ID),
	}

	// Extract EK fingerprint from manifest
	if bundle.Manifest != nil {
		if bundle.Manifest.EKCertificate != nil {
			instance.EKFingerprint = bundle.Manifest.EKCertificate.Fingerprint
		}
		if bundle.Manifest.DeviceProfileID != 0 {
			instance.DeviceProfileID = bundle.Manifest.DeviceProfileID
		}
	}

	return instance
}

// Get retrieves a vTPM instance by ID.
func (g *GeneratorService) Get(ctx context.Context, id string) (*VTPMInstance, error) {
	bundle, err := g.vtpmService.GetBundle(ctx, id)
	if err != nil {
		// Check if it's a bundle not found error
		if _, ok := err.(ErrBundleNotFound); ok {
			return nil, ErrVTPMNotFound{ID: id}
		}
		return nil, err
	}

	return g.bundleToInstance(bundle), nil
}

// GetByProfile retrieves the vTPM instance associated with a device profile.
func (g *GeneratorService) GetByProfile(ctx context.Context, profileID uint64) (*VTPMInstance, error) {
	g.profileIndexMu.RLock()
	bundleID, exists := g.profileIndex[profileID]
	g.profileIndexMu.RUnlock()

	if !exists {
		return nil, ErrProfileNotAssociated{ProfileID: profileID}
	}

	return g.Get(ctx, bundleID)
}

// Delete removes a vTPM instance and all its state files.
func (g *GeneratorService) Delete(ctx context.Context, id string) error {
	// Get the bundle first to check for profile association
	bundle, err := g.vtpmService.GetBundle(ctx, id)
	if err != nil {
		if _, ok := err.(ErrBundleNotFound); ok {
			return ErrVTPMNotFound{ID: id}
		}
		return err
	}

	// Remove from profile index if associated
	if bundle.Manifest != nil && bundle.Manifest.DeviceProfileID != 0 {
		g.profileIndexMu.Lock()
		delete(g.profileIndex, bundle.Manifest.DeviceProfileID)
		g.profileIndexMu.Unlock()
	}

	// Delete the bundle
	if err := g.vtpmService.DeleteBundle(ctx, id); err != nil {
		return err
	}

	g.logger.Info("vTPM instance deleted", "id", id)
	return nil
}

// List returns all vTPM instances.
func (g *GeneratorService) List(ctx context.Context) ([]*VTPMInstance, error) {
	bundles, err := g.vtpmService.ListBundles(ctx, nil)
	if err != nil {
		return nil, err
	}

	instances := make([]*VTPMInstance, 0, len(bundles))
	for _, bundle := range bundles {
		instances = append(instances, g.bundleToInstance(bundle))
	}

	return instances, nil
}

// Start starts the swtpm daemon for the vTPM instance.
func (g *GeneratorService) Start(ctx context.Context, id string) error {
	if err := g.vtpmService.Start(ctx, id); err != nil {
		return err
	}
	g.logger.Info("vTPM instance started", "id", id)
	return nil
}

// Stop stops the swtpm daemon for the vTPM instance.
func (g *GeneratorService) Stop(ctx context.Context, id string) error {
	if err := g.vtpmService.Stop(ctx, id); err != nil {
		return err
	}
	g.logger.Info("vTPM instance stopped", "id", id)
	return nil
}

// IsRunning checks if the vTPM instance is running.
func (g *GeneratorService) IsRunning(id string) bool {
	return g.vtpmService.IsRunning(id)
}

// ExportEKCertificate exports the EK certificate for the vTPM instance.
func (g *GeneratorService) ExportEKCertificate(ctx context.Context, id string) (*x509.Certificate, error) {
	bundle, err := g.vtpmService.GetBundle(ctx, id)
	if err != nil {
		if _, ok := err.(ErrBundleNotFound); ok {
			return nil, ErrVTPMNotFound{ID: id}
		}
		return nil, err
	}

	// Read the EK certificate from the bundle
	bundlePath := g.vtpmService.GetBundlePath(id)
	ekCertPath := filepath.Join(bundlePath, "tpm", "ek.crt")

	certPEM, err := os.ReadFile(ekCertPath)
	if err != nil {
		// If no separate cert file, try to read from NV RAM when running
		if g.vtpmService.IsRunning(id) {
			return g.readEKCertFromRunningTPM(ctx, id, bundle)
		}
		return nil, ErrEKGenerationFailed{Cause: err}
	}

	cert, err := x509.ParseCertificate(certPEM)
	if err != nil {
		// Try PEM decoding first
		return nil, ErrEKGenerationFailed{Cause: err}
	}

	return cert, nil
}

// readEKCertFromRunningTPM reads the EK certificate from a running vTPM's NV RAM.
func (g *GeneratorService) readEKCertFromRunningTPM(ctx context.Context, id string, bundle *Bundle) (*x509.Certificate, error) {
	socketPath := g.vtpmService.GetTPMSocketPath(id)

	// Determine algorithm from manifest
	algorithm := EKAlgorithmRSA
	if bundle.Manifest != nil && bundle.Manifest.EKAlgorithm != "" {
		algorithm = bundle.Manifest.EKAlgorithm
	}

	// Use EKCertInjector to read the certificate
	injector := NewEKCertInjector(socketPath, g.logger)
	cert, err := injector.ReadCertificate(ctx, algorithm)
	if err != nil {
		return nil, ErrEKGenerationFailed{Cause: err}
	}

	return cert, nil
}

// GetEKFingerprint returns the EK certificate fingerprint.
func (g *GeneratorService) GetEKFingerprint(ctx context.Context, id string) (string, error) {
	bundle, err := g.vtpmService.GetBundle(ctx, id)
	if err != nil {
		if _, ok := err.(ErrBundleNotFound); ok {
			return "", ErrVTPMNotFound{ID: id}
		}
		return "", err
	}

	if bundle.Manifest != nil && bundle.Manifest.EKCertificate != nil {
		return bundle.Manifest.EKCertificate.Fingerprint, nil
	}

	// If fingerprint not in manifest, try to compute it from the certificate
	cert, err := g.ExportEKCertificate(ctx, id)
	if err != nil {
		return "", err
	}

	return certFingerprint(cert), nil
}

// Close releases resources held by the generator.
func (g *GeneratorService) Close() error {
	return g.vtpmService.Close()
}

// InstanceMetadata contains serializable metadata for a vTPM instance.
type InstanceMetadata struct {
	ID              string            `json:"id"`
	Version         TPMVersion        `json:"version"`
	EKFingerprint   string            `json:"ek_fingerprint"`
	SRKHandle       uint32            `json:"srk_handle"`
	DeviceProfileID uint64            `json:"device_profile_id,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
}

// SaveMetadata saves instance metadata to a JSON file.
func (g *GeneratorService) SaveMetadata(instance *VTPMInstance) error {
	metadata := &InstanceMetadata{
		ID:              instance.ID,
		Version:         instance.Version,
		EKFingerprint:   instance.EKFingerprint,
		SRKHandle:       instance.SRKHandle,
		DeviceProfileID: instance.DeviceProfileID,
		CreatedAt:       instance.CreatedAt,
	}

	metadataPath := filepath.Join(instance.StoragePath, "instance.json")
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return ErrGenerationFailed{Reason: "failed to marshal metadata", Cause: err}
	}

	if err := os.WriteFile(metadataPath, data, 0600); err != nil {
		return ErrGenerationFailed{Reason: "failed to write metadata", Cause: err}
	}

	return nil
}

// LoadMetadata loads instance metadata from a JSON file.
func (g *GeneratorService) LoadMetadata(id string) (*InstanceMetadata, error) {
	bundlePath := g.vtpmService.GetBundlePath(id)
	metadataPath := filepath.Join(bundlePath, "instance.json")

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, ErrVTPMNotFound{ID: id}
	}

	var metadata InstanceMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, ErrInvalidManifest{Reason: "failed to parse instance metadata"}
	}

	return &metadata, nil
}
