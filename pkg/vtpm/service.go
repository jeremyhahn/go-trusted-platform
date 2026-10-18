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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

// CertificateAuthority interface for CA operations.
// This abstracts the CA dependency to avoid circular imports.
// Implementations should wrap the actual CA and provide EK certificate issuance.
type CertificateAuthority interface {
	// IssueEKCertificate issues an EK certificate for the given public key.
	// The publicKey is the EK public key (RSA or ECC) and hostname is for the certificate CN.
	IssueEKCertificate(ctx context.Context, publicKey crypto.PublicKey, hostname string) (*x509.Certificate, error)
}

// runningInstance tracks a running swtpm instance for a bundle.
type runningInstance struct {
	swtpm      *swtpm.SWTPM
	socketPath string
	tpmOps     *TPMOperations
}

// Service implements the VTPMService interface.
type Service struct {
	config    *Config
	logger    *logging.Logger
	ca        CertificateAuthority
	mu        sync.RWMutex
	instances map[string]*runningInstance // bundleID -> running instance
}

// NewService creates a new vTPM service.
func NewService(config *Config, logger *logging.Logger, ca CertificateAuthority) (*Service, error) {
	if config == nil {
		config = DefaultConfig()
	}

	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Create base directories
	if err := os.MkdirAll(config.BundlesDir(), 0700); err != nil {
		return nil, ErrInvalidConfig{Field: "BaseDir", Reason: fmt.Sprintf("failed to create bundles directory: %v", err)}
	}
	if err := os.MkdirAll(config.TemplatesDir(), 0700); err != nil {
		return nil, ErrInvalidConfig{Field: "BaseDir", Reason: fmt.Sprintf("failed to create templates directory: %v", err)}
	}

	return &Service{
		config:    config,
		logger:    logger,
		ca:        ca,
		instances: make(map[string]*runningInstance),
	}, nil
}

// CreateBundle creates a new vTPM bundle.
func (s *Service) CreateBundle(ctx context.Context, opts *CreateBundleOptions) (*Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if opts == nil {
		return nil, ErrInvalidConfig{Field: "opts", Reason: "cannot be nil"}
	}

	// Set defaults
	if opts.Mode == "" {
		opts.Mode = BundleModePreAssigned
	}
	if opts.EKAlgorithm == "" {
		opts.EKAlgorithm = s.config.EKAlgorithm
	}

	// Validate options
	if !opts.Mode.IsValid() {
		return nil, ErrInvalidConfig{Field: "Mode", Reason: fmt.Sprintf("invalid mode: %s", opts.Mode)}
	}
	if opts.Mode == BundleModePreAssigned && opts.Hostname == "" {
		return nil, ErrInvalidConfig{Field: "Hostname", Reason: "required for pre-assigned mode"}
	}
	if !opts.EKAlgorithm.IsValid() {
		return nil, ErrInvalidEKAlgorithm{Algorithm: string(opts.EKAlgorithm)}
	}

	// Generate bundle ID
	bundleID := s.generateBundleID(opts.Hostname)
	bundlePath := s.config.BundlePath(bundleID)

	// Check if bundle already exists
	if _, err := os.Stat(bundlePath); err == nil {
		return nil, ErrBundleAlreadyExists{ID: bundleID}
	}

	s.logger.Info("Creating vTPM bundle",
		"id", bundleID,
		"mode", opts.Mode,
		"hostname", opts.Hostname,
		"secureBoot", opts.SecureBootEnabled)

	// Create bundle directory structure
	if err := s.createBundleDirectories(bundlePath); err != nil {
		return nil, err
	}

	// Build the bundle
	bundle, err := s.buildBundle(ctx, bundleID, bundlePath, opts)
	if err != nil {
		return nil, removeFailedBundle(bundleID, bundlePath, err)
	}

	return bundle, nil
}

// removeFailedBundle removes the directory of a bundle that failed to build and
// returns the build error. When the directory cannot be removed the result is
// ErrBundleCleanupFailed, which still unwraps to the build error.
func removeFailedBundle(bundleID, bundlePath string, buildErr error) error {
	if err := os.RemoveAll(bundlePath); err != nil {
		return ErrBundleCleanupFailed{BundleID: bundleID, Path: bundlePath, BuildErr: buildErr, Cause: err}
	}
	return buildErr
}

// generateBundleID generates a unique bundle ID.
func (s *Service) generateBundleID(hostname string) string {
	timestamp := time.Now().UnixNano()
	if hostname != "" {
		return fmt.Sprintf("%s-%d", hostname, timestamp)
	}
	return fmt.Sprintf("vtpm-%d", timestamp)
}

// createBundleDirectories creates the bundle directory structure.
func (s *Service) createBundleDirectories(bundlePath string) error {
	dirs := []string{
		bundlePath,
		filepath.Join(bundlePath, "tpm"),
		filepath.Join(bundlePath, "ovmf"),
		filepath.Join(bundlePath, "secure-boot-keys"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return ErrInvalidConfig{Field: "bundlePath", Reason: fmt.Sprintf("failed to create directory %s: %v", dir, err)}
		}
	}

	return nil
}

// buildBundle builds the complete vTPM bundle.
func (s *Service) buildBundle(ctx context.Context, bundleID, bundlePath string, opts *CreateBundleOptions) (*Bundle, error) {
	tpmDir := filepath.Join(bundlePath, "tpm")
	ovmfDir := filepath.Join(bundlePath, "ovmf")
	sbKeysDir := filepath.Join(bundlePath, "secure-boot-keys")

	// Step 1: Initialize swtpm
	s.logger.Debug("Initializing swtpm state")
	swtpmConfig := &swtpm.Config{
		StateDir: tpmDir,
		PCRBanks: s.config.PCRBanks,
		Debug:    s.config.Debug,
	}

	sw, err := swtpm.NewSWTPM(swtpmConfig, s.logger)
	if err != nil {
		return nil, ErrSWTPMOperationFailed{Operation: "create", Cause: err}
	}

	if err := sw.Initialize(ctx); err != nil {
		return nil, ErrSWTPMOperationFailed{Operation: "initialize", Cause: err}
	}

	// Step 2: Start swtpm and wait for socket to be ready before sending startup
	if err := sw.Start(ctx); err != nil {
		return nil, ErrSWTPMOperationFailed{Operation: "start", Cause: err}
	}
	defer sw.Stop()

	// Wait for socket to be ready - this is critical to avoid race condition
	// where we try to connect before swtpm has created the socket file
	if err := sw.WaitForSocket(10 * time.Second); err != nil {
		return nil, ErrSWTPMOperationFailed{Operation: "wait_for_socket", Cause: err}
	}

	if err := sw.SendStartup(); err != nil {
		return nil, ErrSWTPMOperationFailed{Operation: "startup", Cause: err}
	}

	// Step 3: For pre-assigned mode, inject EK certificate
	var ekCertInfo *EKCertInfo
	if opts.Mode == BundleModePreAssigned && s.ca != nil {
		ekCertInfo, err = s.injectEKCertificate(ctx, sw.SocketPath(), opts)
		if err != nil {
			return nil, err
		}
	}

	// Step 4: Stop swtpm before copying NVRAM (state is persisted)
	if err := sw.Stop(); err != nil {
		s.logger.Warn("Failed to stop swtpm gracefully", "error", err)
	}

	// Step 5: Copy OVMF NVRAM template
	nvramPath := filepath.Join(ovmfDir, "OVMF_VARS.fd")
	if err := s.copyFile(s.config.OVMFVars, nvramPath); err != nil {
		return nil, ErrInvalidConfig{Field: "OVMFVars", Reason: fmt.Sprintf("failed to copy NVRAM: %v", err)}
	}

	// Step 6: Generate and enroll Secure Boot keys
	var sbKeyInfo *SecureBootKeyInfo
	var sbKeyPaths *SecureBootKeyPaths
	if opts.SecureBootEnabled {
		sbKeyInfo, sbKeyPaths, err = s.setupSecureBoot(ctx, sbKeysDir, nvramPath, bundleID)
		if err != nil {
			return nil, err
		}
	}

	// Step 7: Generate manifest
	manifest, err := s.generateManifest(bundleID, bundlePath, opts, ekCertInfo, sbKeyInfo)
	if err != nil {
		return nil, err
	}

	// Write manifest
	manifestPath := filepath.Join(bundlePath, "manifest.json")
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to marshal manifest: %v", err)}
	}
	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to write manifest: %v", err)}
	}

	// Build bundle struct
	bundle := &Bundle{
		ID:       bundleID,
		Mode:     opts.Mode,
		Manifest: manifest,
		TPMState: &TPMState{
			StateDir:    tpmDir,
			PermallFile: filepath.Join(tpmDir, "tpm2-00.permall"),
		},
		OVMFState: &OVMFState{
			NVRAMFile: nvramPath,
		},
		SecureBootKeys: sbKeyPaths,
		CreatedAt:      manifest.CreatedAt,
	}

	s.logger.Info("vTPM bundle created successfully",
		"id", bundleID,
		"path", bundlePath)

	return bundle, nil
}

// injectEKCertificate issues and injects an EK certificate into the TPM NV RAM.
// This uses TPMOperations to create the EK and extract the public key.
func (s *Service) injectEKCertificate(ctx context.Context, socketPath string, opts *CreateBundleOptions) (*EKCertInfo, error) {
	s.logger.Debug("Injecting EK certificate",
		"hostname", opts.Hostname,
		"algorithm", opts.EKAlgorithm)

	// Step 1: Create TPM operations wrapper with algorithm configuration
	tpmOps, err := NewTPMOperations(socketPath, opts.EKAlgorithm, opts.Hostname, s.logger)
	if err != nil {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}
	defer tpmOps.Close()

	// Step 2: Provision the vTPM using go-xkms's provisioning flow
	// This creates EK, SRK, and IAK with proper TCG templates
	if err := tpmOps.Provision(""); err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: &WrappedError{Msg: "failed to provision vTPM", Err: err}}
	}

	// Step 3: Get EK public key using go-xkms
	ekPubKey, err := tpmOps.GetEKPublicKey()
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: err}
	}

	s.logger.Debug("EK public key extracted successfully",
		"algorithm", opts.EKAlgorithm)

	// Step 4: Issue EK certificate from CA
	ekCert, err := s.ca.IssueEKCertificate(ctx, ekPubKey, opts.Hostname)
	if err != nil {
		return nil, ErrCAUnavailable{Cause: err}
	}

	s.logger.Debug("EK certificate issued by CA",
		"subject", ekCert.Subject.CommonName,
		"serial", ekCert.SerialNumber.String())

	// Step 5: Inject certificate into NV RAM using go-xkms's ProvisionEKCert
	if err := tpmOps.InjectEKCertificate(ekCert); err != nil {
		return nil, err
	}

	s.logger.Info("EK certificate injected and verified successfully",
		"hostname", opts.Hostname,
		"algorithm", opts.EKAlgorithm,
		"nvIndex", fmt.Sprintf("0x%08X", opts.EKAlgorithm.NVIndex()))

	// Step 7: Return EKCertInfo with metadata
	ekCertInfo := &EKCertInfo{
		Subject:      ekCert.Subject.String(),
		Issuer:       ekCert.Issuer.String(),
		SerialNumber: ekCert.SerialNumber.String(),
		NotBefore:    ekCert.NotBefore,
		NotAfter:     ekCert.NotAfter,
		Fingerprint:  certFingerprint(ekCert),
	}

	return ekCertInfo, nil
}

// injectEKCertificateForClone issues and injects an EK certificate for a cloned bundle.
// This starts swtpm, injects the EK certificate, and stops swtpm.
// Returns nil, nil if the injection fails (best-effort operation for cloning).
func (s *Service) injectEKCertificateForClone(ctx context.Context, bundlePath string, hostname string, algorithm EKAlgorithm) (*EKCertInfo, error) {
	if s.ca == nil {
		s.logger.Warn("No CA configured, skipping EK certificate injection for cloned bundle")
		return nil, nil
	}

	tpmDir := filepath.Join(bundlePath, "tpm")

	s.logger.Debug("Starting swtpm for EK certificate injection",
		"bundlePath", bundlePath,
		"hostname", hostname,
		"algorithm", algorithm)

	// Create and start swtpm instance
	swtpmConfig := &swtpm.Config{
		StateDir: tpmDir,
		PCRBanks: s.config.PCRBanks,
		Debug:    s.config.Debug,
	}

	sw, err := swtpm.NewSWTPM(swtpmConfig, s.logger)
	if err != nil {
		s.logger.Warn("Failed to create swtpm for EK injection, skipping",
			"error", err,
			"bundlePath", bundlePath)
		return nil, nil
	}

	// Start swtpm
	if err := sw.Start(ctx); err != nil {
		s.logger.Warn("Failed to start swtpm for EK injection, skipping",
			"error", err,
			"bundlePath", bundlePath)
		return nil, nil
	}
	defer sw.Stop()

	// Wait for socket to be ready
	if err := sw.WaitForSocket(10 * time.Second); err != nil {
		s.logger.Warn("swtpm socket not ready for EK injection, skipping",
			"error", err,
			"bundlePath", bundlePath)
		return nil, nil
	}

	// Send startup command
	if err := sw.SendStartup(); err != nil {
		s.logger.Warn("Failed to send startup to swtpm for EK injection, skipping",
			"error", err,
			"bundlePath", bundlePath)
		return nil, nil
	}

	// Inject EK certificate using the helper
	opts := &CreateBundleOptions{
		Hostname:    hostname,
		EKAlgorithm: algorithm,
	}
	ekCertInfo, err := s.injectEKCertificate(ctx, sw.SocketPath(), opts)
	if err != nil {
		s.logger.Warn("Failed to inject EK certificate, skipping",
			"error", err,
			"bundlePath", bundlePath)
		return nil, nil
	}

	// Stop swtpm to persist state
	if err := sw.Stop(); err != nil {
		s.logger.Warn("Failed to stop swtpm gracefully after EK injection", "error", err)
	}

	s.logger.Info("EK certificate injected successfully for cloned bundle",
		"hostname", hostname,
		"algorithm", algorithm)

	return ekCertInfo, nil
}

// setupSecureBoot generates Secure Boot keys and enrolls them.
func (s *Service) setupSecureBoot(ctx context.Context, keysDir, nvramPath, bundleID string) (*SecureBootKeyInfo, *SecureBootKeyPaths, error) {
	s.logger.Debug("Setting up Secure Boot keys")

	// Generate Secure Boot keys using secureboot.XKMSManager
	sbConfig := &secureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      secureboot.BackendFile,
		CommonName:   s.config.SecureBootCommonName,
		Organization: s.config.SecureBootOrganization,
		KeySize:      s.config.SecureBootKeySize,
		ValidYears:   s.config.SecureBootValidYears,
		ExportKeys:   true,
	}

	km, err := secureboot.NewXKMSManager(sbConfig, s.logger)
	if err != nil {
		return nil, nil, ErrSecureBootKeyGenFailed{Cause: err}
	}
	defer km.Close()

	if err := km.GenerateAll(ctx); err != nil {
		return nil, nil, ErrSecureBootKeyGenFailed{Cause: err}
	}

	// Get key paths and read certificates from files
	keyPaths := km.GetKeyPaths()

	pkCert, err := loadCertificateFromFile(keyPaths.PKCert)
	if err != nil {
		return nil, nil, ErrSecureBootKeyGenFailed{Cause: &WrappedError{Msg: "failed to load PK certificate", Err: err}}
	}
	kekCert, err := loadCertificateFromFile(keyPaths.KEKCert)
	if err != nil {
		return nil, nil, ErrSecureBootKeyGenFailed{Cause: &WrappedError{Msg: "failed to load KEK certificate", Err: err}}
	}
	dbCert, err := loadCertificateFromFile(keyPaths.DBCert)
	if err != nil {
		return nil, nil, ErrSecureBootKeyGenFailed{Cause: &WrappedError{Msg: "failed to load DB certificate", Err: err}}
	}

	// Enroll keys in OVMF NVRAM
	enrollerConfig := &qemu.SecureBootEnrollerConfig{
		KeysDir:      keysDir,
		NVRAMDir:     filepath.Dir(nvramPath),
		OVMFVarsPath: s.config.OVMFVars,
		Debug:        s.config.Debug,
	}

	enroller, err := qemu.NewSecureBootEnroller(enrollerConfig, s.logger)
	if err != nil {
		return nil, nil, ErrSecureBootEnrollmentFailed{Cause: err}
	}

	if err := enroller.EnrollKeys(ctx); err != nil {
		return nil, nil, ErrSecureBootEnrollmentFailed{Cause: err}
	}

	sbKeyInfo := &SecureBootKeyInfo{
		PKFingerprint:  certFingerprint(pkCert),
		KEKFingerprint: certFingerprint(kekCert),
		DBFingerprint:  certFingerprint(dbCert),
		OwnerGUID:      "", // Owner GUID is managed internally by enroller
	}

	sbKeyPaths := &SecureBootKeyPaths{
		Dir:     keysDir,
		PKKey:   filepath.Join(keysDir, "PK.key"),
		PKCert:  filepath.Join(keysDir, "PK.crt"),
		KEKKey:  filepath.Join(keysDir, "KEK.key"),
		KEKCert: filepath.Join(keysDir, "KEK.crt"),
		DBKey:   filepath.Join(keysDir, "DB.key"),
		DBCert:  filepath.Join(keysDir, "DB.crt"),
	}

	s.logger.Info("Secure Boot keys generated and enrolled",
		"keysDir", keysDir)

	return sbKeyInfo, sbKeyPaths, nil
}

// loadCertificateFromFile loads an X.509 certificate from a PEM file.
func loadCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &MessageError{Msg: "failed to decode PEM block"}
	}

	return x509.ParseCertificate(block.Bytes)
}

// generateManifest generates the bundle manifest.
func (s *Service) generateManifest(bundleID, bundlePath string, opts *CreateBundleOptions, ekCertInfo *EKCertInfo, sbKeyInfo *SecureBootKeyInfo) (*Manifest, error) {
	now := time.Now()

	// Calculate checksums
	checksums := make(map[string]string)

	// TPM state file
	tpmPermall := filepath.Join(bundlePath, "tpm", "tpm2-00.permall")
	if hash, err := fileChecksum(tpmPermall); err == nil {
		checksums["tpm/tpm2-00.permall"] = hash
	}

	// OVMF NVRAM
	ovmfVars := filepath.Join(bundlePath, "ovmf", "OVMF_VARS.fd")
	if hash, err := fileChecksum(ovmfVars); err == nil {
		checksums["ovmf/OVMF_VARS.fd"] = hash
	}

	// Secure Boot keys
	if opts.SecureBootEnabled {
		sbFiles := []string{"PK.key", "PK.crt", "KEK.key", "KEK.crt", "DB.key", "DB.crt"}
		for _, f := range sbFiles {
			path := filepath.Join(bundlePath, "secure-boot-keys", f)
			if hash, err := fileChecksum(path); err == nil {
				checksums["secure-boot-keys/"+f] = hash
			}
		}
	}

	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              opts.Mode,
		Hostname:          opts.Hostname,
		CreatedAt:         now,
		EKCertificate:     ekCertInfo,
		EKAlgorithm:       opts.EKAlgorithm,
		EKHandle:          opts.EKAlgorithm.NVIndex(),
		SecureBootEnabled: opts.SecureBootEnabled,
		SecureBootKeys:    sbKeyInfo,
		Checksums:         checksums,
		Labels:            opts.Labels,
	}

	return manifest, nil
}

// GetBundle retrieves a bundle by ID.
func (s *Service) GetBundle(ctx context.Context, id string) (*Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getBundleLocked(id)
}

// getBundleLocked retrieves a bundle by ID without acquiring a lock.
// Caller must hold at least a read lock.
func (s *Service) getBundleLocked(id string) (*Bundle, error) {
	bundlePath := s.config.BundlePath(id)
	manifestPath := filepath.Join(bundlePath, "manifest.json")

	if _, err := os.Stat(manifestPath); err != nil {
		return nil, ErrBundleNotFound{ID: id}
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to read manifest: %v", err)}
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to parse manifest: %v", err)}
	}

	bundle := &Bundle{
		ID:       manifest.ID,
		Mode:     manifest.Mode,
		Manifest: &manifest,
		TPMState: &TPMState{
			StateDir:    filepath.Join(bundlePath, "tpm"),
			PermallFile: filepath.Join(bundlePath, "tpm", "tpm2-00.permall"),
		},
		OVMFState: &OVMFState{
			NVRAMFile: filepath.Join(bundlePath, "ovmf", "OVMF_VARS.fd"),
		},
		CreatedAt:  manifest.CreatedAt,
		ClonedFrom: manifest.ClonedFrom,
	}

	if manifest.SecureBootEnabled {
		sbDir := filepath.Join(bundlePath, "secure-boot-keys")
		bundle.SecureBootKeys = &SecureBootKeyPaths{
			Dir:     sbDir,
			PKKey:   filepath.Join(sbDir, "PK.key"),
			PKCert:  filepath.Join(sbDir, "PK.crt"),
			KEKKey:  filepath.Join(sbDir, "KEK.key"),
			KEKCert: filepath.Join(sbDir, "KEK.crt"),
			DBKey:   filepath.Join(sbDir, "DB.key"),
			DBCert:  filepath.Join(sbDir, "DB.crt"),
		}
	}

	return bundle, nil
}

// DeleteBundle deletes a bundle.
func (s *Service) DeleteBundle(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop the instance if running
	if instance, exists := s.instances[id]; exists {
		if instance.tpmOps != nil {
			instance.tpmOps.Close()
		}
		if err := instance.swtpm.Stop(); err != nil {
			s.logger.Warn("Failed to stop vTPM before delete", "bundleID", id, "error", err)
		}
		delete(s.instances, id)
	}

	bundlePath := s.config.BundlePath(id)

	if _, err := os.Stat(bundlePath); err != nil {
		return ErrBundleNotFound{ID: id}
	}

	if err := os.RemoveAll(bundlePath); err != nil {
		return &WrappedError{Msg: "failed to delete bundle", Err: err}
	}

	s.logger.Info("Bundle deleted", "id", id)
	return nil
}

// ListBundles lists bundles matching the filter options.
func (s *Service) ListBundles(ctx context.Context, opts *ListOptions) ([]*Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.config.BundlesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []*Bundle{}, nil
		}
		return nil, &WrappedError{Msg: "failed to list bundles", Err: err}
	}

	var bundles []*Bundle
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Use locked version since we already hold the read lock
		bundle, err := s.getBundleLocked(entry.Name())
		if err != nil {
			s.logger.Warn("Failed to load bundle", "id", entry.Name(), "error", err)
			continue
		}

		// Apply filters
		if opts != nil {
			if opts.Mode != "" && bundle.Mode != opts.Mode {
				continue
			}
			if len(opts.Labels) > 0 {
				match := true
				for k, v := range opts.Labels {
					if bundle.Manifest.Labels[k] != v {
						match = false
						break
					}
				}
				if !match {
					continue
				}
			}
			if opts.DeviceProfileID != 0 &&
				(bundle.Manifest == nil || bundle.Manifest.DeviceProfileID != opts.DeviceProfileID) {
				continue
			}
		}

		bundles = append(bundles, bundle)
	}

	// Apply pagination
	if opts != nil {
		if opts.Offset > 0 && opts.Offset < len(bundles) {
			bundles = bundles[opts.Offset:]
		}
		if opts.Limit > 0 && opts.Limit < len(bundles) {
			bundles = bundles[:opts.Limit]
		}
	}

	return bundles, nil
}

// CreateTemplate creates a new vTPM template.
func (s *Service) CreateTemplate(ctx context.Context, opts *CreateTemplateOptions) (*Template, error) {
	// Templates are bundles without EK certificate
	bundleOpts := &CreateBundleOptions{
		Mode:              BundleModeTemplate,
		EKAlgorithm:       opts.EKAlgorithm,
		SecureBootEnabled: opts.SecureBootEnabled,
	}

	bundle, err := s.CreateBundle(ctx, bundleOpts)
	if err != nil {
		return nil, err
	}

	// Move from bundles to templates directory
	oldPath := s.config.BundlePath(bundle.ID)
	newPath := s.config.TemplatePath(opts.ID)

	if err := os.Rename(oldPath, newPath); err != nil {
		os.RemoveAll(oldPath)
		return nil, &WrappedError{Msg: "failed to move template", Err: err}
	}

	// Update manifest with template ID and description
	manifestPath := filepath.Join(newPath, "manifest.json")
	bundle.Manifest.ID = opts.ID
	bundle.Manifest.Description = opts.Description
	manifestData, _ := json.MarshalIndent(bundle.Manifest, "", "  ")
	os.WriteFile(manifestPath, manifestData, 0600)

	template := &Template{
		ID:                opts.ID,
		Description:       opts.Description,
		TPMStateDir:       filepath.Join(newPath, "tpm"),
		NVRAMPath:         filepath.Join(newPath, "ovmf", "OVMF_VARS.fd"),
		SecureBootKeysDir: filepath.Join(newPath, "secure-boot-keys"),
		EKAlgorithm:       bundleOpts.EKAlgorithm, // resolved: an omitted value took the configured default
		SecureBootEnabled: opts.SecureBootEnabled,
		CreatedAt:         bundle.CreatedAt,
	}

	s.logger.Info("Template created", "id", opts.ID)
	return template, nil
}

// CloneTemplate clones a template to create a new bundle with identity.
func (s *Service) CloneTemplate(ctx context.Context, opts *CloneOptions) (*Bundle, error) {
	// Validate hostname is provided
	if opts.Hostname == "" {
		return nil, ErrMissingHostname{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Get template (use locked version since we already hold the write lock)
	template, err := s.getTemplateLocked(opts.TemplateID)
	if err != nil {
		return nil, err
	}

	// Generate new bundle ID
	bundleID := s.generateBundleID(opts.Hostname)
	bundlePath := s.config.BundlePath(bundleID)

	// Create bundle directories
	if err := s.createBundleDirectories(bundlePath); err != nil {
		return nil, err
	}

	// Copy template files
	templatePath := s.config.TemplatePath(opts.TemplateID)
	if err := s.copyDir(filepath.Join(templatePath, "tpm"), filepath.Join(bundlePath, "tpm")); err != nil {
		os.RemoveAll(bundlePath)
		return nil, &WrappedError{Msg: "failed to copy TPM state", Err: err}
	}
	if err := s.copyDir(filepath.Join(templatePath, "ovmf"), filepath.Join(bundlePath, "ovmf")); err != nil {
		os.RemoveAll(bundlePath)
		return nil, &WrappedError{Msg: "failed to copy OVMF state", Err: err}
	}
	if template.SecureBootEnabled {
		if err := s.copyDir(filepath.Join(templatePath, "secure-boot-keys"), filepath.Join(bundlePath, "secure-boot-keys")); err != nil {
			os.RemoveAll(bundlePath)
			return nil, &WrappedError{Msg: "failed to copy Secure Boot keys", Err: err}
		}
	}

	// Start swtpm, inject EK certificate, stop swtpm (best-effort)
	// EK injection may fail if the template TPM state is not usable by swtpm,
	// such as when using mock/test templates with fake state data.
	var ekCertInfo *EKCertInfo
	if s.ca != nil && opts.Hostname != "" {
		ekCertInfo, _ = s.injectEKCertificateForClone(ctx, bundlePath, opts.Hostname, template.EKAlgorithm)
		// Note: We ignore the error here intentionally - EK injection is best-effort for cloning.
		// The bundle will be created without an EK certificate if injection fails.
	}

	// Generate manifest
	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                bundleID,
		Mode:              BundleModePreAssigned,
		Hostname:          opts.Hostname,
		CreatedAt:         time.Now(),
		EKCertificate:     ekCertInfo,
		EKAlgorithm:       template.EKAlgorithm,
		EKHandle:          template.EKAlgorithm.NVIndex(),
		SecureBootEnabled: template.SecureBootEnabled,
		Labels:            opts.Labels,
		ClonedFrom:        opts.TemplateID,
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		os.RemoveAll(bundlePath)
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to marshal manifest: %v", err)}
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "manifest.json"), manifestData, 0600); err != nil {
		os.RemoveAll(bundlePath)
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to write manifest: %v", err)}
	}

	bundle := &Bundle{
		ID:         bundleID,
		Mode:       BundleModePreAssigned,
		Manifest:   manifest,
		CreatedAt:  manifest.CreatedAt,
		ClonedFrom: opts.TemplateID,
		TPMState: &TPMState{
			StateDir:    filepath.Join(bundlePath, "tpm"),
			PermallFile: filepath.Join(bundlePath, "tpm", "tpm2-00.permall"),
		},
		OVMFState: &OVMFState{
			NVRAMFile: filepath.Join(bundlePath, "ovmf", "OVMF_VARS.fd"),
		},
	}

	if template.SecureBootEnabled {
		sbDir := filepath.Join(bundlePath, "secure-boot-keys")
		bundle.SecureBootKeys = &SecureBootKeyPaths{
			Dir:     sbDir,
			PKKey:   filepath.Join(sbDir, "PK.key"),
			PKCert:  filepath.Join(sbDir, "PK.crt"),
			KEKKey:  filepath.Join(sbDir, "KEK.key"),
			KEKCert: filepath.Join(sbDir, "KEK.crt"),
			DBKey:   filepath.Join(sbDir, "DB.key"),
			DBCert:  filepath.Join(sbDir, "DB.crt"),
		}
	}

	s.logger.Info("Bundle cloned from template",
		"bundleID", bundleID,
		"templateID", opts.TemplateID,
		"ekCertInjected", ekCertInfo != nil)

	return bundle, nil
}

// GetTemplate retrieves a template by ID.
func (s *Service) GetTemplate(ctx context.Context, id string) (*Template, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getTemplateLocked(id)
}

// getTemplateLocked retrieves a template by ID without acquiring a lock.
// Caller must hold at least a read lock.
func (s *Service) getTemplateLocked(id string) (*Template, error) {
	templatePath := s.config.TemplatePath(id)
	manifestPath := filepath.Join(templatePath, "manifest.json")

	if _, err := os.Stat(manifestPath); err != nil {
		return nil, ErrTemplateNotFound{ID: id}
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to read manifest: %v", err)}
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, ErrInvalidManifest{Reason: fmt.Sprintf("failed to parse manifest: %v", err)}
	}

	template := &Template{
		ID:                manifest.ID,
		Description:       manifest.Description,
		TPMStateDir:       filepath.Join(templatePath, "tpm"),
		NVRAMPath:         filepath.Join(templatePath, "ovmf", "OVMF_VARS.fd"),
		SecureBootKeysDir: filepath.Join(templatePath, "secure-boot-keys"),
		EKAlgorithm:       manifest.EKAlgorithm,
		SecureBootEnabled: manifest.SecureBootEnabled,
		CreatedAt:         manifest.CreatedAt,
	}

	return template, nil
}

// DeleteTemplate deletes a template.
func (s *Service) DeleteTemplate(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	templatePath := s.config.TemplatePath(id)

	if _, err := os.Stat(templatePath); err != nil {
		return ErrTemplateNotFound{ID: id}
	}

	if err := os.RemoveAll(templatePath); err != nil {
		return &WrappedError{Msg: "failed to delete template", Err: err}
	}

	s.logger.Info("Template deleted", "id", id)
	return nil
}

// ListTemplates lists all templates.
func (s *Service) ListTemplates(ctx context.Context) ([]*Template, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.config.TemplatesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []*Template{}, nil
		}
		return nil, &WrappedError{Msg: "failed to list templates", Err: err}
	}

	var templates []*Template
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Use locked version since we already hold the read lock
		template, err := s.getTemplateLocked(entry.Name())
		if err != nil {
			s.logger.Warn("Failed to load template", "id", entry.Name(), "error", err)
			continue
		}

		templates = append(templates, template)
	}

	return templates, nil
}

// ExportBundle exports a bundle to a tar.gz archive.
func (s *Service) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	// Delegate to archive.go
	archiver := NewArchiver(s.config, s.logger)
	return archiver.Export(ctx, id, w)
}

// ImportBundle imports a bundle from a tar.gz archive.
func (s *Service) ImportBundle(ctx context.Context, r io.Reader) (*Bundle, error) {
	// Delegate to archive.go
	archiver := NewArchiver(s.config, s.logger)
	return archiver.Import(ctx, r)
}

// ValidateBundle validates bundle integrity.
func (s *Service) ValidateBundle(ctx context.Context, id string) error {
	bundle, err := s.GetBundle(ctx, id)
	if err != nil {
		return err
	}

	bundlePath := s.config.BundlePath(id)

	// Verify checksums
	for relPath, expectedHash := range bundle.Manifest.Checksums {
		fullPath := filepath.Join(bundlePath, relPath)
		actualHash, err := fileChecksum(fullPath)
		if err != nil {
			return ErrChecksumMismatch{File: relPath, Expected: expectedHash, Actual: "file not found"}
		}
		if actualHash != expectedHash {
			return ErrChecksumMismatch{File: relPath, Expected: expectedHash, Actual: actualHash}
		}
	}

	s.logger.Debug("Bundle validation passed", "id", id)
	return nil
}

// GetBundlePath returns the filesystem path to a bundle.
func (s *Service) GetBundlePath(id string) string {
	return s.config.BundlePath(id)
}

// GetTPMSocketPath returns the TPM socket path for a bundle.
func (s *Service) GetTPMSocketPath(id string) string {
	return filepath.Join(s.config.BundlePath(id), "tpm", "swtpm.sock")
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (s *Service) GetNVRAMPath(id string) string {
	return filepath.Join(s.config.BundlePath(id), "ovmf", "OVMF_VARS.fd")
}

// =============================================================================
// Runtime TPM Operations
// =============================================================================

// Start starts the swtpm daemon for the specified bundle.
func (s *Service) Start(ctx context.Context, bundleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already running
	if _, exists := s.instances[bundleID]; exists {
		return ErrVTPMAlreadyRunning{BundleID: bundleID}
	}

	// Verify bundle exists and get its metadata
	bundle, err := s.getBundleLocked(bundleID)
	if err != nil {
		return err
	}

	// Get EK algorithm from bundle manifest (defaults to RSA)
	ekAlgorithm := EKAlgorithmRSA
	hostname := ""
	if bundle.Manifest != nil {
		if bundle.Manifest.EKAlgorithm != "" {
			ekAlgorithm = bundle.Manifest.EKAlgorithm
		}
		hostname = bundle.Manifest.Hostname
	}

	bundlePath := s.config.BundlePath(bundleID)
	tpmDir := filepath.Join(bundlePath, "tpm")

	// Create swtpm instance
	swtpmConfig := &swtpm.Config{
		StateDir: tpmDir,
		PCRBanks: s.config.PCRBanks,
		Debug:    s.config.Debug,
	}

	sw, err := swtpm.NewSWTPM(swtpmConfig, s.logger)
	if err != nil {
		return ErrVTPMStartFailed{BundleID: bundleID, Cause: err}
	}

	// Start the swtpm daemon
	if err := sw.Start(ctx); err != nil {
		return ErrVTPMStartFailed{BundleID: bundleID, Cause: err}
	}

	// Wait for socket to be ready
	if err := sw.WaitForSocket(10 * time.Second); err != nil {
		sw.Stop()
		return ErrVTPMStartFailed{BundleID: bundleID, Cause: err}
	}

	// Send TPM2_Startup command
	if err := sw.SendStartup(); err != nil {
		sw.Stop()
		return ErrVTPMStartFailed{BundleID: bundleID, Cause: err}
	}

	// Create TPM operations wrapper for runtime operations
	tpmOps, err := NewTPMOperations(sw.SocketPath(), ekAlgorithm, hostname, s.logger)
	if err != nil {
		sw.Stop()
		return ErrVTPMStartFailed{BundleID: bundleID, Cause: err}
	}

	// Track the running instance
	s.instances[bundleID] = &runningInstance{
		swtpm:      sw,
		socketPath: sw.SocketPath(),
		tpmOps:     tpmOps,
	}

	s.logger.Info("vTPM started", "bundleID", bundleID, "socket", sw.SocketPath())
	return nil
}

// Stop stops the swtpm daemon for the specified bundle.
func (s *Service) Stop(ctx context.Context, bundleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance, exists := s.instances[bundleID]
	if !exists {
		return ErrVTPMNotRunning{BundleID: bundleID}
	}

	// Close TPM operations
	if instance.tpmOps != nil {
		instance.tpmOps.Close()
	}

	if err := instance.swtpm.Stop(); err != nil {
		return ErrVTPMStopFailed{BundleID: bundleID, Cause: err}
	}

	delete(s.instances, bundleID)
	s.logger.Info("vTPM stopped", "bundleID", bundleID)
	return nil
}

// IsRunning checks if the vTPM for the specified bundle is running.
func (s *Service) IsRunning(bundleID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	instance, exists := s.instances[bundleID]
	if !exists {
		return false
	}
	return instance.swtpm.IsRunning()
}

// Quote generates a TPM quote over the specified PCRs using go-xkms.
func (s *Service) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*QuoteResult, error) {
	s.mu.RLock()
	instance, exists := s.instances[bundleID]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrVTPMNotRunning{BundleID: bundleID}
	}

	// Validate nonce
	if len(nonce) == 0 {
		return nil, ErrInvalidNonce{Reason: "nonce cannot be empty"}
	}
	if len(nonce) > 64 {
		return nil, ErrInvalidNonce{Reason: "nonce too long (max 64 bytes)"}
	}

	// Validate PCR indices
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, ErrInvalidPCRIndex{PCRIndex: pcr}
		}
	}

	// Check if tpmOps is available
	if instance.tpmOps == nil {
		return nil, ErrTPMConnectionFailed{SocketPath: instance.socketPath, Cause: &MessageError{Msg: "TPM operations not initialized"}}
	}

	// Use TPMOperations Quote method which uses go-xkms
	result, err := instance.tpmOps.Quote(nonce, pcrs)
	if err != nil {
		return nil, ErrTPMQuoteFailed{BundleID: bundleID, Cause: err}
	}

	s.logger.Debug("TPM quote generated", "bundleID", bundleID, "pcrs", pcrs)
	return result, nil
}

// Seal encrypts data to the TPM, optionally binding to PCR values.
// This uses go-xkms's Seal method internally for TPM operations.
func (s *Service) Seal(ctx context.Context, bundleID string, data []byte, opts *SealOptions) ([]byte, error) {
	s.mu.RLock()
	instance, exists := s.instances[bundleID]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrVTPMNotRunning{BundleID: bundleID}
	}

	if len(data) == 0 {
		return nil, ErrTPMSealFailed{BundleID: bundleID, Cause: &MessageError{Msg: "data cannot be empty"}}
	}

	// Validate PCR indices if provided
	var pcrs []int
	var authValue string
	if opts != nil {
		for _, pcr := range opts.PCRs {
			if pcr < 0 || pcr > 23 {
				return nil, ErrInvalidPCRIndex{PCRIndex: pcr}
			}
		}
		pcrs = opts.PCRs
		authValue = opts.AuthValue
	}

	// Check if tpmOps is available
	if instance.tpmOps == nil {
		return nil, ErrTPMConnectionFailed{SocketPath: instance.socketPath, Cause: &MessageError{Msg: "TPM operations not initialized"}}
	}

	// Use TPMOperations Seal method which uses go-xkms
	sealedData, err := instance.tpmOps.Seal(ctx, data, pcrs, authValue)
	if err != nil {
		return nil, ErrTPMSealFailed{BundleID: bundleID, Cause: err}
	}

	// Marshal the sealed data for storage
	result, err := json.Marshal(sealedData)
	if err != nil {
		return nil, ErrTPMSealFailed{BundleID: bundleID, Cause: err}
	}

	s.logger.Debug("Data sealed to TPM", "bundleID", bundleID, "size", len(data))
	return result, nil
}

// Unseal decrypts previously sealed data from the TPM.
// This uses go-xkms's Unseal method internally for TPM operations.
func (s *Service) Unseal(ctx context.Context, bundleID string, sealedBlob []byte, authValue string) ([]byte, error) {
	s.mu.RLock()
	instance, exists := s.instances[bundleID]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrVTPMNotRunning{BundleID: bundleID}
	}

	// Unmarshal the sealed data - let JSON parsing fail naturally for empty input
	var sealedData *xkmssdk.SealedData
	if err := json.Unmarshal(sealedBlob, &sealedData); err != nil {
		return nil, ErrTPMUnsealFailed{BundleID: bundleID, Cause: &WrappedError{Msg: "invalid sealed data format", Err: err}}
	}

	// Check if tpmOps is available
	if instance.tpmOps == nil {
		return nil, ErrTPMConnectionFailed{SocketPath: instance.socketPath, Cause: &MessageError{Msg: "TPM operations not initialized"}}
	}

	// Use TPMOperations Unseal method which uses go-xkms
	data, err := instance.tpmOps.Unseal(ctx, sealedData, authValue)
	if err != nil {
		return nil, ErrTPMUnsealFailed{BundleID: bundleID, Cause: err}
	}

	s.logger.Debug("Data unsealed from TPM", "bundleID", bundleID, "size", len(data))
	return data, nil
}

// ReadPCR reads a PCR value from the TPM.
func (s *Service) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	s.mu.RLock()
	instance, exists := s.instances[bundleID]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrVTPMNotRunning{BundleID: bundleID}
	}

	if pcrIndex < 0 || pcrIndex > 23 {
		return nil, ErrInvalidPCRIndex{PCRIndex: pcrIndex}
	}

	// Check if tpmOps is available
	if instance.tpmOps == nil {
		return nil, ErrTPMConnectionFailed{SocketPath: instance.socketPath, Cause: &MessageError{Msg: "TPM operations not initialized"}}
	}

	// Use TPMOperations ReadPCR method
	pcrValue, err := instance.tpmOps.ReadPCR(pcrIndex)
	if err != nil {
		return nil, ErrPCRReadFailed{BundleID: bundleID, PCRIndex: pcrIndex, Cause: err}
	}

	s.logger.Debug("PCR read", "bundleID", bundleID, "pcr", pcrIndex)
	return pcrValue, nil
}

// ExtendPCR extends a PCR with the given data.
func (s *Service) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	s.mu.RLock()
	instance, exists := s.instances[bundleID]
	s.mu.RUnlock()

	if !exists {
		return ErrVTPMNotRunning{BundleID: bundleID}
	}

	if pcrIndex < 0 || pcrIndex > 23 {
		return ErrInvalidPCRIndex{PCRIndex: pcrIndex}
	}

	if len(data) == 0 {
		return ErrPCRExtendFailed{BundleID: bundleID, PCRIndex: pcrIndex, Cause: &MessageError{Msg: "data cannot be empty"}}
	}

	// Check if tpmOps is available
	if instance.tpmOps == nil {
		return ErrTPMConnectionFailed{SocketPath: instance.socketPath, Cause: &MessageError{Msg: "TPM operations not initialized"}}
	}

	// Use TPMOperations ExtendPCR method
	if err := instance.tpmOps.ExtendPCR(pcrIndex, data); err != nil {
		return ErrPCRExtendFailed{BundleID: bundleID, PCRIndex: pcrIndex, Cause: err}
	}

	s.logger.Debug("PCR extended", "bundleID", bundleID, "pcr", pcrIndex)
	return nil
}

// Close stops all running vTPM instances and cleans up resources.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var lastErr error
	for bundleID, instance := range s.instances {
		if instance.tpmOps != nil {
			instance.tpmOps.Close()
		}
		if err := instance.swtpm.Stop(); err != nil {
			s.logger.Warn("Failed to stop vTPM during close", "bundleID", bundleID, "error", err)
			lastErr = err
		}
		delete(s.instances, bundleID)
	}
	return lastErr
}

// =============================================================================
// Helper Functions
// =============================================================================

// copyFile copies a single file from src to dst with restrictive permissions.
func (s *Service) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// Set restrictive permissions (0600) for security
	return os.Chmod(dst, 0600)
}

// copyDir copies a directory recursively.
func (s *Service) copyDir(src, dst string) error {
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, sourceInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := s.copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := s.copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// fileChecksum calculates the SHA-256 checksum of a file with sha256: prefix.
func fileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
