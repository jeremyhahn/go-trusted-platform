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

package installer

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// dracutUKIBuilder implements UKIBuilder using dracut's native UKI support
type dracutUKIBuilder struct {
	logger *logging.Logger
}

// NewDracutUKIBuilder creates a new dracut-based UKI builder
func NewDracutUKIBuilder(logger *logging.Logger) UKIBuilder {
	return &dracutUKIBuilder{
		logger: logger,
	}
}

// BuildUKI builds a Unified Kernel Image using dracut
// dracut has native UKI support via the --uefi flag which combines
// initramfs generation and UKI building in one step
func (db *dracutUKIBuilder) BuildUKI(ctx context.Context, config *UKIConfig, output io.Writer) error {
	db.logger.Info("[DRACUT] Building Unified Kernel Image with dracut")

	// Validate configuration
	if config.KernelPath == "" {
		return ErrUKIBuild("kernel path is required", nil)
	}
	if config.Cmdline == "" {
		return ErrUKIBuild("kernel command line is required", nil)
	}

	// Determine kernel version from kernel path
	// Typical path: /boot/vmlinuz-6.6.67-0-lts -> 6.6.67-0-lts
	kernelVersion := filepath.Base(config.KernelPath)
	kernelVersion = strings.TrimPrefix(kernelVersion, "vmlinuz-")
	db.logger.Debug("[DRACUT] Detected kernel version", "version", kernelVersion)

	// Create temporary directory for dracut working files
	tmpDir, err := os.MkdirTemp("", "dracut-uki-*")
	if err != nil {
		return ErrUKIBuild("failed to create temporary directory", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			db.logger.Warn("[DRACUT] Failed to clean up temp directory", "error", removeErr)
		}
	}()

	// Write kernel command line to temporary file
	cmdlinePath := filepath.Join(tmpDir, "cmdline.txt")
	if err := os.WriteFile(cmdlinePath, []byte(config.Cmdline), 0644); err != nil {
		return ErrUKIBuild("failed to write cmdline file", err)
	}
	db.logger.Debug("[DRACUT] Wrote kernel command line", "path", cmdlinePath, "cmdline", config.Cmdline)

	// Write os-release if provided
	var osReleasePath string
	if config.OSRelease != "" {
		osReleasePath = filepath.Join(tmpDir, "os-release")
		if err := os.WriteFile(osReleasePath, []byte(config.OSRelease), 0644); err != nil {
			return ErrUKIBuild("failed to write os-release file", err)
		}
		db.logger.Debug("[DRACUT] Wrote os-release", "path", osReleasePath)
	}

	// Create temporary output file for the UKI
	// We need to write to a file first because dracut doesn't support stdout output
	ukiTmpPath := filepath.Join(tmpDir, "linux.efi")

	// Build dracut command with UKI generation
	// dracut will:
	// 1. Generate initramfs with platformd LUKS support (go-luks2, no cryptsetup)
	// 2. Bundle kernel + initramfs + cmdline + os-release into UKI
	// 3. Use systemd-boot stub (if available) or fall back to objcopy approach
	args := []string{
		"--force",               // Overwrite existing initramfs
		"--kver", kernelVersion, // Kernel version
		"--add", "platformd", // Add platformd module (LUKS via go-luks2)
		"--kernel-cmdline", config.Cmdline, // Kernel command line
		"--uefi",                            // Generate UKI
		"--kernel-image", config.KernelPath, // Path to kernel
		ukiTmpPath, // Output UKI path
	}

	// Add os-release if provided
	if osReleasePath != "" {
		args = append(args, "--uefi-os-release", osReleasePath)
	}

	// Add microcode if provided
	if config.MicrocodePath != "" {
		args = append(args, "--early-microcode", config.MicrocodePath)
	}

	// Look for systemd-boot EFI stub
	// Common locations: /usr/lib/systemd/boot/efi/linuxx64.efi.stub
	stubPaths := []string{
		"/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
		"/lib/systemd/boot/efi/linuxx64.efi.stub",
		"/usr/lib/systemd/boot/efi/linux.efi.stub",
	}

	var stubPath string
	for _, path := range stubPaths {
		if _, err := os.Stat(path); err == nil {
			stubPath = path
			break
		}
	}

	if stubPath != "" {
		args = append(args, "--uefi-stub", stubPath)
		db.logger.Debug("[DRACUT] Using systemd-boot EFI stub", "path", stubPath)
	} else {
		db.logger.Warn("[DRACUT] No systemd-boot EFI stub found, dracut will use fallback method")
	}

	db.logger.Info("[DRACUT] Running dracut to build UKI", "args", strings.Join(args, " "))

	// Execute dracut command
	cmd := exec.CommandContext(ctx, "dracut", args...)
	cmd.Stdout = os.Stderr // Send dracut output to stderr for visibility
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return ErrUKIBuild(fmt.Sprintf("dracut command failed: %v", err), err)
	}

	// Read the generated UKI and write to output
	ukiData, err := os.ReadFile(ukiTmpPath)
	if err != nil {
		return ErrUKIBuild("failed to read generated UKI", err)
	}

	if _, err := output.Write(ukiData); err != nil {
		return ErrUKIBuild("failed to write UKI to output", err)
	}

	db.logger.Info("[DRACUT] UKI built successfully", "size", len(ukiData))
	return nil
}

// SignUKI signs the UKI with Secure Boot keys using native authenticode
func (db *dracutUKIBuilder) SignUKI(ctx context.Context, ukiPath string, config *SecureBootConfig) error {
	db.logger.Info("[DRACUT] Signing UKI with native authenticode")

	// Validate configuration
	if config == nil {
		return ErrSecureBoot("secure boot configuration is required", nil)
	}
	if config.KeyPath == "" {
		return ErrSecureBoot("signing key path is required", nil)
	}
	if config.CertPath == "" {
		return ErrSecureBoot("signing certificate path is required", nil)
	}

	// Read private key
	keyPEM, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return ErrSecureBoot(fmt.Sprintf("failed to read signing key: %v", err), err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return ErrSecureBoot("failed to decode signing key PEM", nil)
	}

	// Parse the private key (support both PKCS#1 and PKCS#8)
	var privateKey crypto.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else {
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		return ErrSecureBoot(fmt.Sprintf("failed to parse signing key: %v", err), err)
	}

	// Read certificate
	certPEM, err := os.ReadFile(config.CertPath)
	if err != nil {
		return ErrSecureBoot(fmt.Sprintf("failed to read signing certificate: %v", err), err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return ErrSecureBoot("failed to decode signing certificate PEM", nil)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return ErrSecureBoot(fmt.Sprintf("failed to parse signing certificate: %v", err), err)
	}

	// Create keystore backend for signing
	signingBackend := &dracutSigningBackend{
		privateKey: privateKey,
		logger:     db.logger,
	}

	// Create authenticode signer
	signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
		KeyStore:      signingBackend,
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot"},
		Certificate:   cert,
		Logger:        db.logger,
	})
	if err != nil {
		return ErrSecureBoot(fmt.Sprintf("failed to create authenticode signer: %v", err), err)
	}

	// Check if UKI exists
	if _, err := os.Stat(ukiPath); err != nil {
		return ErrSecureBoot(fmt.Sprintf("UKI not found at %s", ukiPath), err)
	}

	// Sign in-place
	db.logger.Info("[DRACUT] Signing UKI", "path", ukiPath)

	// Create temporary file for signed output
	signedPath := ukiPath + ".signed"
	if err := signer.SignFile(ukiPath, signedPath); err != nil {
		return ErrSecureBoot(fmt.Sprintf("failed to sign UKI: %v", err), err)
	}

	// Replace original with signed
	if err := os.Rename(signedPath, ukiPath); err != nil {
		if removeErr := os.Remove(signedPath); removeErr != nil {
			db.logger.Warn("[DRACUT] Failed to remove signed file", "error", removeErr)
		}
		return ErrSecureBoot(fmt.Sprintf("failed to replace UKI with signed version: %v", err), err)
	}

	db.logger.Info("[DRACUT] UKI signed successfully with native authenticode")
	return nil
}

// dracutSigningBackend is a minimal Backend implementation for Secure Boot signing
type dracutSigningBackend struct {
	privateKey crypto.PrivateKey
	logger     *logging.Logger
}

func (b *dracutSigningBackend) Type() xkmssdk.BackendType {
	return "dracut-secure-boot"
}

func (b *dracutSigningBackend) Capabilities() xkmssdk.Capabilities {
	return xkmssdk.Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     false,
		KeyRotation:    false,
	}
}

func (b *dracutSigningBackend) Signer(attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	if signer, ok := b.privateKey.(crypto.Signer); ok {
		return signer, nil
	}
	return nil, fmt.Errorf("private key does not implement crypto.Signer")
}

func (b *dracutSigningBackend) GenerateKey(attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("not implemented")
}

func (b *dracutSigningBackend) GetKey(attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return b.privateKey, nil
}

func (b *dracutSigningBackend) DeleteKey(attrs *xkmssdk.KeyAttributes) error {
	return fmt.Errorf("not implemented")
}

func (b *dracutSigningBackend) ListKeys() ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (b *dracutSigningBackend) Decrypter(attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, fmt.Errorf("not implemented")
}

func (b *dracutSigningBackend) RotateKey(attrs *xkmssdk.KeyAttributes) error {
	return fmt.Errorf("not implemented")
}

func (b *dracutSigningBackend) Close() error {
	return nil
}
