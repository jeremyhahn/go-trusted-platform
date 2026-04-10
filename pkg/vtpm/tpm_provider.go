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
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TPMProvider creates and manages go-xkms TrustedPlatformModule instances
// for vTPM sockets. This provides a factory pattern for creating TPM instances
// connected to swtpm Unix domain sockets.
type TPMProvider struct {
	logger    *logging.Logger
	instances sync.Map // socketPath -> *tpmInstance
}

// tpmInstance tracks a go-xkms TPM instance.
type tpmInstance struct {
	tpm xkmssdk.TrustedPlatformModule
}

// NewTPMProvider creates a new TPM provider.
func NewTPMProvider(logger *logging.Logger) *TPMProvider {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &TPMProvider{
		logger: logger,
	}
}

// GetTPM returns a go-xkms TrustedPlatformModule connected to the specified
// swtpm socket. The TPM instance is cached for reuse.
func (p *TPMProvider) GetTPM(socketPath string) (xkmssdk.TrustedPlatformModule, error) {
	// Check cache first
	if val, ok := p.instances.Load(socketPath); ok {
		instance := val.(*tpmInstance)
		return instance.tpm, nil
	}

	// Create new transport and TPM instance
	t, err := xkmssdk.OpenUnixSocketTransport(socketPath)
	if err != nil {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	// Create TPM config for the socket
	tpmConfig := &xkmssdk.TPMConfig{
		Device: socketPath,
		Hash:   "SHA256",
		EK: &xkmssdk.EKConfig{
			Handle:       0x81010001, // Standard EK handle
			KeyAlgorithm: "RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		},
	}

	// Create TPM instance with custom transport
	params := &xkmssdk.TPMParams{
		Config:    tpmConfig,
		Logger:    nil, // Will use go-xkms's default logger
		Transport: t,
	}

	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil {
		// Close the transport if it implements io.Closer
		if closer, ok := t.(io.Closer); ok {
			closer.Close()
		}
		// If ErrNotInitialized, the TPM is usable but not provisioned
		if err == xkmssdk.ErrTPMNotInitialized {
			// Store even uninitialized TPM - it can still be used for basic operations
			instance := &tpmInstance{tpm: tpm}
			p.instances.Store(socketPath, instance)
			return tpm, nil
		}
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	instance := &tpmInstance{tpm: tpm}
	p.instances.Store(socketPath, instance)

	return tpm, nil
}

// CloseTPM closes the TPM instance for the specified socket and removes it from cache.
func (p *TPMProvider) CloseTPM(socketPath string) error {
	if val, ok := p.instances.LoadAndDelete(socketPath); ok {
		instance := val.(*tpmInstance)
		return instance.tpm.Close()
	}
	return nil
}

// CloseAll closes all cached TPM instances.
func (p *TPMProvider) CloseAll() error {
	var lastErr error
	p.instances.Range(func(key, value any) bool {
		socketPath := key.(string)
		instance := value.(*tpmInstance)
		if err := instance.tpm.Close(); err != nil {
			p.logger.Warn("Failed to close TPM instance", "socket", socketPath, "error", err)
			lastErr = err
		}
		p.instances.Delete(key)
		return true
	})
	return lastErr
}

// TPMOperations provides high-level TPM operations using go-xkms.
// This wraps a go-xkms TrustedPlatformModule and provides operations
// specific to vTPM bundle management.
type TPMOperations struct {
	tpm        xkmssdk.TrustedPlatformModule
	socketPath string
	algorithm  EKAlgorithm
	logger     *logging.Logger
}

// NewTPMOperations creates a new TPM operations wrapper configured for the
// specified EK algorithm. The algorithm determines the TCG NV index used
// for EK certificate storage (RSA: 0x01C00002, ECC: 0x01C0000A).
func NewTPMOperations(socketPath string, algorithm EKAlgorithm, logger *logging.Logger) (*TPMOperations, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Open transport to swtpm socket
	t, err := xkmssdk.OpenUnixSocketTransport(socketPath)
	if err != nil {
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	// Configure EK based on algorithm with TCG-specified NV indices
	var ekConfig *xkmssdk.EKConfig
	switch algorithm {
	case EKAlgorithmECC:
		ekConfig = &xkmssdk.EKConfig{
			Handle:       0x81010002, // ECC EK handle
			CertHandle:   NVIndexECCEKCert,
			KeyAlgorithm: "ECDSA",
			ECCConfig: &xkmssdk.ECCConfig{
				Curve: "P-256",
			},
		}
	case EKAlgorithmRSA:
		fallthrough
	default:
		ekConfig = &xkmssdk.EKConfig{
			Handle:       0x81010001, // RSA EK handle
			CertHandle:   NVIndexRSAEKCert,
			KeyAlgorithm: "RSA",
			RSAConfig: &xkmssdk.RSAConfig{
				KeySize: 2048,
			},
		}
	}

	tpmConfig := &xkmssdk.TPMConfig{
		Device:          socketPath,
		Hash:            "SHA256",
		PlatformPCR:     16,
		PlatformPCRBank: "SHA256",
		EK:              ekConfig,
	}

	params := &xkmssdk.TPMParams{
		Config:    tpmConfig,
		Logger:    nil, // Will use go-xkms's default logger
		Transport: t,
	}

	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil && err != xkmssdk.ErrTPMNotInitialized {
		// Close the transport if it implements io.Closer
		if closer, ok := t.(io.Closer); ok {
			closer.Close()
		}
		return nil, ErrTPMConnectionFailed{SocketPath: socketPath, Cause: err}
	}

	return &TPMOperations{
		tpm:        tpm,
		socketPath: socketPath,
		algorithm:  algorithm,
		logger:     logger,
	}, nil
}

// Close closes the TPM connection.
func (ops *TPMOperations) Close() error {
	if ops.tpm != nil {
		return ops.tpm.Close()
	}
	return nil
}

// TPM returns the underlying go-xkms TrustedPlatformModule.
func (ops *TPMOperations) TPM() xkmssdk.TrustedPlatformModule {
	return ops.tpm
}

// Provision provisions the vTPM with EK, SRK, and IAK using go-xkms.
// This should be called once when creating a new vTPM bundle.
func (ops *TPMOperations) Provision(soPIN string) error {
	ops.logger.Debug("Provisioning vTPM", "algorithm", string(ops.algorithm))

	password := xkmssdk.NewPassword([]byte(soPIN))
	if err := ops.tpm.Provision(password); err != nil {
		return ErrEKCertInjectionFailed{Cause: fmt.Errorf("failed to provision TPM: %w", err)}
	}

	ops.logger.Debug("vTPM provisioned successfully")
	return nil
}

// GetEKPublicKey returns the EK public key using go-xkms.
// The TPM must be provisioned first.
func (ops *TPMOperations) GetEKPublicKey() (crypto.PublicKey, error) {
	pubKey, err := ops.tpm.EK()
	if err != nil {
		return nil, ErrEKCertInjectionFailed{Cause: err}
	}
	if pubKey == nil {
		return nil, ErrEKCertInjectionFailed{Cause: fmt.Errorf("EK not available - TPM may not be provisioned")}
	}
	return pubKey, nil
}

// InjectEKCertificate injects an EK certificate into the TPM's NV RAM
// using go-xkms's ProvisionEKCert method.
func (ops *TPMOperations) InjectEKCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrEKCertInjectionFailed{Cause: fmt.Errorf("certificate cannot be nil")}
	}

	ops.logger.Debug("Injecting EK certificate",
		"algorithm", string(ops.algorithm),
		"nvIndex", fmt.Sprintf("0x%08X", ops.algorithm.NVIndex()))

	// Use go-xkms's ProvisionEKCert to inject the certificate
	if err := ops.tpm.ProvisionEKCert(nil, cert.Raw); err != nil {
		return ErrEKCertInjectionFailed{Cause: fmt.Errorf("failed to inject EK certificate: %w", err)}
	}

	ops.logger.Debug("EK certificate injected successfully")
	return nil
}

// ReadPCRs reads the specified PCR values using go-xkms's ReadPCRs method.
func (ops *TPMOperations) ReadPCRs(pcrs []int) (map[int][]byte, error) {
	// Convert int slice to uint slice for go-xkms
	pcrList := make([]uint, len(pcrs))
	for i, pcr := range pcrs {
		pcrList[i] = uint(pcr)
	}

	banks, err := ops.tpm.ReadPCRs(pcrList)
	if err != nil {
		return nil, err
	}

	// Extract SHA256 bank values
	result := make(map[int][]byte)
	for _, bank := range banks {
		if bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				result[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}

	return result, nil
}

// Quote generates a TPM quote using go-xkms's Quote method.
// Note: This requires an initialized IAK. For basic vTPM operations
// without IAK, use QuoteWithKey.
func (ops *TPMOperations) Quote(nonce []byte, pcrs []int) (*QuoteResult, error) {
	// Convert int slice to uint slice
	pcrList := make([]uint, len(pcrs))
	for i, pcr := range pcrs {
		pcrList[i] = uint(pcr)
	}

	quote, err := ops.tpm.Quote(pcrList, nonce)
	if err != nil {
		return nil, err
	}

	// Convert PCR bytes back to map
	pcrBanks, err := xkmssdk.DecodePCRs(quote.PCRs)
	if err != nil {
		return nil, err
	}

	pcrValues := make(map[int][]byte)
	for _, bank := range pcrBanks {
		if bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				pcrValues[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}

	return &QuoteResult{
		Quote:         quote.Quoted,
		Signature:     quote.Signature,
		PCRValues:     pcrValues,
		HashAlgorithm: "SHA256",
	}, nil
}

// Seal encrypts data to the TPM using go-xkms's Seal method.
func (ops *TPMOperations) Seal(ctx context.Context, data []byte, pcrs []int, authValue string) (*xkmssdk.SealedData, error) {
	// Build key attributes for sealing
	keyAttrs := &xkmssdk.KeyAttributes{
		CN:        "vtpm-sealed-data",
		StoreType: xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Get SSRK as parent
	ssrkAttrs, err := ops.tpm.SSRKAttributes()
	if err != nil {
		return nil, fmt.Errorf("failed to get SSRK attributes: %w", err)
	}
	keyAttrs.Parent = ssrkAttrs

	// Set auth value if provided
	if authValue != "" {
		keyAttrs.Password = xkmssdk.NewPassword([]byte(authValue))
	}

	// Build TPM policy for PCR binding
	var tpmPolicy *xkmssdk.TPMSealPolicy
	if len(pcrs) > 0 {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: pcrBitmask(pcrs),
				},
			},
		}
		tpmPolicy = &xkmssdk.TPMSealPolicy{
			PCRSelection: pcrSelection,
			HashAlg:      tpm2.TPMAlgSHA256,
		}
	}

	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: keyAttrs,
		TPMPolicy:     tpmPolicy,
	}

	return ops.tpm.Seal(ctx, data, sealOpts)
}

// Unseal decrypts data from the TPM using go-xkms's Unseal method.
func (ops *TPMOperations) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, authValue string) ([]byte, error) {
	// Build key attributes for unsealing
	keyAttrs := &xkmssdk.KeyAttributes{
		CN:        "vtpm-sealed-data",
		StoreType: xkmssdk.StoreTPM2,
		TPMAttributes: &xkmssdk.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	// Get SSRK as parent
	ssrkAttrs, err := ops.tpm.SSRKAttributes()
	if err != nil {
		return nil, fmt.Errorf("failed to get SSRK attributes: %w", err)
	}
	keyAttrs.Parent = ssrkAttrs

	// Set auth value if provided
	var password xkmssdk.Password
	if authValue != "" {
		password = xkmssdk.NewPassword([]byte(authValue))
	}

	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: keyAttrs,
		Password:      password,
	}

	return ops.tpm.Unseal(ctx, sealed, unsealOpts)
}

// ExtendPCR extends a PCR with the provided data using go-xkms.
func (ops *TPMOperations) ExtendPCR(pcrIndex int, data []byte) error {
	return ops.tpm.ExtendPCR(pcrIndex, "sha256", data)
}

// ReadPCR reads a single PCR value.
func (ops *TPMOperations) ReadPCR(pcrIndex int) ([]byte, error) {
	values, err := ops.ReadPCRs([]int{pcrIndex})
	if err != nil {
		return nil, err
	}
	return values[pcrIndex], nil
}

// pcrBitmask converts a list of PCR indices to a TPM PCR bitmask.
func pcrBitmask(pcrs []int) []byte {
	mask := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr >= 0 && pcr <= 23 {
			mask[pcr/8] |= 1 << (pcr % 8)
		}
	}
	return mask
}

// certFingerprint calculates the SHA-256 fingerprint of a certificate.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("sha256:%x", hash)
}
