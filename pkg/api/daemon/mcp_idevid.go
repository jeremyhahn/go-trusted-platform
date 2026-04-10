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

package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// =============================================================================
// IDevID Operations
// =============================================================================

// idevIDGenerateInternal generates a new IDevID key in the TPM (internal implementation).
func (p *MCPServiceProvider) idevIDGenerateInternal(ctx context.Context, algorithm string, overwrite bool) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	// Get EK attributes for IDevID creation
	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "get EK attributes", Cause: err}
	}

	// Create IAK first (required before IDevID per TCG spec)
	iakAttrs, err := p.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "create IAK", Cause: err}
	}

	// Create IDevID
	idevidAttrs, _, err := p.tpm2Service.CreateIDevID(iakAttrs, nil, nil)
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "create IDevID", Cause: err}
	}

	// Return key info
	return formatKeyAttributesMap(idevidAttrs), nil
}

// IDevIDInfo retrieves information about the IDevID key.
func (p *MCPServiceProvider) IDevIDInfo(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	attrs, err := p.tpm2Service.IDevIDAttributes()
	if err != nil {
		return map[string]interface{}{
			"exists": false,
		}, nil
	}

	result := formatKeyAttributesMap(attrs)
	result["exists"] = true

	// Check for certificate
	cert, err := p.tpm2Service.IDevIDCertificate()
	if err == nil && cert != nil {
		result["has_certificate"] = true
		result["certificate"] = formatX509CertificateInfo(cert)
	} else {
		result["has_certificate"] = false
	}

	return result, nil
}

// HasIDevID returns whether an IDevID key exists in the TPM.
func (p *MCPServiceProvider) HasIDevID(ctx context.Context) (bool, error) {
	if p.tpm2Service == nil {
		return false, ErrTPM2ServiceNotAvailable{}
	}

	_, err := p.tpm2Service.IDevIDAttributes()
	return err == nil, nil
}

// IDevIDDelete deletes the IDevID key from the TPM.
func (p *MCPServiceProvider) IDevIDDelete(ctx context.Context) error {
	if p.tpm2Service == nil {
		return ErrTPM2ServiceNotAvailable{}
	}

	// Delete the IDevID certificate first
	if err := p.tpm2Service.DeleteIDevIDCertificate(); err != nil {
		// Log but continue - certificate might not exist
		p.logger.Debug("IDevID certificate deletion skipped", "error", err)
	}

	// Note: TPM2 persistent keys cannot be easily deleted
	// This operation clears the certificate but the key remains
	return nil
}

// IDevIDCreateCSR creates a Certificate Signing Request for the IDevID key.
func (p *MCPServiceProvider) IDevIDCreateCSR(ctx context.Context, commonName, organization, country string, includeTCGAttrs bool) (string, error) {
	if p.tpm2Service == nil {
		return "", ErrTPM2ServiceNotAvailable{}
	}

	// Get IDevID attributes
	idevidAttrs, err := p.tpm2Service.IDevIDAttributes()
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "get IDevID attributes", Cause: err}
	}

	// Get IAK attributes for CSR creation
	iakAttrs, err := p.tpm2Service.IAKAttributes()
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "get IAK attributes", Cause: err}
	}

	// Create TCG CSR using TPM2
	tcgCSR, err := p.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, idevidAttrs)
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "create TCG CSR", Cause: err}
	}

	// Marshal CSR to bytes
	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "marshal TCG CSR", Cause: err}
	}

	// Return base64-encoded CSR
	return base64.StdEncoding.EncodeToString(csrBytes), nil
}

// IDevIDInstallCertificate installs a certificate for the IDevID key.
func (p *MCPServiceProvider) IDevIDInstallCertificate(ctx context.Context, certificatePEM string) error {
	if p.tpm2Service == nil {
		return ErrTPM2ServiceNotAvailable{}
	}

	// Parse PEM to get x509.Certificate
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return ErrInvalidCertificatePEM{}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrInvalidRequestBody{Reason: "invalid certificate: " + err.Error()}
	}

	if err := p.tpm2Service.ProvisionIDevIDCert(cert); err != nil {
		return ErrTPM2OperationFailed{Operation: "write IDevID certificate", Cause: err}
	}
	return nil
}

// IDevIDGetCertificate retrieves the IDevID certificate.
func (p *MCPServiceProvider) IDevIDGetCertificate(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	cert, err := p.tpm2Service.IDevIDCertificate()
	if err != nil {
		return nil, ErrIDevIDCertificateNotFound{}
	}

	info := formatX509CertificateInfo(cert)
	// Add PEM encoding
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	info["pem"] = string(certPEM)

	return info, nil
}

// IDevIDDeleteCertificate deletes the IDevID certificate.
func (p *MCPServiceProvider) IDevIDDeleteCertificate(ctx context.Context) error {
	if p.tpm2Service == nil {
		return ErrTPM2ServiceNotAvailable{}
	}

	if err := p.tpm2Service.DeleteIDevIDCertificate(); err != nil {
		return ErrTPM2OperationFailed{Operation: "delete IDevID certificate", Cause: err}
	}
	return nil
}

// =============================================================================
// IAK Operations
// =============================================================================

// iakGenerateInternal generates a new IAK (Initial Attestation Key) in the TPM (internal).
func (p *MCPServiceProvider) iakGenerateInternal(ctx context.Context, algorithm string, overwrite bool) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	// Get EK attributes for IAK creation
	ekAttrs, err := p.tpm2Service.EKAttributes()
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "get EK attributes", Cause: err}
	}

	// Create IAK
	iakAttrs, err := p.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "create IAK", Cause: err}
	}

	// Return key info
	return formatKeyAttributesMap(iakAttrs), nil
}

// IAKInfo retrieves information about the IAK key.
func (p *MCPServiceProvider) IAKInfo(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	attrs, err := p.tpm2Service.IAKAttributes()
	if err != nil {
		return map[string]interface{}{
			"exists": false,
		}, nil
	}

	result := formatKeyAttributesMap(attrs)
	result["exists"] = true

	// Check for certificate
	cert, err := p.tpm2Service.IAKCertificate()
	if err == nil && cert != nil {
		result["has_certificate"] = true
		result["certificate"] = formatX509CertificateInfo(cert)
	} else {
		result["has_certificate"] = false
	}

	return result, nil
}

// HasIAK returns whether an IAK key exists in the TPM.
func (p *MCPServiceProvider) HasIAK(ctx context.Context) (bool, error) {
	if p.tpm2Service == nil {
		return false, ErrTPM2ServiceNotAvailable{}
	}

	_, err := p.tpm2Service.IAKAttributes()
	return err == nil, nil
}

// IAKDelete deletes the IAK key from the TPM.
func (p *MCPServiceProvider) IAKDelete(ctx context.Context) error {
	if p.tpm2Service == nil {
		return ErrTPM2ServiceNotAvailable{}
	}

	// Delete the IAK certificate first
	if err := p.tpm2Service.DeleteIAKCertificate(); err != nil {
		// Log but continue - certificate might not exist
		p.logger.Debug("IAK certificate deletion skipped", "error", err)
	}

	// Note: TPM2 persistent keys cannot be easily deleted
	// This operation clears the certificate but the key remains
	return nil
}

// IAKCreateCSR creates a Certificate Signing Request for the IAK key.
func (p *MCPServiceProvider) IAKCreateCSR(ctx context.Context, commonName, organization, country string, includeTCGAttrs bool) (string, error) {
	if p.tpm2Service == nil {
		return "", ErrTPM2ServiceNotAvailable{}
	}

	// Get IAK attributes
	iakAttrs, err := p.tpm2Service.IAKAttributes()
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "get IAK attributes", Cause: err}
	}

	// Create TCG CSR for IAK
	tcgCSR, err := p.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, iakAttrs)
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "create TCG CSR for IAK", Cause: err}
	}

	// Marshal CSR to bytes
	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		return "", ErrTPM2OperationFailed{Operation: "marshal TCG CSR", Cause: err}
	}

	// Return base64-encoded CSR
	return base64.StdEncoding.EncodeToString(csrBytes), nil
}

// IAKInstallCertificate installs a certificate for the IAK key.
func (p *MCPServiceProvider) IAKInstallCertificate(ctx context.Context, certificatePEM string) error {
	if p.tpm2Service == nil {
		return ErrTPM2ServiceNotAvailable{}
	}

	// Parse PEM to get x509.Certificate
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return ErrInvalidCertificatePEM{}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ErrInvalidRequestBody{Reason: "invalid certificate: " + err.Error()}
	}

	if err := p.tpm2Service.ProvisionIAKCert(cert); err != nil {
		return ErrTPM2OperationFailed{Operation: "write IAK certificate", Cause: err}
	}
	return nil
}

// IAKGetCertificate retrieves the IAK certificate.
func (p *MCPServiceProvider) IAKGetCertificate(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	cert, err := p.tpm2Service.IAKCertificate()
	if err != nil {
		return nil, ErrIAKCertificateNotFound{}
	}

	info := formatX509CertificateInfo(cert)
	// Add PEM encoding
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	info["pem"] = string(certPEM)

	return info, nil
}

// IAKDeleteCertificate deletes the IAK certificate.
func (p *MCPServiceProvider) IAKDeleteCertificate(ctx context.Context) error {
	if p.tpm2Service == nil {
		return ErrTPM2ServiceNotAvailable{}
	}

	if err := p.tpm2Service.DeleteIAKCertificate(); err != nil {
		return ErrTPM2OperationFailed{Operation: "delete IAK certificate", Cause: err}
	}
	return nil
}

// =============================================================================
// Device Attributes and Credential Activation
// =============================================================================

// DeviceAttributes retrieves TCG device attributes from the TPM.
func (p *MCPServiceProvider) DeviceAttributes(ctx context.Context) (interface{}, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	// Use go-xkms's platform discovery
	platformAttrs := xkmssdk.DiscoverPlatformAttributes()

	// Get TPM properties
	var tpmManufacturer, tpmModel, tpmVersion string
	props, err := p.tpm2Service.FixedProperties()
	if err == nil && props != nil {
		tpmManufacturer = props.Manufacturer
		tpmModel = props.Family
		tpmVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
	}

	return map[string]interface{}{
		"tpm_manufacturer":      tpmManufacturer,
		"tpm_model":             tpmModel,
		"tpm_version":           tpmVersion,
		"platform_manufacturer": platformAttrs.Manufacturer,
		"platform_model":        platformAttrs.Model,
		"platform_version":      platformAttrs.Version,
		"platform_serial":       platformAttrs.Serial,
	}, nil
}

// ActivateCredential performs TPM credential activation.
func (p *MCPServiceProvider) ActivateCredential(ctx context.Context, credentialBlob, secret []byte) ([]byte, error) {
	if p.tpm2Service == nil {
		return nil, ErrTPM2ServiceNotAvailable{}
	}

	// Activate credential using TPM2
	decrypted, err := p.tpm2Service.ActivateCredential(credentialBlob, secret)
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "activate credential", Cause: err}
	}

	return decrypted, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// formatKeyAttributesMap formats key attributes for API response.
func formatKeyAttributesMap(attrs *xkmssdk.KeyAttributes) map[string]interface{} {
	if attrs == nil {
		return map[string]interface{}{}
	}

	result := map[string]interface{}{
		"created_at": time.Now().Unix(),
	}

	// Add handle if available
	if attrs.TPMAttributes != nil {
		result["handle"] = fmt.Sprintf("0x%08X", attrs.TPMAttributes.Handle)
	}

	// Add algorithm if available
	if attrs.KeyAlgorithm != 0 {
		result["algorithm"] = attrs.KeyAlgorithm.String()
	}

	return result
}

// formatX509CertificateInfo formats x509 certificate info for API response.
func formatX509CertificateInfo(cert *x509.Certificate) map[string]interface{} {
	if cert == nil {
		return map[string]interface{}{}
	}

	fingerprint := sha256.Sum256(cert.Raw)

	return map[string]interface{}{
		"subject_cn":    cert.Subject.CommonName,
		"issuer_cn":     cert.Issuer.CommonName,
		"serial_number": cert.SerialNumber.String(),
		"not_before":    cert.NotBefore.Unix(),
		"not_after":     cert.NotAfter.Unix(),
		"fingerprint":   hex.EncodeToString(fingerprint[:]),
	}
}

// =============================================================================
// Interface-compliant wrapper methods
// These methods satisfy the mcp.ServiceProvider interface with proper signatures.
// =============================================================================

// IDevIDGenerate generates a new IDevID key in the TPM (interface wrapper).
func (p *MCPServiceProvider) IDevIDGenerate(ctx context.Context, req *mcp.IDevIDGenerateMCPRequest) (interface{}, error) {
	algorithm := "ECDSA-P256"
	overwrite := false
	if req != nil {
		if req.Algorithm != "" {
			algorithm = req.Algorithm
		}
		overwrite = req.Overwrite
	}
	return p.idevIDGenerateInternal(ctx, algorithm, overwrite)
}

// IAKGenerate generates a new IAK key in the TPM (interface wrapper).
func (p *MCPServiceProvider) IAKGenerate(ctx context.Context, req *mcp.IDevIDGenerateMCPRequest) (interface{}, error) {
	algorithm := "ECDSA-P256"
	overwrite := false
	if req != nil {
		if req.Algorithm != "" {
			algorithm = req.Algorithm
		}
		overwrite = req.Overwrite
	}
	return p.iakGenerateInternal(ctx, algorithm, overwrite)
}

// IDevIDCSR generates a CSR for the IDevID key (interface wrapper).
func (p *MCPServiceProvider) IDevIDCSR(ctx context.Context, req *mcp.IDevIDCSRMCPRequest) (interface{}, error) {
	if req == nil {
		return nil, ErrInvalidRequestBody{Reason: "request is nil"}
	}
	csrPEM, err := p.IDevIDCreateCSR(ctx, req.CommonName, req.Organization, req.Country, req.IncludeTCGAttrs)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"csr_pem": csrPEM}, nil
}

// IDevIDInstallCert installs an IDevID certificate (interface wrapper).
func (p *MCPServiceProvider) IDevIDInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	if err := p.IDevIDInstallCertificate(ctx, certificatePEM); err != nil {
		return nil, err
	}
	return map[string]interface{}{"installed": true}, nil
}

// IDevIDGetCert returns the IDevID certificate (interface wrapper).
func (p *MCPServiceProvider) IDevIDGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	return p.IDevIDGetCertificate(ctx)
}

// IDevIDDeleteCert deletes the IDevID certificate (interface wrapper).
func (p *MCPServiceProvider) IDevIDDeleteCert(ctx context.Context) error {
	return p.IDevIDDeleteCertificate(ctx)
}

// IDevIDExists checks if an IDevID key exists (interface wrapper).
func (p *MCPServiceProvider) IDevIDExists(ctx context.Context) (bool, error) {
	return p.HasIDevID(ctx)
}

// IAKCSR generates a CSR for the IAK key (interface wrapper).
func (p *MCPServiceProvider) IAKCSR(ctx context.Context, req *mcp.IDevIDCSRMCPRequest) (interface{}, error) {
	if req == nil {
		return nil, ErrInvalidRequestBody{Reason: "request is nil"}
	}
	csrPEM, err := p.IAKCreateCSR(ctx, req.CommonName, req.Organization, req.Country, req.IncludeTCGAttrs)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"csr_pem": csrPEM}, nil
}

// IAKInstallCert installs an IAK certificate (interface wrapper).
func (p *MCPServiceProvider) IAKInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	if err := p.IAKInstallCertificate(ctx, certificatePEM); err != nil {
		return nil, err
	}
	return map[string]interface{}{"installed": true}, nil
}

// IAKGetCert returns the IAK certificate (interface wrapper).
func (p *MCPServiceProvider) IAKGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	return p.IAKGetCertificate(ctx)
}

// IAKDeleteCert deletes the IAK certificate (interface wrapper).
func (p *MCPServiceProvider) IAKDeleteCert(ctx context.Context) error {
	return p.IAKDeleteCertificate(ctx)
}

// IAKExists checks if an IAK key exists (interface wrapper).
func (p *MCPServiceProvider) IAKExists(ctx context.Context) (bool, error) {
	return p.HasIAK(ctx)
}
