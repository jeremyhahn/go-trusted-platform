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
	"fmt"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

// =============================================================================
// IDevID Operations
// =============================================================================

// The IDevID and IAK tools delegate to the shared IDevIDGRPCService, the
// service the gRPC, REST v1 and embedded transports call, so each tool
// answers with the gRPC reply message and fails with the gRPC error class.

// deviceIdentityService returns the injected IDevIDGRPCService.
func (p *MCPServiceProvider) deviceIdentityService() (*IDevIDGRPCService, error) {
	if p.idevidService == nil {
		return nil, ErrIDevIDServiceNotConfigured{}
	}
	return p.idevidService, nil
}

// deviceIdentityReply returns a gRPC reply as the tool result. A failed call
// yields a nil interface rather than a typed nil pointer.
func deviceIdentityReply[T any](reply *T, err error) (interface{}, error) {
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// deviceKeyAlgorithm maps an MCP algorithm name onto the pb enum. A name the
// SDK does not know stays unspecified, the service default.
func deviceKeyAlgorithm(name string) platformv1.DeviceKeyAlgorithm {
	algorithm, ok := idevidsvc.AlgorithmToProto(name)
	if !ok {
		return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED
	}
	return algorithm
}

// csrTemplate maps the MCP CSR arguments onto the pb CSR template.
func csrTemplate(req *mcp.IDevIDCSRMCPRequest) *platformv1.CSRTemplate {
	if req == nil {
		return nil
	}
	return &platformv1.CSRTemplate{
		CommonName:         req.CommonName,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Country:            req.Country,
		Province:           req.Province,
		Locality:           req.Locality,
		DnsNames:           req.DNSNames,
		EmailAddresses:     req.EmailAddresses,
	}
}

// certificateReply drops the PEM encoding when the caller asked for the
// certificate without it; the DER and the parsed fields remain.
func certificateReply(cert *platformv1.DeviceIdentityCertificate, includePEM bool) {
	if cert != nil && !includePEM {
		cert.Pem = nil
	}
}

// IDevIDGenerate generates the IDevID key through GenerateIDevID.
func (p *MCPServiceProvider) IDevIDGenerate(ctx context.Context, req *mcp.IDevIDGenerateMCPRequest) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	config := &platformv1.IDevIDConfig{}
	if req != nil {
		config.Algorithm = deviceKeyAlgorithm(req.Algorithm)
		config.Overwrite = req.Overwrite
	}
	return deviceIdentityReply(svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{Config: config}))
}

// IDevIDInfo reports the IDevID key through GetIDevIDInfo.
func (p *MCPServiceProvider) IDevIDInfo(ctx context.Context) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	return deviceIdentityReply(svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{}))
}

// IDevIDExists reports whether the IDevID key exists through HasIDevID.
func (p *MCPServiceProvider) IDevIDExists(ctx context.Context) (bool, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return false, err
	}
	reply, err := svc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})
	if err != nil {
		return false, err
	}
	return reply.GetExists(), nil
}

// IDevIDDelete answers as DeleteIDevID does: it refuses with
// ErrDeviceIdentityKeyNotDeletable and changes nothing.
func (p *MCPServiceProvider) IDevIDDelete(ctx context.Context) error {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return err
	}
	_, err = svc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
	return err
}

// IDevIDCSR creates the IDevID CSR through CreateIDevIDCSR.
func (p *MCPServiceProvider) IDevIDCSR(ctx context.Context, req *mcp.IDevIDCSRMCPRequest) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	return deviceIdentityReply(svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{Template: csrTemplate(req)}))
}

// IDevIDInstallCert installs the IDevID certificate through
// InstallIDevIDCertificate, which refuses a certificate whose public key is
// not the TPM-resident IDevID key.
func (p *MCPServiceProvider) IDevIDInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	return deviceIdentityReply(svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
		CertificatePem: []byte(certificatePEM),
	}))
}

// IDevIDGetCert returns the IDevID certificate through GetIDevIDCertificate.
func (p *MCPServiceProvider) IDevIDGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	reply, err := svc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
	if err != nil {
		return nil, err
	}
	certificateReply(reply.GetCertificate(), includePEM)
	return reply, nil
}

// IDevIDDeleteCert deletes the IDevID certificate through
// DeleteIDevIDCertificate.
func (p *MCPServiceProvider) IDevIDDeleteCert(ctx context.Context) error {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return err
	}
	_, err = svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})
	return err
}

// IAKGenerate generates the IAK through GenerateIAK.
func (p *MCPServiceProvider) IAKGenerate(ctx context.Context, req *mcp.IDevIDGenerateMCPRequest) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	config := &platformv1.IAKConfig{}
	if req != nil {
		config.Algorithm = deviceKeyAlgorithm(req.Algorithm)
		config.Overwrite = req.Overwrite
	}
	return deviceIdentityReply(svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{Config: config}))
}

// IAKInfo reports the IAK through GetIAKInfo.
func (p *MCPServiceProvider) IAKInfo(ctx context.Context) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	return deviceIdentityReply(svc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{}))
}

// IAKExists reports whether the IAK exists through HasIAK.
func (p *MCPServiceProvider) IAKExists(ctx context.Context) (bool, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return false, err
	}
	reply, err := svc.HasIAK(ctx, &platformv1.HasIAKRequest{})
	if err != nil {
		return false, err
	}
	return reply.GetExists(), nil
}

// IAKDelete answers as DeleteIAK does: it refuses with
// ErrDeviceIdentityKeyNotDeletable and changes nothing.
func (p *MCPServiceProvider) IAKDelete(ctx context.Context) error {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return err
	}
	_, err = svc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
	return err
}

// IAKCSR creates the IAK CSR through CreateIAKCSR.
func (p *MCPServiceProvider) IAKCSR(ctx context.Context, req *mcp.IDevIDCSRMCPRequest) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	return deviceIdentityReply(svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{Template: csrTemplate(req)}))
}

// IAKInstallCert installs the IAK certificate through InstallIAKCertificate,
// which refuses a certificate whose public key is not the TPM-resident IAK.
func (p *MCPServiceProvider) IAKInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	return deviceIdentityReply(svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
		CertificatePem: []byte(certificatePEM),
	}))
}

// IAKGetCert returns the IAK certificate through GetIAKCertificate.
func (p *MCPServiceProvider) IAKGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return nil, err
	}
	reply, err := svc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
	if err != nil {
		return nil, err
	}
	certificateReply(reply.GetCertificate(), includePEM)
	return reply, nil
}

// IAKDeleteCert deletes the IAK certificate through DeleteIAKCertificate.
func (p *MCPServiceProvider) IAKDeleteCert(ctx context.Context) error {
	svc, err := p.deviceIdentityService()
	if err != nil {
		return err
	}
	_, err = svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})
	return err
}

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

	// Delegate through the shared activateCredential path.
	decrypted, err := activateCredential(p.tpm2Service, credentialBlob, secret)
	if err != nil {
		return nil, ErrTPM2OperationFailed{Operation: "activate credential", Cause: err}
	}

	return decrypted, nil
}

// =============================================================================
// Helper Functions
// =============================================================================
