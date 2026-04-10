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

package main

import (
	"log/slog"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// VTPMBinding exposes virtual TPM service methods to the Wails frontend.
type VTPMBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewVTPMBinding creates a new VTPMBinding.
func NewVTPMBinding(logger *slog.Logger, conn *ConnectionBinding) *VTPMBinding {
	return &VTPMBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *VTPMBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// CreateBundle creates a new vTPM bundle.
func (b *VTPMBinding) CreateBundle(mode, hostname, ekAlgorithm, templateID string,
	secureBootEnabled bool, labels map[string]string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	bundleMode, err := parseBundleMode(mode)
	if err != nil {
		return nil, err
	}
	ekAlgo, err := parseEKAlgorithm(ekAlgorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().CreateBundle(b.conn.ctx, &platformv1.CreateBundleRequest{
		Options: &platformv1.CreateBundleOptions{
			Mode:              bundleMode,
			Hostname:          hostname,
			EkAlgorithm:       ekAlgo,
			SecureBootEnabled: secureBootEnabled,
			Labels:            labels,
			TemplateId:        templateID,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetBundle retrieves a vTPM bundle by ID.
func (b *VTPMBinding) GetBundle(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().GetBundle(b.conn.ctx, &platformv1.GetBundleRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteBundle deletes a vTPM bundle by ID.
func (b *VTPMBinding) DeleteBundle(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().DeleteBundle(b.conn.ctx, &platformv1.DeleteBundleRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListBundles lists vTPM bundles with optional filtering.
func (b *VTPMBinding) ListBundles(mode string, labels map[string]string,
	limit, offset int32) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	bundleMode, err := parseBundleMode(mode)
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().ListBundles(b.conn.ctx, &platformv1.ListBundlesRequest{
		Options: &platformv1.ListBundleOptions{
			Mode:   bundleMode,
			Labels: labels,
			Limit:  limit,
			Offset: offset,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateTemplate creates a new vTPM template.
func (b *VTPMBinding) CreateTemplate(id, description, ekAlgorithm string,
	secureBootEnabled bool) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	ekAlgo, err := parseEKAlgorithm(ekAlgorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().CreateTemplate(b.conn.ctx, &platformv1.CreateTemplateRequest{
		Options: &platformv1.CreateTemplateOptions{
			Id:                id,
			Description:       description,
			EkAlgorithm:       ekAlgo,
			SecureBootEnabled: secureBootEnabled,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetTemplate retrieves a vTPM template by ID.
func (b *VTPMBinding) GetTemplate(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().GetTemplate(b.conn.ctx, &platformv1.GetTemplateRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteTemplate deletes a vTPM template by ID.
func (b *VTPMBinding) DeleteTemplate(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().DeleteTemplate(b.conn.ctx, &platformv1.DeleteTemplateRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListTemplates lists all vTPM templates.
func (b *VTPMBinding) ListTemplates() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().ListTemplates(b.conn.ctx, &platformv1.ListTemplatesRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CloneTemplate clones a vTPM template into a new bundle.
func (b *VTPMBinding) CloneTemplate(templateID, hostname string,
	labels map[string]string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().CloneTemplate(b.conn.ctx, &platformv1.CloneTemplateRequest{
		Options: &platformv1.CloneOptions{
			TemplateId: templateID,
			Hostname:   hostname,
			Labels:     labels,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ValidateBundle validates a vTPM bundle by ID.
func (b *VTPMBinding) ValidateBundle(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().ValidateBundle(b.conn.ctx, &platformv1.ValidateBundleRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetBundlePath returns the filesystem path for a vTPM bundle.
func (b *VTPMBinding) GetBundlePath(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().GetBundlePath(b.conn.ctx, &platformv1.GetBundlePathRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetTPMSocketPath returns the TPM socket path for a vTPM bundle.
func (b *VTPMBinding) GetTPMSocketPath(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().GetTPMSocketPath(b.conn.ctx, &platformv1.GetTPMSocketPathRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetNVRAMPath returns the NVRAM path for a vTPM bundle.
func (b *VTPMBinding) GetNVRAMPath(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().GetNVRAMPath(b.conn.ctx, &platformv1.GetNVRAMPathRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// StartVTPM starts a virtual TPM instance by bundle ID.
func (b *VTPMBinding) StartVTPM(bundleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().StartVTPM(b.conn.ctx, &platformv1.StartVTPMRequest{
		BundleId: bundleID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// StopVTPM stops a virtual TPM instance by bundle ID.
func (b *VTPMBinding) StopVTPM(bundleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().StopVTPM(b.conn.ctx, &platformv1.StopVTPMRequest{
		BundleId: bundleID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// IsVTPMRunning checks whether a virtual TPM instance is running.
func (b *VTPMBinding) IsVTPMRunning(bundleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().IsVTPMRunning(b.conn.ctx, &platformv1.IsVTPMRunningRequest{
		BundleId: bundleID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// QuoteVTPM generates a quote from a virtual TPM.
func (b *VTPMBinding) QuoteVTPM(bundleID string, nonce []byte,
	pcrs []int32) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().QuoteVTPM(b.conn.ctx, &platformv1.QuoteVTPMRequest{
		BundleId: bundleID,
		Nonce:    nonce,
		Pcrs:     pcrs,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// SealVTPM seals data using a virtual TPM.
func (b *VTPMBinding) SealVTPM(bundleID string, data []byte,
	pcrs []int32, authValue string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().SealVTPM(b.conn.ctx, &platformv1.SealVTPMRequest{
		BundleId:  bundleID,
		Data:      data,
		Pcrs:      pcrs,
		AuthValue: authValue,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// UnsealVTPM unseals previously sealed data from a virtual TPM.
func (b *VTPMBinding) UnsealVTPM(bundleID string, sealedData []byte,
	authValue string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().UnsealVTPM(b.conn.ctx, &platformv1.UnsealVTPMRequest{
		BundleId:   bundleID,
		SealedData: sealedData,
		AuthValue:  authValue,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ExtendVTPMPCR extends a PCR in a virtual TPM.
func (b *VTPMBinding) ExtendVTPMPCR(bundleID string, pcrIndex int32,
	data []byte) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().ExtendVTPMPCR(b.conn.ctx, &platformv1.ExtendVTPMPCRRequest{
		BundleId: bundleID,
		PcrIndex: pcrIndex,
		Data:     data,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ReadVTPMPCR reads a PCR value from a virtual TPM.
func (b *VTPMBinding) ReadVTPMPCR(bundleID string,
	pcrIndex int32) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.VTPM().ReadVTPMPCR(b.conn.ctx, &platformv1.ReadVTPMPCRRequest{
		BundleId: bundleID,
		PcrIndex: pcrIndex,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// parseBundleMode converts a bundle mode string to the protobuf enum.
// It accepts both short names (e.g., "template") and full enum names
// (e.g., "BUNDLE_MODE_TEMPLATE").
func parseBundleMode(input string) (platformv1.BundleMode, error) {
	if input == "" {
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED, nil
	}

	upper := strings.ToUpper(input)

	if val, ok := platformv1.BundleMode_value[upper]; ok {
		return platformv1.BundleMode(val), nil
	}

	prefixed := "BUNDLE_MODE_" + upper
	if val, ok := platformv1.BundleMode_value[prefixed]; ok {
		return platformv1.BundleMode(val), nil
	}

	return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED,
		&InvalidBundleModeError{Input: input}
}

// parseEKAlgorithm converts an EK algorithm string to the protobuf enum.
// It accepts both short names (e.g., "rsa") and full enum names
// (e.g., "EK_ALGORITHM_RSA").
func parseEKAlgorithm(input string) (platformv1.EKAlgorithm, error) {
	if input == "" {
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED, nil
	}

	upper := strings.ToUpper(input)

	if val, ok := platformv1.EKAlgorithm_value[upper]; ok {
		return platformv1.EKAlgorithm(val), nil
	}

	prefixed := "EK_ALGORITHM_" + upper
	if val, ok := platformv1.EKAlgorithm_value[prefixed]; ok {
		return platformv1.EKAlgorithm(val), nil
	}

	return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED,
		&InvalidEKAlgorithmError{Input: input}
}
