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
	"io"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// Domain-typed convenience methods
//
// These methods accept and return domain types instead of proto types,
// enabling callers to avoid importing platformv1 directly.

// CreateBundleDomain creates a new vTPM bundle using domain types.
func (c *Client) CreateBundleDomain(ctx context.Context, opts *CreateBundleOptions) (*CreateBundleResponse, error) {
	protoOpts := &platformv1.CreateBundleOptions{
		Mode:              BundleModeToProto(opts.Mode),
		Hostname:          opts.Hostname,
		EkAlgorithm:       EKAlgorithmToProto(opts.EKAlgorithm),
		SecureBootEnabled: opts.SecureBootEnabled,
		TemplateId:        opts.TemplateID,
		Labels:            opts.Labels,
	}
	bundle, err := c.CreateBundle(ctx, protoOpts)
	if err != nil {
		return nil, err
	}
	return &CreateBundleResponse{
		Status: &Status{Success: true},
		Bundle: BundleFromProto(bundle),
	}, nil
}

// GetBundleDomain retrieves a vTPM bundle by ID using domain types.
func (c *Client) GetBundleDomain(ctx context.Context, id string) (*GetBundleResponse, error) {
	bundle, err := c.GetBundle(ctx, id)
	if err != nil {
		return nil, err
	}
	return &GetBundleResponse{
		Bundle: BundleFromProto(bundle),
	}, nil
}

// DeleteBundleDomain deletes a vTPM bundle using domain types.
func (c *Client) DeleteBundleDomain(ctx context.Context, id string) (*DeleteResponse, error) {
	err := c.DeleteBundle(ctx, id)
	if err != nil {
		return nil, err
	}
	return &DeleteResponse{
		Status: &Status{Success: true, Message: "Bundle deleted successfully"},
	}, nil
}

// ListBundlesDomain lists vTPM bundles using domain types.
func (c *Client) ListBundlesDomain(ctx context.Context, opts *ListBundleOptions) (*ListBundlesResponse, error) {
	protoOpts := &platformv1.ListBundleOptions{}
	if opts != nil {
		protoOpts.Mode = BundleModeToProto(opts.Mode)
		protoOpts.Limit = opts.Limit
		protoOpts.Offset = opts.Offset
	}
	bundles, total, err := c.ListBundles(ctx, protoOpts)
	if err != nil {
		return nil, err
	}
	return &ListBundlesResponse{
		Bundles: BundlesFromProto(bundles),
		Total:   total,
	}, nil
}

// CreateTemplateDomain creates a new vTPM template using domain types.
func (c *Client) CreateTemplateDomain(ctx context.Context, opts *CreateTemplateOptions) (*CreateTemplateResponse, error) {
	protoOpts := &platformv1.CreateTemplateOptions{
		Id:                opts.ID,
		Description:       opts.Description,
		EkAlgorithm:       EKAlgorithmToProto(opts.EKAlgorithm),
		SecureBootEnabled: opts.SecureBootEnabled,
	}
	tmpl, err := c.CreateTemplate(ctx, protoOpts)
	if err != nil {
		return nil, err
	}
	return &CreateTemplateResponse{
		Status:   &Status{Success: true},
		Template: TemplateFromProto(tmpl),
	}, nil
}

// GetTemplateDomain retrieves a vTPM template by ID using domain types.
func (c *Client) GetTemplateDomain(ctx context.Context, id string) (*Template, error) {
	tmpl, err := c.GetTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	return TemplateFromProto(tmpl), nil
}

// DeleteTemplateDomain deletes a vTPM template using domain types.
func (c *Client) DeleteTemplateDomain(ctx context.Context, id string) (*DeleteResponse, error) {
	err := c.DeleteTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	return &DeleteResponse{
		Status: &Status{Success: true, Message: "Template deleted successfully"},
	}, nil
}

// ListTemplatesDomain lists all vTPM templates using domain types.
func (c *Client) ListTemplatesDomain(ctx context.Context) (*ListTemplatesResponse, error) {
	templates, err := c.ListTemplates(ctx)
	if err != nil {
		return nil, err
	}
	return &ListTemplatesResponse{
		Templates: TemplatesFromProto(templates),
	}, nil
}

// CloneTemplateDomain clones a template to create a new bundle using domain types.
func (c *Client) CloneTemplateDomain(ctx context.Context, opts *CloneOptions) (*CloneResponse, error) {
	protoOpts := &platformv1.CloneOptions{
		TemplateId: opts.TemplateID,
		Hostname:   opts.Hostname,
		Labels:     opts.Labels,
	}
	bundle, err := c.CloneTemplate(ctx, protoOpts)
	if err != nil {
		return nil, err
	}
	return &CloneResponse{
		Status: &Status{Success: true},
		Bundle: BundleFromProto(bundle),
	}, nil
}

// ExportBundleDomain exports a vTPM bundle using domain types.
func (c *Client) ExportBundleDomain(ctx context.Context, id string, writer io.Writer) error {
	return c.ExportBundle(ctx, id, writer)
}

// ImportBundleDomain imports a vTPM bundle using domain types.
func (c *Client) ImportBundleDomain(ctx context.Context, reader io.Reader) (*ImportBundleResponse, error) {
	bundle, err := c.ImportBundle(ctx, reader)
	if err != nil {
		return nil, err
	}
	return &ImportBundleResponse{
		Status: &Status{Success: true},
		Bundle: BundleFromProto(bundle),
	}, nil
}

// ValidateBundleDomain validates a vTPM bundle using domain types.
func (c *Client) ValidateBundleDomain(ctx context.Context, id string) (bool, []string, error) {
	return c.ValidateBundle(ctx, id)
}

// GetBundlePathDomain returns the filesystem path for a bundle using domain types.
func (c *Client) GetBundlePathDomain(ctx context.Context, id string) (string, error) {
	return c.GetBundlePath(ctx, id)
}

// GetTPMSocketPathDomain returns the TPM socket path for a bundle using domain types.
func (c *Client) GetTPMSocketPathDomain(ctx context.Context, id string) (string, error) {
	return c.GetTPMSocketPath(ctx, id)
}

// GetNVRAMPathDomain returns the NVRAM path for a bundle using domain types.
func (c *Client) GetNVRAMPathDomain(ctx context.Context, id string) (string, error) {
	return c.GetNVRAMPath(ctx, id)
}

// StartDomain starts a vTPM instance using domain types.
func (c *Client) StartDomain(ctx context.Context, bundleID string) (*StartResponse, error) {
	resp, err := c.grpc.StartVTPM(ctx, &platformv1.StartVTPMRequest{BundleId: bundleID})
	if err != nil {
		return nil, &ErrStartFailed{BundleID: bundleID, Cause: err}
	}
	return &StartResponse{
		BundleID:   resp.BundleId,
		Running:    resp.Running,
		SocketPath: resp.SocketPath,
	}, nil
}

// StopDomain stops a vTPM instance using domain types.
func (c *Client) StopDomain(ctx context.Context, bundleID string) (*StopResponse, error) {
	resp, err := c.grpc.StopVTPM(ctx, &platformv1.StopVTPMRequest{BundleId: bundleID})
	if err != nil {
		return nil, &ErrStopFailed{BundleID: bundleID, Cause: err}
	}
	return &StopResponse{
		BundleID: resp.BundleId,
		Stopped:  resp.Stopped,
	}, nil
}

// IsRunningDomain checks if a vTPM instance is running using domain types.
func (c *Client) IsRunningDomain(ctx context.Context, bundleID string) (*IsRunningResponse, error) {
	resp, err := c.grpc.IsVTPMRunning(ctx, &platformv1.IsVTPMRunningRequest{BundleId: bundleID})
	if err != nil {
		return nil, &ErrIsRunningFailed{BundleID: bundleID, Cause: err}
	}
	return &IsRunningResponse{
		BundleID: resp.BundleId,
		Running:  resp.Running,
	}, nil
}

// QuoteDomain generates a TPM quote using domain types.
func (c *Client) QuoteDomain(ctx context.Context, bundleID string, pcrIndices []int32, nonce []byte) (*QuoteResponse, error) {
	resp, err := c.grpc.QuoteVTPM(ctx, &platformv1.QuoteVTPMRequest{
		BundleId: bundleID,
		Pcrs:     pcrIndices,
		Nonce:    nonce,
	})
	if err != nil {
		return nil, &ErrQuoteFailed{BundleID: bundleID, Cause: err}
	}
	return &QuoteResponse{
		BundleID:      resp.BundleId,
		HashAlgorithm: resp.HashAlgorithm,
		Quote:         resp.Quote,
		Signature:     resp.Signature,
		PCRValues:     resp.PcrValues,
	}, nil
}

// SealDomain seals data to a vTPM using domain types.
func (c *Client) SealDomain(ctx context.Context, bundleID string, data []byte, pcrIndices []int32, authValue string) (*SealResponse, error) {
	resp, err := c.grpc.SealVTPM(ctx, &platformv1.SealVTPMRequest{
		BundleId:  bundleID,
		Data:      data,
		Pcrs:      pcrIndices,
		AuthValue: authValue,
	})
	if err != nil {
		return nil, &ErrSealFailed{BundleID: bundleID, Cause: err}
	}
	return &SealResponse{
		BundleID:   resp.BundleId,
		SealedData: resp.SealedData,
	}, nil
}

// UnsealDomain unseals data from a vTPM using domain types.
func (c *Client) UnsealDomain(ctx context.Context, bundleID string, sealedData []byte, authValue string) (*UnsealResponse, error) {
	resp, err := c.grpc.UnsealVTPM(ctx, &platformv1.UnsealVTPMRequest{
		BundleId:   bundleID,
		SealedData: sealedData,
		AuthValue:  authValue,
	})
	if err != nil {
		return nil, &ErrUnsealFailed{BundleID: bundleID, Cause: err}
	}
	return &UnsealResponse{
		BundleID: resp.BundleId,
		Data:     resp.Data,
	}, nil
}

// ExtendPCRDomain extends a PCR using domain types.
func (c *Client) ExtendPCRDomain(ctx context.Context, bundleID string, pcrIndex int32, data []byte) (*ExtendPCRResponse, error) {
	resp, err := c.grpc.ExtendVTPMPCR(ctx, &platformv1.ExtendVTPMPCRRequest{
		BundleId: bundleID,
		PcrIndex: pcrIndex,
		Data:     data,
	})
	if err != nil {
		return nil, &ErrExtendPCRFailed{BundleID: bundleID, Cause: err}
	}
	return &ExtendPCRResponse{
		BundleID: resp.BundleId,
		PCRIndex: resp.PcrIndex,
		Extended: resp.Extended,
	}, nil
}

// ReadPCRDomain reads a PCR value using domain types.
func (c *Client) ReadPCRDomain(ctx context.Context, bundleID string, pcrIndex int32) (*ReadPCRResponse, error) {
	resp, err := c.grpc.ReadVTPMPCR(ctx, &platformv1.ReadVTPMPCRRequest{
		BundleId: bundleID,
		PcrIndex: pcrIndex,
	})
	if err != nil {
		return nil, &ErrReadPCRFailed{BundleID: bundleID, Cause: err}
	}
	return &ReadPCRResponse{
		BundleID: resp.BundleId,
		PCRIndex: resp.PcrIndex,
		Value:    resp.Value,
	}, nil
}
