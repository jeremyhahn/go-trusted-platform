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

// Package vtpm provides a client for virtual TPM service operations.
package vtpm

import (
	"context"
	"io"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to vTPM service operations.
type Client struct {
	grpc platformv1.VTPMServiceClient
}

// NewClient creates a new vTPM service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewVTPMServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new vTPM service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.VTPMServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Bundle Operations

// CreateBundle creates a new vTPM bundle.
func (c *Client) CreateBundle(ctx context.Context, opts *platformv1.CreateBundleOptions) (*platformv1.Bundle, error) {
	resp, err := c.grpc.CreateBundle(ctx, &platformv1.CreateBundleRequest{Options: opts})
	if err != nil {
		return nil, &ErrCreateBundleFailed{Cause: err}
	}
	return resp.Bundle, nil
}

// GetBundle retrieves a vTPM bundle by ID.
func (c *Client) GetBundle(ctx context.Context, id string) (*platformv1.Bundle, error) {
	resp, err := c.grpc.GetBundle(ctx, &platformv1.GetBundleRequest{Id: id})
	if err != nil {
		return nil, &ErrGetBundleFailed{ID: id, Cause: err}
	}
	return resp.Bundle, nil
}

// DeleteBundle deletes a vTPM bundle.
func (c *Client) DeleteBundle(ctx context.Context, id string) error {
	_, err := c.grpc.DeleteBundle(ctx, &platformv1.DeleteBundleRequest{Id: id})
	if err != nil {
		return &ErrDeleteBundleFailed{ID: id, Cause: err}
	}
	return nil
}

// ListBundles lists vTPM bundles with optional filtering.
func (c *Client) ListBundles(ctx context.Context, opts *platformv1.ListBundleOptions) ([]*platformv1.Bundle, int32, error) {
	resp, err := c.grpc.ListBundles(ctx, &platformv1.ListBundlesRequest{Options: opts})
	if err != nil {
		return nil, 0, &ErrListBundlesFailed{Cause: err}
	}
	return resp.Bundles, resp.Total, nil
}

// Template Operations

// CreateTemplate creates a new vTPM template.
func (c *Client) CreateTemplate(ctx context.Context, opts *platformv1.CreateTemplateOptions) (*platformv1.Template, error) {
	resp, err := c.grpc.CreateTemplate(ctx, &platformv1.CreateTemplateRequest{Options: opts})
	if err != nil {
		return nil, &ErrCreateTemplateFailed{Cause: err}
	}
	return resp.Template, nil
}

// GetTemplate retrieves a vTPM template by ID.
func (c *Client) GetTemplate(ctx context.Context, id string) (*platformv1.Template, error) {
	resp, err := c.grpc.GetTemplate(ctx, &platformv1.GetTemplateRequest{Id: id})
	if err != nil {
		return nil, &ErrGetTemplateFailed{ID: id, Cause: err}
	}
	return resp.Template, nil
}

// DeleteTemplate deletes a vTPM template.
func (c *Client) DeleteTemplate(ctx context.Context, id string) error {
	_, err := c.grpc.DeleteTemplate(ctx, &platformv1.DeleteTemplateRequest{Id: id})
	if err != nil {
		return &ErrDeleteTemplateFailed{ID: id, Cause: err}
	}
	return nil
}

// ListTemplates lists all vTPM templates.
func (c *Client) ListTemplates(ctx context.Context) ([]*platformv1.Template, error) {
	resp, err := c.grpc.ListTemplates(ctx, &platformv1.ListTemplatesRequest{})
	if err != nil {
		return nil, &ErrListTemplatesFailed{Cause: err}
	}
	return resp.Templates, nil
}

// CloneTemplate clones a template to create a new bundle.
func (c *Client) CloneTemplate(ctx context.Context, opts *platformv1.CloneOptions) (*platformv1.Bundle, error) {
	resp, err := c.grpc.CloneTemplate(ctx, &platformv1.CloneTemplateRequest{Options: opts})
	if err != nil {
		return nil, &ErrCloneTemplateFailed{TemplateID: opts.TemplateId, Cause: err}
	}
	return resp.Bundle, nil
}

// Export/Import Operations

// ExportBundle exports a vTPM bundle as a streaming tar.gz archive.
func (c *Client) ExportBundle(ctx context.Context, id string, writer io.Writer) error {
	stream, err := c.grpc.ExportBundle(ctx, &platformv1.ExportBundleRequest{Id: id})
	if err != nil {
		return &ErrExportBundleFailed{ID: id, Cause: err}
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ErrExportBundleFailed{ID: id, Cause: err}
		}
		if _, err := writer.Write(resp.Data); err != nil {
			return &ErrExportBundleFailed{ID: id, Cause: err}
		}
	}
	return nil
}

// ImportBundle imports a vTPM bundle from a streaming tar.gz archive.
func (c *Client) ImportBundle(ctx context.Context, reader io.Reader) (*platformv1.Bundle, error) {
	stream, err := c.grpc.ImportBundle(ctx)
	if err != nil {
		return nil, &ErrImportBundleFailed{Cause: err}
	}

	buf := make([]byte, 32*1024) // 32KB chunks
	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &ErrImportBundleFailed{Cause: err}
		}
		if err := stream.Send(&platformv1.ImportBundleRequest{Data: buf[:n]}); err != nil {
			return nil, &ErrImportBundleFailed{Cause: err}
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, &ErrImportBundleFailed{Cause: err}
	}
	return resp.Bundle, nil
}

// Validation

// ValidateBundle validates a vTPM bundle.
func (c *Client) ValidateBundle(ctx context.Context, id string) (bool, []string, error) {
	resp, err := c.grpc.ValidateBundle(ctx, &platformv1.ValidateBundleRequest{Id: id})
	if err != nil {
		return false, nil, &ErrValidateBundleFailed{ID: id, Cause: err}
	}
	return resp.Valid, resp.Errors, nil
}

// Path Getters

// GetBundlePath returns the filesystem path for a bundle.
func (c *Client) GetBundlePath(ctx context.Context, id string) (string, error) {
	resp, err := c.grpc.GetBundlePath(ctx, &platformv1.GetBundlePathRequest{Id: id})
	if err != nil {
		return "", &ErrGetBundlePathFailed{ID: id, Cause: err}
	}
	return resp.Path, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle.
func (c *Client) GetTPMSocketPath(ctx context.Context, id string) (string, error) {
	resp, err := c.grpc.GetTPMSocketPath(ctx, &platformv1.GetTPMSocketPathRequest{Id: id})
	if err != nil {
		return "", &ErrGetTPMSocketPathFailed{ID: id, Cause: err}
	}
	return resp.Path, nil
}

// GetNVRAMPath returns the NVRAM path for a bundle.
func (c *Client) GetNVRAMPath(ctx context.Context, id string) (string, error) {
	resp, err := c.grpc.GetNVRAMPath(ctx, &platformv1.GetNVRAMPathRequest{Id: id})
	if err != nil {
		return "", &ErrGetNVRAMPathFailed{ID: id, Cause: err}
	}
	return resp.Path, nil
}
