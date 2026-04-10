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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// InstanceClient provides access to vTPM instance service operations.
// This client manages the lifecycle of virtual TPM instances for device provisioning.
type InstanceClient struct {
	grpc platformv1.VTPMInstanceServiceClient
}

// NewInstanceClient creates a new vTPM instance service client.
func NewInstanceClient(conn transport.Adapter) (*InstanceClient, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &InstanceClient{
		grpc: platformv1.NewVTPMInstanceServiceClient(grpcConn),
	}, nil
}

// NewInstanceClientFromGRPC creates a new vTPM instance service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewInstanceClientFromGRPC(grpcClient platformv1.VTPMInstanceServiceClient) *InstanceClient {
	return &InstanceClient{
		grpc: grpcClient,
	}
}

// Instance CRUD Operations

// Create creates a new vTPM instance.
// If profileID is provided, the instance will be associated with that device profile.
// The config parameter allows customizing the vTPM instance configuration.
func (c *InstanceClient) Create(ctx context.Context, profileID uint64, config *platformv1.VTPMInstanceConfig) (*platformv1.VTPMInstance, error) {
	resp, err := c.grpc.CreateInstance(ctx, &platformv1.CreateVTPMInstanceRequest{
		ProfileId: profileID,
		Config:    config,
	})
	if err != nil {
		return nil, &ErrCreateInstanceFailed{Cause: err}
	}
	return resp.Instance, nil
}

// Get retrieves a vTPM instance by its ID.
func (c *InstanceClient) Get(ctx context.Context, id string) (*platformv1.VTPMInstance, error) {
	resp, err := c.grpc.GetInstance(ctx, &platformv1.GetVTPMInstanceRequest{
		Id: id,
	})
	if err != nil {
		return nil, &ErrGetInstanceFailed{ID: id, Cause: err}
	}
	return resp.Instance, nil
}

// GetByProfile retrieves a vTPM instance by its associated device profile ID.
func (c *InstanceClient) GetByProfile(ctx context.Context, profileID uint64) (*platformv1.VTPMInstance, error) {
	resp, err := c.grpc.GetInstanceByProfile(ctx, &platformv1.GetVTPMInstanceByProfileRequest{
		ProfileId: profileID,
	})
	if err != nil {
		return nil, &ErrGetInstanceByProfileFailed{ProfileID: profileID, Cause: err}
	}
	return resp.Instance, nil
}

// Delete removes a vTPM instance.
func (c *InstanceClient) Delete(ctx context.Context, id string) error {
	_, err := c.grpc.DeleteInstance(ctx, &platformv1.DeleteVTPMInstanceRequest{
		Id: id,
	})
	if err != nil {
		return &ErrDeleteInstanceFailed{ID: id, Cause: err}
	}
	return nil
}

// List returns vTPM instances with optional filtering and pagination.
// The request can include pagination parameters and label selectors for filtering.
func (c *InstanceClient) List(ctx context.Context, req *platformv1.ListVTPMInstancesRequest) ([]*platformv1.VTPMInstance, *common.PageResult, error) {
	if req == nil {
		req = &platformv1.ListVTPMInstancesRequest{}
	}
	resp, err := c.grpc.ListInstances(ctx, req)
	if err != nil {
		return nil, nil, &ErrListInstancesFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Instances, pageResult, nil
}

// Instance Lifecycle Operations

// Start starts a vTPM instance.
// Returns the socket path for TPM communication once the instance is running.
func (c *InstanceClient) Start(ctx context.Context, id string) (string, error) {
	resp, err := c.grpc.StartInstance(ctx, &platformv1.StartVTPMInstanceRequest{
		Id: id,
	})
	if err != nil {
		return "", &ErrStartInstanceFailed{ID: id, Cause: err}
	}
	return resp.SocketPath, nil
}

// Stop stops a running vTPM instance.
func (c *InstanceClient) Stop(ctx context.Context, id string) error {
	_, err := c.grpc.StopInstance(ctx, &platformv1.StopVTPMInstanceRequest{
		Id: id,
	})
	if err != nil {
		return &ErrStopInstanceFailed{ID: id, Cause: err}
	}
	return nil
}

// InstanceStatus holds the status information for a vTPM instance.
type InstanceStatus struct {
	// ID is the vTPM instance identifier.
	ID string
	// Running indicates if the vTPM is currently running.
	Running bool
	// SocketPath is the Unix socket path for TPM communication (if running).
	SocketPath string
}

// GetStatus retrieves the current status of a vTPM instance.
func (c *InstanceClient) GetStatus(ctx context.Context, id string) (*InstanceStatus, error) {
	resp, err := c.grpc.GetInstanceStatus(ctx, &platformv1.GetVTPMInstanceStatusRequest{
		Id: id,
	})
	if err != nil {
		return nil, &ErrGetInstanceStatusFailed{ID: id, Cause: err}
	}
	return &InstanceStatus{
		ID:         resp.Id,
		Running:    resp.Running,
		SocketPath: resp.SocketPath,
	}, nil
}

// EK Certificate Operations

// EKCertificate holds the EK certificate data and metadata.
type EKCertificate struct {
	// ID is the vTPM instance identifier.
	ID string
	// Certificate is the raw certificate data.
	Certificate []byte
	// Format is the certificate encoding format (e.g., "PEM", "DER").
	Format string
	// Subject is the certificate subject.
	Subject string
	// Issuer is the certificate issuer.
	Issuer string
	// SerialNumber is the certificate serial number.
	SerialNumber string
	// NotBefore is the certificate validity start time.
	NotBefore string
	// NotAfter is the certificate validity end time.
	NotAfter string
}

// GetEKCert retrieves the EK certificate for a vTPM instance.
// The format parameter specifies the desired encoding (e.g., "PEM" or "DER").
// If empty, defaults to "PEM".
func (c *InstanceClient) GetEKCert(ctx context.Context, id string, format string) (*EKCertificate, error) {
	resp, err := c.grpc.ExportEKCertificate(ctx, &platformv1.ExportEKCertificateRequest{
		Id:     id,
		Format: format,
	})
	if err != nil {
		return nil, &ErrExportEKCertFailed{ID: id, Cause: err}
	}
	var notBefore, notAfter string
	if resp.NotBefore != nil {
		notBefore = resp.NotBefore.AsTime().String()
	}
	if resp.NotAfter != nil {
		notAfter = resp.NotAfter.AsTime().String()
	}
	return &EKCertificate{
		ID:           resp.Id,
		Certificate:  resp.Certificate,
		Format:       resp.Format,
		Subject:      resp.Subject,
		Issuer:       resp.Issuer,
		SerialNumber: resp.SerialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}, nil
}

// EKFingerprint holds the EK certificate fingerprint data.
type EKFingerprint struct {
	// ID is the vTPM instance identifier.
	ID string
	// Fingerprint is the hash of the EK certificate.
	Fingerprint string
	// Algorithm is the hash algorithm used (e.g., "SHA256").
	Algorithm string
}

// GetEKFingerprint retrieves the EK certificate fingerprint for a vTPM instance.
func (c *InstanceClient) GetEKFingerprint(ctx context.Context, id string) (*EKFingerprint, error) {
	resp, err := c.grpc.GetEKFingerprint(ctx, &platformv1.GetEKFingerprintRequest{
		Id: id,
	})
	if err != nil {
		return nil, &ErrGetEKFingerprintFailed{ID: id, Cause: err}
	}
	return &EKFingerprint{
		ID:          resp.Id,
		Fingerprint: resp.Fingerprint,
		Algorithm:   resp.Algorithm,
	}, nil
}
