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

//go:build integration

package tpm

import (
	"context"
	"os"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements TPMCommands using gRPC calls to platformd.
type GRPCAdapter struct {
	conn *grpc.ClientConn
	tpm  pb.TPMServiceClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformGRPC
	}

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrConnectionFailed{Protocol: "gRPC", Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.tpm = pb.NewTPMServiceClient(conn)

	// Verify connectivity by getting TPM info
	_, err = g.tpm.Info(ctx, &pb.TPMInfoRequest{})
	if err != nil {
		conn.Close()
		return ErrConnectionFailed{Protocol: "gRPC", Endpoint: endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// TPM Info Operations
// =============================================================================

// Info retrieves TPM information via gRPC.
func (g *GRPCAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := g.tpm.Info(ctx, &pb.TPMInfoRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Info", Err: err}
	}

	result := &InfoResult{
		Version:      formatTPMVersion(resp.Version),
		IsSimulator:  resp.IsSimulator,
		FIPSMode:     resp.FipsMode,
		MaxNVRAMSize: resp.MaxNvramSize,
	}

	if resp.Manufacturer != nil {
		result.Manufacturer = &ManufacturerInfo{
			Name:            resp.Manufacturer.Name,
			ID:              resp.Manufacturer.Id,
			Model:           resp.Manufacturer.Model,
			FirmwareVersion: resp.Manufacturer.FirmwareVersion,
		}
	}

	for _, bank := range resp.PcrBanks {
		result.PCRBanks = append(result.PCRBanks, formatPCRBank(bank))
	}

	return result, nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via gRPC.
func (g *GRPCAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	req := &pb.TPMProvisionRequest{
		CreateEk:            opts.CreateEK,
		CreateSrk:           opts.CreateSRK,
		CreateAk:            opts.CreateAK,
		OwnerPassword:       opts.OwnerPassword,
		EndorsementPassword: opts.EndorsementPassword,
	}

	resp, err := g.tpm.Provision(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Provision", Err: err}
	}

	result := &ProvisionResult{
		Success: resp.Status != nil && resp.Status.Success,
		Message: "",
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	result.EKCreated = len(resp.EkPublic) > 0
	result.SRKCreated = len(resp.SrkPublic) > 0
	result.AKCreated = len(resp.AkPublic) > 0

	return result, nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via gRPC.
func (g *GRPCAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	req := &pb.TPMClearRequest{
		OwnerPassword: opts.OwnerPassword,
		Confirm:       opts.Confirm,
	}

	resp, err := g.tpm.Clear(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Clear", Err: err}
	}

	result := &ClearResult{
		Success: resp.Status != nil && resp.Status.Success,
		Message: "",
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via gRPC.
func (g *GRPCAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	alg, err := parseKeyAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	req := &pb.CreateEKRequest{
		Attributes: &pb.KeyAttributes{
			Algorithm: alg,
		},
		Persistent: opts.Persistent,
	}

	resp, err := g.tpm.CreateEK(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "CreateEK", Err: err}
	}

	return &EKCreateResult{
		Success:   resp.Status != nil && resp.Status.Success,
		Handle:    resp.Handle,
		Algorithm: opts.Algorithm,
		PublicKey: resp.PublicKey,
		CreatedAt: time.Now(),
	}, nil
}

// EKInfo retrieves EK information via gRPC.
func (g *GRPCAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	req := &pb.GetEKRequest{
		Handle: handle,
	}

	resp, err := g.tpm.GetEK(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetEK", Err: err}
	}

	return &EKInfoResult{
		Handle:    resp.Handle,
		Algorithm: formatKeyAlgorithm(resp.Algorithm),
		PublicKey: resp.PublicKey,
	}, nil
}

// EKCertificate retrieves the EK certificate via gRPC.
func (g *GRPCAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	req := &pb.GetEKCertificateRequest{}

	resp, err := g.tpm.GetEKCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetEKCertificate", Err: err}
	}

	return &EKCertificateResult{
		Format:      resp.Format,
		Certificate: resp.Certificate,
	}, nil
}

// EKDelete deletes the EK via gRPC.
func (g *GRPCAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	req := &pb.DeleteEKRequest{
		Handle:   handle,
		Password: password,
	}

	resp, err := g.tpm.DeleteEK(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "DeleteEK", Err: err}
	}

	result := &EKDeleteResult{
		Success: resp.Status != nil && resp.Status.Success,
		Message: "",
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via gRPC.
func (g *GRPCAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	alg, err := parseKeyAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	req := &pb.CreateSRKRequest{
		Attributes: &pb.KeyAttributes{
			Algorithm: alg,
		},
		Persistent:     opts.Persistent,
		ParentHandle:   opts.Handle,
		ParentPassword: opts.Password,
	}

	resp, err := g.tpm.CreateSRK(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "CreateSRK", Err: err}
	}

	return &SRKCreateResult{
		Success:   resp.Status != nil && resp.Status.Success,
		Handle:    resp.Handle,
		Algorithm: opts.Algorithm,
		PublicKey: resp.PublicKey,
		CreatedAt: time.Now(),
	}, nil
}

// SRKInfo retrieves SRK information via gRPC.
func (g *GRPCAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	req := &pb.GetSRKRequest{
		Handle: handle,
	}

	resp, err := g.tpm.GetSRK(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetSRK", Err: err}
	}

	return &SRKInfoResult{
		Handle:    resp.Handle,
		Algorithm: formatKeyAlgorithm(resp.Algorithm),
		PublicKey: resp.PublicKey,
	}, nil
}

// SRKDelete deletes the SRK via gRPC.
func (g *GRPCAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	req := &pb.DeleteSRKRequest{
		Handle:   handle,
		Password: password,
	}

	resp, err := g.tpm.DeleteSRK(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "DeleteSRK", Err: err}
	}

	result := &SRKDeleteResult{
		Success: resp.Status != nil && resp.Status.Success,
		Message: "",
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via gRPC.
func (g *GRPCAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	req := &pb.SealRequest{
		Cn:             opts.CN,
		Data:           opts.Data,
		Password:       opts.Password,
		ParentPassword: opts.ParentPassword,
	}

	resp, err := g.tpm.Seal(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Seal", Err: err}
	}

	result := &SealResult{
		Success: resp.Status != nil && resp.Status.Success,
		Message: "",
	}
	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// Unseal unseals data from the TPM via gRPC.
func (g *GRPCAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	req := &pb.UnsealRequest{
		Cn:             opts.CN,
		Password:       opts.Password,
		ParentPassword: opts.ParentPassword,
	}

	resp, err := g.tpm.Unseal(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Unseal", Err: err}
	}

	return &UnsealResult{
		Success: resp.Status != nil && resp.Status.Success,
		Data:    resp.Data,
	}, nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via gRPC.
func (g *GRPCAdapter) EventLog(ctx context.Context, path string) (*EventLogResult, error) {
	req := &pb.GetEventLogRequest{
		Format: "json",
	}

	resp, err := g.tpm.GetEventLog(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetEventLog", Err: err}
	}

	// The response contains raw event log data, not parsed events
	result := &EventLogResult{
		Events: make([]EventLogEntry, 0),
	}

	// If we have event log data, we could parse it here
	// For now, just return the raw data wrapped in a single entry
	if len(resp.EventLog) > 0 {
		result.Events = append(result.Events, EventLogEntry{
			EventData: resp.EventLog,
		})
	}

	return result, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// formatTPMVersion formats TPM version enum to string.
func formatTPMVersion(version pb.TPMVersion) string {
	switch version {
	case pb.TPMVersion_TPM_VERSION_1_2:
		return "1.2"
	case pb.TPMVersion_TPM_VERSION_2_0:
		return "2.0"
	default:
		return "Unknown"
	}
}

// formatPCRBank formats PCR bank enum to string.
func formatPCRBank(bank pb.PCRBank) string {
	switch bank {
	case pb.PCRBank_PCR_BANK_SHA1:
		return "SHA-1"
	case pb.PCRBank_PCR_BANK_SHA256:
		return "SHA-256"
	case pb.PCRBank_PCR_BANK_SHA384:
		return "SHA-384"
	case pb.PCRBank_PCR_BANK_SHA512:
		return "SHA-512"
	case pb.PCRBank_PCR_BANK_SM3_256:
		return "SM3-256"
	default:
		return "Unknown"
	}
}

// parseKeyAlgorithm converts a string algorithm name to the proto enum value.
func parseKeyAlgorithm(algorithm string) (pb.KeyAlgorithm, error) {
	switch algorithm {
	case "RSA-2048", "RSA2048", "rsa":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, nil
	case "RSA-3072", "RSA3072":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_3072, nil
	case "RSA-4096", "RSA4096":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_4096, nil
	case "ECDSA-P256", "ECDSAP256", "P256", "ecdsa":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, nil
	case "ECDSA-P384", "ECDSAP384", "P384":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, nil
	case "ECDSA-P521", "ECDSAP521", "P521":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521, nil
	default:
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, nil
	}
}

// formatKeyAlgorithm converts a proto enum value to a human-readable string.
func formatKeyAlgorithm(alg pb.KeyAlgorithm) string {
	switch alg {
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:
		return "RSA-2048"
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:
		return "RSA-3072"
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:
		return "RSA-4096"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:
		return "ECDSA-P256"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:
		return "ECDSA-P384"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:
		return "ECDSA-P521"
	default:
		return "Unknown"
	}
}

// Ensure GRPCAdapter implements TPMCommands interface.
var _ TPMCommands = (*GRPCAdapter)(nil)
