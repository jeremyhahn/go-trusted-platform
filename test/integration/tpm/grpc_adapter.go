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
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements TPMCommands using the TPM SDK client over gRPC.
type GRPCAdapter struct {
	conn   *grpc.ClientConn
	client *tpmsvc.Client
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
	endpoint, err := helpers.RequireEndpoint(EnvPlatformGRPCEndpoint)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrConnectionFailed{Protocol: "gRPC", Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.client = tpmsvc.NewClientFromGRPC(pb.NewTPMServiceClient(conn))

	// Verify connectivity by getting TPM info
	if _, err := g.client.InfoDomain(ctx); err != nil {
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

// Info retrieves TPM information via the SDK client over gRPC.
func (g *GRPCAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := g.client.InfoDomain(ctx)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Info", Err: err}
	}

	return infoResultFromResponse(resp), nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via the SDK client over gRPC.
func (g *GRPCAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	resp, err := g.client.ProvisionDomain(ctx, provisionRequestFromOptions(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Provision", Err: err}
	}

	return provisionResultFromResponse(resp), nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via the SDK client over gRPC.
func (g *GRPCAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	resp, err := g.client.ClearDomain(ctx, opts.OwnerPassword, opts.Confirm)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Clear", Err: err}
	}

	return clearResultFromResponse(resp), nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via the SDK client over gRPC.
func (g *GRPCAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	resp, err := g.client.CreateEKDomain(ctx, keyAlgorithmFromString(opts.Algorithm), opts.Persistent)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "CreateEK", Err: err}
	}

	return ekCreateResultFromResponse(resp, opts.Algorithm), nil
}

// EKInfo retrieves EK information via the SDK client over gRPC.
func (g *GRPCAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	resp, err := g.client.GetEKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, handle)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetEK", Err: err}
	}

	return ekInfoResultFromResponse(resp), nil
}

// EKCertificate retrieves the EK certificate via the SDK client over gRPC.
func (g *GRPCAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	resp, err := g.client.GetEKCertificateDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, 0)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetEKCertificate", Err: err}
	}

	return ekCertificateResultFromResponse(resp), nil
}

// EKDelete deletes the EK via the SDK client over gRPC.
func (g *GRPCAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	resp, err := g.client.DeleteEKDomain(ctx, handle, tpmsvc.KeyAlgorithmUnspecified, password)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "DeleteEK", Err: err}
	}

	success, message := statusFields(deleteKeyStatus(resp))
	return &EKDeleteResult{Success: success, Message: message}, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via the SDK client over gRPC.
func (g *GRPCAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	resp, err := g.client.CreateSRKDomain(ctx, keyAlgorithmFromString(opts.Algorithm),
		opts.Persistent, opts.Parent, opts.ParentPassword)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "CreateSRK", Err: err}
	}

	return srkCreateResultFromResponse(resp, opts.Algorithm), nil
}

// SRKInfo retrieves SRK information via the SDK client over gRPC.
func (g *GRPCAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	resp, err := g.client.GetSRKDomain(ctx, tpmsvc.KeyAlgorithmUnspecified, handle)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetSRK", Err: err}
	}

	return srkInfoResultFromResponse(resp), nil
}

// SRKDelete deletes the SRK via the SDK client over gRPC.
func (g *GRPCAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	resp, err := g.client.DeleteSRKDomain(ctx, handle, tpmsvc.KeyAlgorithmUnspecified, password)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "DeleteSRK", Err: err}
	}

	success, message := statusFields(deleteKeyStatus(resp))
	return &SRKDeleteResult{Success: success, Message: message}, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via the SDK client over gRPC.
func (g *GRPCAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	resp, err := g.client.SealDomain(ctx, sealRequestFromOptions(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Seal", Err: err}
	}

	return sealResultFromResponse(resp), nil
}

// Unseal unseals data from the TPM via the SDK client over gRPC.
func (g *GRPCAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	resp, err := g.client.UnsealDomain(ctx, unsealRequestFromOptions(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "Unseal", Err: err}
	}

	return unsealResultFromResponse(resp), nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via the SDK client over gRPC.
func (g *GRPCAdapter) EventLog(ctx context.Context) (*EventLogResult, error) {
	resp, err := g.client.GetEventLogDomain(ctx, "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetEventLog", Err: err}
	}

	return eventLogResultFromResponse(resp), nil
}

// =============================================================================
// Shared SDK Domain Mapping Helpers
// =============================================================================

// infoResultFromResponse converts the SDK domain InfoResponse to an InfoResult.
func infoResultFromResponse(resp *tpmsvc.InfoResponse) *InfoResult {
	if resp == nil {
		return nil
	}

	result := &InfoResult{
		Version:      formatTPMVersion(resp.Version),
		IsSimulator:  resp.IsSimulator,
		FIPSMode:     resp.FIPSMode,
		MaxNVRAMSize: resp.MaxNVRAMSize,
	}

	if resp.Manufacturer != nil {
		result.Manufacturer = &ManufacturerInfo{
			Name:            resp.Manufacturer.Name,
			ID:              resp.Manufacturer.ID,
			Model:           resp.Manufacturer.Model,
			FirmwareVersion: resp.Manufacturer.FirmwareVersion,
		}
	}

	for _, bank := range resp.PCRBanks {
		result.PCRBanks = append(result.PCRBanks, formatPCRBank(bank))
	}

	return result
}

// provisionRequestFromOptions converts ProvisionOptions to a SDK ProvisionRequest.
func provisionRequestFromOptions(opts ProvisionOptions) *tpmsvc.ProvisionRequest {
	return &tpmsvc.ProvisionRequest{
		CreateEK:            opts.CreateEK,
		CreateSRK:           opts.CreateSRK,
		CreateAK:            opts.CreateAK,
		OwnerPassword:       opts.OwnerPassword,
		EndorsementPassword: opts.EndorsementPassword,
	}
}

// provisionResultFromResponse converts a SDK ProvisionResponse to a ProvisionResult.
func provisionResultFromResponse(resp *tpmsvc.ProvisionResponse) *ProvisionResult {
	result := &ProvisionResult{}
	if resp == nil {
		return result
	}

	result.Success, result.Message = statusFields(resp.Status)
	result.EKCreated = len(resp.EKPublic) > 0
	result.SRKCreated = len(resp.SRKPublic) > 0
	result.AKCreated = len(resp.AKPublic) > 0

	return result
}

// clearResultFromResponse converts a SDK ClearResponse to a ClearResult.
func clearResultFromResponse(resp *tpmsvc.ClearResponse) *ClearResult {
	result := &ClearResult{}
	if resp != nil {
		result.Success, result.Message = statusFields(resp.Status)
	}
	return result
}

// ekCreateResultFromResponse converts a SDK CreateKeyResponse to an EKCreateResult.
func ekCreateResultFromResponse(resp *tpmsvc.CreateKeyResponse, algorithm string) *EKCreateResult {
	result := &EKCreateResult{
		Algorithm: algorithm,
		CreatedAt: time.Now(),
	}
	if resp != nil {
		result.Success, _ = statusFields(resp.Status)
		result.Handle = resp.Handle
		result.PublicKey = resp.PublicKey
	}
	return result
}

// srkCreateResultFromResponse converts a SDK CreateKeyResponse to an SRKCreateResult.
func srkCreateResultFromResponse(resp *tpmsvc.CreateKeyResponse, algorithm string) *SRKCreateResult {
	result := &SRKCreateResult{
		Algorithm: algorithm,
		CreatedAt: time.Now(),
	}
	if resp != nil {
		result.Success, _ = statusFields(resp.Status)
		result.Handle = resp.Handle
		result.PublicKey = resp.PublicKey
	}
	return result
}

// ekInfoResultFromResponse converts a SDK KeyInfoResponse to an EKInfoResult.
func ekInfoResultFromResponse(resp *tpmsvc.KeyInfoResponse) *EKInfoResult {
	result := &EKInfoResult{}
	if resp != nil {
		result.Handle = resp.Handle
		result.Algorithm = string(resp.Algorithm)
		result.PublicKey = resp.PublicKey
	}
	return result
}

// srkInfoResultFromResponse converts a SDK KeyInfoResponse to an SRKInfoResult.
func srkInfoResultFromResponse(resp *tpmsvc.KeyInfoResponse) *SRKInfoResult {
	result := &SRKInfoResult{}
	if resp != nil {
		result.Handle = resp.Handle
		result.Algorithm = string(resp.Algorithm)
		result.PublicKey = resp.PublicKey
	}
	return result
}

// ekCertificateResultFromResponse converts a SDK EKCertificateResponse to an EKCertificateResult.
func ekCertificateResultFromResponse(resp *tpmsvc.EKCertificateResponse) *EKCertificateResult {
	result := &EKCertificateResult{}
	if resp != nil {
		result.Format = resp.Format
		result.Certificate = resp.Certificate
	}
	return result
}

// sealRequestFromOptions converts SealOptions to a SDK SealRequest.
func sealRequestFromOptions(opts SealOptions) *tpmsvc.SealRequest {
	return &tpmsvc.SealRequest{
		CN:             opts.CN,
		Data:           opts.Data,
		Password:       opts.Password,
		ParentPassword: opts.ParentPassword,
	}
}

// unsealRequestFromOptions converts UnsealOptions to a SDK UnsealRequest.
func unsealRequestFromOptions(opts UnsealOptions) *tpmsvc.UnsealRequest {
	return &tpmsvc.UnsealRequest{
		CN:             opts.CN,
		Password:       opts.Password,
		ParentPassword: opts.ParentPassword,
	}
}

// sealResultFromResponse converts a SDK SealResponse to a SealResult.
func sealResultFromResponse(resp *tpmsvc.SealResponse) *SealResult {
	result := &SealResult{}
	if resp != nil {
		result.Success, result.Message = statusFields(resp.Status)
	}
	return result
}

// unsealResultFromResponse converts a SDK UnsealResponse to an UnsealResult.
func unsealResultFromResponse(resp *tpmsvc.UnsealResponse) *UnsealResult {
	result := &UnsealResult{}
	if resp != nil {
		result.Success, _ = statusFields(resp.Status)
		result.Data = resp.Data
	}
	return result
}

// eventLogResultFromResponse converts a SDK EventLogResponse to an EventLogResult.
func eventLogResultFromResponse(resp *tpmsvc.EventLogResponse) *EventLogResult {
	result := &EventLogResult{
		Events: make([]EventLogEntry, 0),
	}

	if resp != nil && len(resp.EventLog) > 0 {
		result.Events = append(result.Events, EventLogEntry{
			EventData: resp.EventLog,
		})
	}

	return result
}

// deleteKeyStatus extracts the status from a SDK DeleteKeyResponse.
func deleteKeyStatus(resp *tpmsvc.DeleteKeyResponse) *tpmsvc.Status {
	if resp == nil {
		return nil
	}
	return resp.Status
}

// statusFields extracts the success flag and message from a SDK Status.
func statusFields(status *tpmsvc.Status) (bool, string) {
	if status == nil {
		return false, ""
	}
	return status.Success, status.Message
}

// keyAlgorithmFromString converts a string algorithm name to the SDK domain
// KeyAlgorithm, preserving the legacy lowercase shorthand values and the
// RSA-2048 default of the previous raw proto adapters.
func keyAlgorithmFromString(algorithm string) tpmsvc.KeyAlgorithm {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "rsa":
		return tpmsvc.KeyAlgorithmRSA2048
	case "ecdsa":
		return tpmsvc.KeyAlgorithmECDSAP256
	}

	if alg, ok := tpmsvc.ParseKeyAlgorithm(algorithm); ok {
		return alg
	}
	return tpmsvc.KeyAlgorithmRSA2048
}

// formatTPMVersion formats a SDK domain TPM version to its display string.
func formatTPMVersion(version tpmsvc.TPMVersion) string {
	switch version {
	case tpmsvc.TPMVersion12:
		return "1.2"
	case tpmsvc.TPMVersion20:
		return "2.0"
	default:
		return "Unknown"
	}
}

// formatPCRBank formats a SDK domain PCR bank to its display string.
func formatPCRBank(bank tpmsvc.PCRBank) string {
	switch bank {
	case tpmsvc.PCRBankSHA1:
		return "SHA-1"
	case tpmsvc.PCRBankSHA256:
		return "SHA-256"
	case tpmsvc.PCRBankSHA384:
		return "SHA-384"
	case tpmsvc.PCRBankSHA512:
		return "SHA-512"
	case tpmsvc.PCRBankSM3256:
		return "SM3-256"
	default:
		return "Unknown"
	}
}

// Ensure GRPCAdapter implements TPMCommands interface.
var _ TPMCommands = (*GRPCAdapter)(nil)
