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
	"crypto/x509"
	"log/slog"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TPMGRPCService implements the gRPC TPMService interface.
// It wraps the go-xkms TrustedPlatformModule interface to provide gRPC access to TPM operations.
type TPMGRPCService struct {
	platformv1.UnimplementedTPMServiceServer
	tpm    xkmssdk.TrustedPlatformModule
	logger *logging.Logger
	mu     sync.RWMutex
}

// NewTPMGRPCService creates a new TPMGRPCService.
func NewTPMGRPCService(logger *logging.Logger) *TPMGRPCService {
	return &TPMGRPCService{
		logger: logger,
	}
}

// SetTPM2Service sets the TPM2 service for this gRPC service.
func (s *TPMGRPCService) SetTPM2Service(tpm xkmssdk.TrustedPlatformModule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tpm = tpm
}

// Info returns TPM capabilities and information.
//
// This is a thin pass-through to the go-xkms TrustedPlatformModule.Info()
// method, which already composes a comprehensive multi-line report from
// the TPM's fixed properties (manufacturer, firmware, supported algorithms,
// session/NV/persistent slot accounting, lockout state, etc.). We do NOT
// reinvent that formatting here — the xkms library owns it. Clients
// consume the full report from resp.Properties["info"] verbatim.
//
// The only per-response fields we still populate are the ones clients
// may want to branch on without parsing the text blob: TPM version,
// simulator flag, and FIPS mode. Everything else that used to be
// duplicated into proto fields (Manufacturer, Capabilities, MaxNvramSize)
// is available inside the info string and should be read from there.
func (s *TPMGRPCService) Info(
	ctx context.Context,
	req *platformv1.TPMInfoRequest,
) (*platformv1.TPMInfoResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM Info request received")

	info, err := tpm.Info()
	if err != nil {
		s.logger.Slog().Error("TPM Info failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	resp := &platformv1.TPMInfoResponse{
		Version: platformv1.TPMVersion_TPM_VERSION_2_0,
		Properties: map[string]string{
			"info": info,
		},
	}

	if cfg := tpm.Config(); cfg != nil {
		resp.IsSimulator = cfg.UseSimulator
	}

	s.logger.Debug("TPM Info request completed")
	return resp, nil
}

// Provision initializes the TPM with required keys.
func (s *TPMGRPCService) Provision(
	ctx context.Context,
	req *platformv1.TPMProvisionRequest,
) (*platformv1.TPMProvisionResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM Provision request received")

	// Provision with owner password
	var ownerPwd xkmssdk.Password
	if req.GetOwnerPassword() != "" {
		ownerPwd = xkmssdk.NewPasswordFromString(req.GetOwnerPassword())
	}

	_, err := tpm.ProvisionOwner(ownerPwd)
	if err != nil {
		s.logger.Slog().Error("TPM Provision failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Provision completed")
	return &platformv1.TPMProvisionResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "TPM provisioned successfully",
		},
	}, nil
}

// Clear clears the TPM (requires owner authorization).
func (s *TPMGRPCService) Clear(
	ctx context.Context,
	req *platformv1.TPMClearRequest,
) (*platformv1.TPMClearResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM Clear request received")

	// Use owner password for clear operation
	var lockoutAuth []byte
	if req.GetOwnerPassword() != "" {
		lockoutAuth = []byte(req.GetOwnerPassword())
	}

	if err := tpm.Clear(lockoutAuth); err != nil {
		s.logger.Slog().Error("TPM Clear failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Clear completed")
	return &platformv1.TPMClearResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "TPM cleared successfully",
		},
	}, nil
}

// CreateEK creates an Endorsement Key.
func (s *TPMGRPCService) CreateEK(
	ctx context.Context,
	req *platformv1.CreateEKRequest,
) (*platformv1.CreateEKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM CreateEK request received")

	// Get EK attributes from config or use defaults
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		s.logger.Slog().Error("Failed to get EK attributes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	if err := tpm.CreateEK(ekAttrs); err != nil {
		s.logger.Slog().Error("TPM CreateEK failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM CreateEK completed")
	return &platformv1.CreateEKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "EK created successfully",
		},
		Handle: uint32(ekAttrs.TPMAttributes.Handle),
	}, nil
}

// GetEK retrieves the Endorsement Key public key.
func (s *TPMGRPCService) GetEK(
	ctx context.Context,
	req *platformv1.GetEKRequest,
) (*platformv1.GetEKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM GetEK request received")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		s.logger.Slog().Error("Failed to get EK attributes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM GetEK completed")
	return &platformv1.GetEKResponse{
		Handle:    uint32(ekAttrs.TPMAttributes.Handle),
		PublicKey: ekAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: keyAlgorithmToProto(ekAttrs.KeyAlgorithm),
	}, nil
}

// GetEKCertificate retrieves the EK certificate.
func (s *TPMGRPCService) GetEKCertificate(
	ctx context.Context,
	req *platformv1.GetEKCertificateRequest,
) (*platformv1.GetEKCertificateResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM GetEKCertificate request received")

	cert, err := tpm.EKCertificate()
	if err != nil {
		s.logger.Slog().Error("Failed to get EK certificate", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM GetEKCertificate completed")
	return &platformv1.GetEKCertificateResponse{
		Certificate: cert.Raw,
	}, nil
}

// ImportEKCertificate imports an EK certificate into the TPM.
func (s *TPMGRPCService) ImportEKCertificate(
	ctx context.Context,
	req *platformv1.ImportEKCertificateRequest,
) (*platformv1.ImportEKCertificateResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	if len(req.GetCertificate()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate is required")
	}

	s.logger.Debug("TPM ImportEKCertificate request received")

	// ProvisionEKCert takes hierarchyAuth and certificate bytes
	// The hierarchy auth is optional and can be nil for default
	if err := tpm.ProvisionEKCert(nil, req.GetCertificate()); err != nil {
		s.logger.Slog().Error("Failed to import EK certificate", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM ImportEKCertificate completed")
	return &platformv1.ImportEKCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "EK certificate imported successfully",
		},
	}, nil
}

// DeleteEK deletes the Endorsement Key.
func (s *TPMGRPCService) DeleteEK(
	ctx context.Context,
	req *platformv1.DeleteEKRequest,
) (*platformv1.DeleteEKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM DeleteEK request received")

	// EK is typically not deleted, but we can flush the handle
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, s.mapError(err)
	}

	tpm.Flush(ekAttrs.TPMAttributes.Handle)

	s.logger.Debug("TPM DeleteEK completed")
	return &platformv1.DeleteEKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "EK handle flushed",
		},
	}, nil
}

// CreateSRK creates a Storage Root Key.
func (s *TPMGRPCService) CreateSRK(
	ctx context.Context,
	req *platformv1.CreateSRKRequest,
) (*platformv1.CreateSRKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM CreateSRK request received")

	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		s.logger.Slog().Error("Failed to get SRK attributes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	if err := tpm.CreateSRK(srkAttrs); err != nil {
		s.logger.Slog().Error("TPM CreateSRK failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM CreateSRK completed")
	return &platformv1.CreateSRKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "SRK created successfully",
		},
		Handle: uint32(srkAttrs.TPMAttributes.Handle),
	}, nil
}

// GetSRK retrieves the Storage Root Key.
func (s *TPMGRPCService) GetSRK(
	ctx context.Context,
	req *platformv1.GetSRKRequest,
) (*platformv1.GetSRKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM GetSRK request received")

	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		s.logger.Slog().Error("Failed to get SRK attributes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM GetSRK completed")
	return &platformv1.GetSRKResponse{
		Handle:    uint32(srkAttrs.TPMAttributes.Handle),
		PublicKey: srkAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: keyAlgorithmToProto(srkAttrs.KeyAlgorithm),
	}, nil
}

// DeleteSRK deletes the Storage Root Key.
func (s *TPMGRPCService) DeleteSRK(
	ctx context.Context,
	req *platformv1.DeleteSRKRequest,
) (*platformv1.DeleteSRKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM DeleteSRK request received")

	srkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		return nil, s.mapError(err)
	}

	tpm.Flush(srkAttrs.TPMAttributes.Handle)

	s.logger.Debug("TPM DeleteSRK completed")
	return &platformv1.DeleteSRKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "SRK handle flushed",
		},
	}, nil
}

// CreateAK creates an Attestation Key (IAK).
func (s *TPMGRPCService) CreateAK(
	ctx context.Context,
	req *platformv1.CreateAKRequest,
) (*platformv1.CreateAKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM CreateAK request received")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		s.logger.Slog().Error("Failed to get EK attributes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	// CreateIAK takes EK attributes and optional qualifying data
	// The qualifying data is not provided in the proto request
	iakAttrs, err := tpm.CreateIAK(ekAttrs, nil)
	if err != nil {
		s.logger.Slog().Error("TPM CreateAK failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM CreateAK completed")
	return &platformv1.CreateAKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "AK created successfully",
		},
		Handle: uint32(iakAttrs.TPMAttributes.Handle),
	}, nil
}

// GetAK retrieves the Attestation Key.
func (s *TPMGRPCService) GetAK(
	ctx context.Context,
	req *platformv1.GetAKRequest,
) (*platformv1.GetAKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM GetAK request received")

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		s.logger.Slog().Error("Failed to get IAK attributes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	pubKey, iakErr := tpm.IAK()
	if iakErr != nil {
		return nil, s.mapError(iakErr)
	}
	if pubKey == nil {
		return nil, status.Error(codes.NotFound, "IAK not found")
	}

	s.logger.Debug("TPM GetAK completed")
	return &platformv1.GetAKResponse{
		Handle:    uint32(iakAttrs.TPMAttributes.Handle),
		PublicKey: iakAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: keyAlgorithmToProto(iakAttrs.KeyAlgorithm),
	}, nil
}

// DeleteAK deletes the Attestation Key.
func (s *TPMGRPCService) DeleteAK(
	ctx context.Context,
	req *platformv1.DeleteAKRequest,
) (*platformv1.DeleteAKResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM DeleteAK request received")

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, s.mapError(err)
	}

	tpm.Flush(iakAttrs.TPMAttributes.Handle)

	s.logger.Debug("TPM DeleteAK completed")
	return &platformv1.DeleteAKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "AK handle flushed",
		},
	}, nil
}

// Seal seals data to the TPM.
func (s *TPMGRPCService) Seal(
	ctx context.Context,
	req *platformv1.SealRequest,
) (*platformv1.SealResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	s.logger.Debug("TPM Seal request received")

	// Build seal options - for now, use nil options which uses platform defaults
	// Full PCR policy support would require additional implementation
	sealed, err := tpm.Seal(ctx, req.GetData(), nil)
	if err != nil {
		s.logger.Slog().Error("TPM Seal failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Seal completed")
	return &platformv1.SealResponse{
		SealedData: sealed.Ciphertext,
	}, nil
}

// Unseal unseals data from the TPM.
func (s *TPMGRPCService) Unseal(
	ctx context.Context,
	req *platformv1.UnsealRequest,
) (*platformv1.UnsealResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	// Unseal by common name - the sealed object must have been previously sealed
	// with a known CN
	cn := req.GetCn()
	if cn == "" {
		return nil, status.Error(codes.InvalidArgument, "common name (cn) is required")
	}

	s.logger.Debug("TPM Unseal request received", "cn", cn)

	// Build sealed data reference with the CN
	// The actual sealed data is stored in the TPM XKMS backend
	sealed := &xkmssdk.SealedData{
		KeyID: cn, // Use CN to look up the sealed object
	}

	data, err := tpm.Unseal(ctx, sealed, nil)
	if err != nil {
		s.logger.Slog().Error("TPM Unseal failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Unseal completed")
	return &platformv1.UnsealResponse{
		Data: data,
	}, nil
}

// Quote creates a TPM quote.
func (s *TPMGRPCService) Quote(
	ctx context.Context,
	req *platformv1.QuoteRequest,
) (*platformv1.QuoteResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM Quote request received")

	// Convert PCR indices from uint32 to uint
	pcrIndices := req.GetPcrIndices()
	pcrs := make([]uint, len(pcrIndices))
	for i, pcr := range pcrIndices {
		pcrs[i] = uint(pcr)
	}

	quote, err := tpm.Quote(pcrs, req.GetNonce())
	if err != nil {
		s.logger.Slog().Error("TPM Quote failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Quote completed")
	return &platformv1.QuoteResponse{
		Quote:     quote.Quoted,
		Signature: quote.Signature,
		EventLog:  quote.EventLog,
	}, nil
}

// VerifyQuote verifies a TPM quote.
func (s *TPMGRPCService) VerifyQuote(
	ctx context.Context,
	req *platformv1.VerifyQuoteRequest,
) (*platformv1.VerifyQuoteResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM VerifyQuote request received")

	// Quote verification is typically done by the verifier, not the TPM
	// This would require the AK public key and the quote data
	// For now, return unimplemented until we have the full verification API
	return nil, status.Error(codes.Unimplemented, "quote verification not yet implemented")
}

// GetEventLog retrieves the TPM event log.
func (s *TPMGRPCService) GetEventLog(
	ctx context.Context,
	req *platformv1.GetEventLogRequest,
) (*platformv1.GetEventLogResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM GetEventLog request received")

	rawLog, err := tpm.EventLog()
	if err != nil {
		s.logger.Slog().Error("Failed to get event log", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	// Try to parse the event log to get event count
	events, err := tpm.ParsedEventLog()
	var eventCount uint64
	if err == nil {
		eventCount = uint64(len(events))
	}

	s.logger.Debug("TPM GetEventLog completed")
	return &platformv1.GetEventLogResponse{
		EventLog:   rawLog,
		Format:     "tcg2", // TCG PC Client event log format
		EventCount: eventCount,
	}, nil
}

// GetPCRs retrieves PCR values.
func (s *TPMGRPCService) GetPCRs(
	ctx context.Context,
	req *platformv1.GetPCRsRequest,
) (*platformv1.GetPCRsResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM GetPCRs request received")

	// Convert PCR indices from request
	indices := req.GetIndices()
	pcrs := make([]uint, len(indices))
	for i, idx := range indices {
		pcrs[i] = uint(idx)
	}

	// If no PCRs specified, read all standard PCRs (0-23)
	if len(pcrs) == 0 {
		pcrs = make([]uint, 24)
		for i := 0; i < 24; i++ {
			pcrs[i] = uint(i)
		}
	}

	pcrBanks, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		s.logger.Slog().Error("Failed to read PCRs", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	// Convert to proto format
	pcrValues := make([]*platformv1.PCRValue, 0)
	for _, bank := range pcrBanks {
		protoBank := hashAlgToProtoPCRBank(bank.Algorithm)
		for _, pcr := range bank.PCRs {
			pcrValues = append(pcrValues, &platformv1.PCRValue{
				Index: uint32(pcr.ID),
				Bank:  protoBank,
				Value: pcr.Value,
			})
		}
	}

	s.logger.Debug("TPM GetPCRs completed")
	return &platformv1.GetPCRsResponse{
		PcrValues: pcrValues,
	}, nil
}

// DefineNVRAM defines an NVRAM index.
func (s *TPMGRPCService) DefineNVRAM(
	ctx context.Context,
	req *platformv1.DefineNVRAMRequest,
) (*platformv1.DefineNVRAMResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM DefineNVRAM request received")

	// NVRAM operations require KeyAttributes with NV index information
	// For now, return unimplemented - would need to construct proper KeyAttributes
	return nil, status.Error(codes.Unimplemented, "NVRAM define not yet fully implemented")
}

// WriteNVRAM writes data to an NVRAM index.
func (s *TPMGRPCService) WriteNVRAM(
	ctx context.Context,
	req *platformv1.WriteNVRAMRequest,
) (*platformv1.WriteNVRAMResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM WriteNVRAM request received")

	// NVRAM operations require KeyAttributes with NV index information
	return nil, status.Error(codes.Unimplemented, "NVRAM write not yet fully implemented")
}

// ReadNVRAM reads data from an NVRAM index.
func (s *TPMGRPCService) ReadNVRAM(
	ctx context.Context,
	req *platformv1.ReadNVRAMRequest,
) (*platformv1.ReadNVRAMResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM ReadNVRAM request received")

	// NVRAM operations require KeyAttributes with NV index information
	return nil, status.Error(codes.Unimplemented, "NVRAM read not yet fully implemented")
}

// UndefineNVRAM undefines an NVRAM index.
func (s *TPMGRPCService) UndefineNVRAM(
	ctx context.Context,
	req *platformv1.UndefineNVRAMRequest,
) (*platformv1.UndefineNVRAMResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM UndefineNVRAM request received")

	// NVRAM operations require KeyAttributes with NV index information
	return nil, status.Error(codes.Unimplemented, "NVRAM undefine not yet fully implemented")
}

// GetRandom returns random bytes from the TPM.
func (s *TPMGRPCService) GetRandom(
	ctx context.Context,
	req *platformv1.GetRandomRequest,
) (*platformv1.GetRandomResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	numBytes := req.GetNumBytes()
	if numBytes == 0 {
		numBytes = 32 // Default to 32 bytes
	}
	if numBytes > 1024 {
		return nil, status.Error(codes.InvalidArgument, "maximum size is 1024 bytes")
	}

	s.logger.Debug("TPM GetRandom request received", "numBytes", numBytes)

	random, err := tpm.RandomBytes(int(numBytes))
	if err != nil {
		s.logger.Slog().Error("Failed to get random bytes", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM GetRandom completed")
	return &platformv1.GetRandomResponse{
		RandomBytes: random,
	}, nil
}

// mapError converts service errors to gRPC status errors.
func (s *TPMGRPCService) mapError(err error) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Check for not found errors
	if containsAny(errMsg, "not found", "does not exist", "no such") {
		return status.Error(codes.NotFound, errMsg)
	}

	// Check for already exists errors
	if containsAny(errMsg, "already exists", "duplicate") {
		return status.Error(codes.AlreadyExists, errMsg)
	}

	// Check for invalid argument errors
	if containsAny(errMsg, "invalid", "required", "must be", "cannot be") {
		return status.Error(codes.InvalidArgument, errMsg)
	}

	// Check for permission errors
	if containsAny(errMsg, "permission", "denied", "unauthorized", "forbidden", "authorization") {
		return status.Error(codes.PermissionDenied, errMsg)
	}

	// Check for TPM-specific errors
	if containsAny(errMsg, "TPM", "tpm", "handle") {
		return status.Error(codes.FailedPrecondition, errMsg)
	}

	// Default to internal error
	return status.Error(codes.Internal, errMsg)
}

// Helper functions

func hashAlgToProtoPCRBank(alg string) platformv1.PCRBank {
	switch alg {
	case "sha1", "SHA-1", "SHA1":
		return platformv1.PCRBank_PCR_BANK_SHA1
	case "sha256", "SHA-256", "SHA256":
		return platformv1.PCRBank_PCR_BANK_SHA256
	case "sha384", "SHA-384", "SHA384":
		return platformv1.PCRBank_PCR_BANK_SHA384
	case "sha512", "SHA-512", "SHA512":
		return platformv1.PCRBank_PCR_BANK_SHA512
	case "sm3", "SM3-256":
		return platformv1.PCRBank_PCR_BANK_SM3_256
	default:
		return platformv1.PCRBank_PCR_BANK_SHA256
	}
}

// keyAlgorithmToProto converts x509.PublicKeyAlgorithm to platformv1.KeyAlgorithm.
func keyAlgorithmToProto(alg x509.PublicKeyAlgorithm) platformv1.KeyAlgorithm {
	switch alg {
	case x509.RSA:
		// Default to RSA-2048 since we don't have key size info here
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	case x509.ECDSA:
		// Default to P-256 since we don't have curve info here
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case x509.Ed25519:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}
