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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"
	"sync"

	tpmgo "github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	// TPM types are sourced from go-quicbaas's xkms sub-package
	// rather than go-xkms directly. The xkms sub-package
	// (sdk/go/xkms) re-exports the upstream go-xkms SDK surface
	// — TrustedPlatformModule, KeyAttributes, SealOptions,
	// SealedData, NewPassword, etc. — so the platform has one
	// curated dependency for cryptographic primitives. The
	// sub-package boundary keeps xkms's TPM types from
	// colliding with QuicBaaS's own type aliases of the same
	// name (UnsealRequest, KeyInfo, PIVSignRequest, …).
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmsrk"
)

// TPMGRPCService implements the gRPC TPMService interface.
// It wraps the go-xkms TrustedPlatformModule interface to provide gRPC access to TPM operations.
type TPMGRPCService struct {
	platformv1.UnimplementedTPMServiceServer
	tpm    quicbaassdk.TrustedPlatformModule
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
func (s *TPMGRPCService) SetTPM2Service(tpm quicbaassdk.TrustedPlatformModule) {
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
// consume the full report from resp.Properties["info"] verbatim AND
// the structured fields populated below (manufacturer, capabilities,
// max_nvram_size). The text dump remains available for clients that
// want the verbatim tpm2-tools-style report; the proto fields are
// the canonical machine-readable surface every dashboard / SDK
// caller should use.
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
		Version:    platformv1.TPMVersion_TPM_VERSION_2_0,
		Properties: tpmsrk.InfoProperties(tpm),
	}
	resp.Properties["info"] = info

	if cfg := tpm.Config(); cfg != nil {
		resp.IsSimulator = cfg.UseSimulator
	}

	// Populate structured fields from the typed xkms.FixedProperties
	// view of TPM2_CAP_TPM_PROPERTIES. This is the production wire
	// surface — dashboards must not parse the free-form text blob
	// when these fields are available. We fail soft on the
	// FixedProperties read because some TPMs (e.g. early-rev simulators)
	// can refuse a few specific properties; the response still ships
	// the text fallback so consumers degrade gracefully.
	if props, propsErr := tpm.FixedProperties(); propsErr != nil {
		s.logger.Slog().Warn("TPM FixedProperties read failed; proto fields will be empty",
			slog.String("error", propsErr.Error()))
	} else if props != nil {
		resp.Manufacturer = &platformv1.TPMManufacturer{
			Name:            props.Manufacturer,
			Model:           props.Model,
			FirmwareVersion: fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor),
		}
		resp.MaxNvramSize = props.NVBufferMax
		resp.FipsMode = props.Fips1402

		// Surface high-signal capability flags as structured
		// TPMCapability rows. Each entry's `value` field is the
		// numeric source so dashboards that want to render
		// "8 / 64" style fractions don't have to round-trip
		// the text blob.
		caps := []*platformv1.TPMCapability{
			{Name: "lockoutCounter", Supported: props.LockoutCounter > 0,
				Value: fmt.Sprintf("%d", props.LockoutCounter)},
			{Name: "lockoutInterval", Supported: true,
				Value: fmt.Sprintf("%d", props.LockoutInterval)},
			{Name: "lockoutRecovery", Supported: true,
				Value: fmt.Sprintf("%d", props.LockoutRecovery)},
			{Name: "maxAuthFail", Supported: true,
				Value: fmt.Sprintf("%d", props.MaxAuthFail)},
			{Name: "nvIndexesDefined", Supported: props.NVIndexesDefined > 0,
				Value: fmt.Sprintf("%d", props.NVIndexesDefined)},
			{Name: "nvIndexesMax", Supported: true,
				Value: fmt.Sprintf("%d", props.NVIndexesMax)},
			{Name: "nvBufferMax", Supported: true,
				Value: fmt.Sprintf("%d", props.NVBufferMax)},
			{Name: "persistentLoaded", Supported: props.PersistentLoaded > 0,
				Value: fmt.Sprintf("%d", props.PersistentLoaded)},
			{Name: "persistentAvailable", Supported: true,
				Value: fmt.Sprintf("%d", props.PersistentAvail)},
			{Name: "transientAvailable", Supported: true,
				Value: fmt.Sprintf("%d", props.TransientAvail)},
			{Name: "maxRSAKeyBits", Supported: props.MaxRSAKeyBits > 0,
				Value: fmt.Sprintf("%d", props.MaxRSAKeyBits)},
			{Name: "maxECCKeyBits", Supported: props.MaxECCKeyBits > 0,
				Value: fmt.Sprintf("%d", props.MaxECCKeyBits)},
			{Name: "fips1402", Supported: props.Fips1402, Value: fmt.Sprintf("%t", props.Fips1402)},
		}
		resp.Capabilities = caps

		// Enumerate the actual NV index handles defined on the
		// device. xkms's FixedProperties walks TPM_CAP_HANDLES @
		// 0x01000000 and returns a slice of NVIndexInfo per index.
		// We translate each into the proto NVIndex shape so the
		// WebUI's NVRAM page can render an actionable table.
		if len(props.NVIndexes) > 0 {
			indexes := make([]*platformv1.NVIndex, 0, len(props.NVIndexes))
			for _, ix := range props.NVIndexes {
				indexes = append(indexes, &platformv1.NVIndex{
					Handle:    uint32(ix.Handle),
					Type:      ix.Type,
					Size:      uint32(ix.Size),
					AuthRead:  ix.AuthRead,
					AuthWrite: ix.AuthWrite,
				})
			}
			resp.NvIndexes = indexes
		}
	}

	s.logger.Debug("TPM Info request completed",
		slog.Bool("manufacturer_populated", resp.Manufacturer != nil),
		slog.Uint64("max_nvram_size", uint64(resp.MaxNvramSize)),
		slog.Int("capability_count", len(resp.Capabilities)))
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
	var ownerPwd quicbaassdk.Password
	if req.GetOwnerPassword() != "" {
		held, err := quicbaassdk.NewPasswordFromString(req.GetOwnerPassword())
		if err != nil {
			s.logger.Slog().Error("TPM Provision failed", slog.String("error", err.Error()))
			return nil, s.mapError(err)
		}
		ownerPwd = held
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

// GetSRK retrieves a Storage Root Key. The TCG-prescribed
// inventory has TWO SRKs: the Storage hierarchy SSRK at
// 0x81000001 and the Platform hierarchy PlatformSRK at 0x81000002.
// req.Handle selects which one to return:
//
//   - 0 (unset) or 0x81000001: SSRK (default for backwards compat)
//   - 0x81000002: PlatformSRK
//
// Anything else returns codes.NotFound. The dashboard's TPM Keys
// page issues two GetSRK calls (one for each handle) so it can
// render the full 5-handle persistent-key inventory; the previous
// hardcoded SSRK return left PlatformSRK invisible to every
// SDK consumer.
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

	s.logger.Debug("TPM GetSRK request received",
		slog.Uint64("requested_handle", uint64(req.GetHandle())))

	srkAttrs, err := tpmsrk.Resolve(tpm, req.GetHandle())
	if err != nil {
		if tpmsrk.IsUnknownHandle(err) {
			return nil, status.Errorf(codes.NotFound, "GetSRK: %s", err.Error())
		}
		s.logger.Slog().Error("Failed to get SRK attributes",
			slog.Uint64("requested_handle", uint64(req.GetHandle())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

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

	s.logger.Debug("TPM Seal request received",
		slog.String("cn", req.GetCn()),
		slog.Int("pcr_count", len(req.GetPcrIndices())),
		slog.String("pcr_bank", req.GetPcrBank().String()))

	opts, err := buildSealOptions(tpm, req.GetCn(), req.GetPassword(), req.GetPcrIndices(), req.GetPcrBank())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "build seal options: "+err.Error())
	}

	sealed, err := tpm.Seal(ctx, req.GetData(), opts)
	if err != nil {
		s.logger.Slog().Error("TPM Seal failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Seal completed", slog.String("key_id", sealed.KeyID))
	// TPM seal doesn't produce a single Ciphertext blob — it
	// produces TPM2B_PUBLIC + TPM2B_PRIVATE. Concatenate them with
	// a length prefix so the client can round-trip through Unseal
	// (or simply hand the SealedData identifier — keyed by CN — to
	// the unseal call).
	payload := encodeSealedData(sealed)
	// Status is what the SDK's SealResponse carries and what
	// `platformctl tpm seal` judges the call by: a response without one
	// reads as "unknown error" after a seal that succeeded.
	return &platformv1.SealResponse{
		Status:     &platformv1.Status{Success: true, Message: "sealed " + sealed.KeyID},
		SealedData: payload,
	}, nil
}

// buildSealOptions translates the proto request fields into xkms's
// SealOptions. Operator-initiated seals (the WebUI Seal page,
// `platformctl tpm seal …`) parent the sealed object on the
// **Storage SRK** at 0x81000001 — a plain owner-hierarchy SRK
// without PCR-binding on the parent itself. The PlatformSRK at
// 0x81000002 is reserved for platform-policy-bound sealing (vTPM
// bundles, barrier strategies) where the parent's auth derives
// from the live PlatformPolicyDigest; using PSRK as the parent
// for ad-hoc seals fails with TPM_RC_AUTH_FAIL whenever a measured
// PCR (kernel/initrd at PCR 9, IMA at 10, etc.) has drifted since
// provisioning. PCR-binding the *sealed object* (via TPMPolicy
// below) still works and is what an operator wants when they tick
// "seal to PCRs 7,9" in the UI.
//
// When everything is empty we still go through the SSRK path so
// fresh-from-the-WebUI seal calls succeed without the operator
// having to provide a CN.
func buildSealOptions(tpm quicbaassdk.TrustedPlatformModule, cn, password string, pcrIndices []uint32, bank platformv1.PCRBank) (*quicbaassdk.SealOptions, error) {
	ssrkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		return nil, &WrappedError{Msg: "read SSRK attributes", Err: err}
	}

	if cn == "" {
		cn = "platform-sealing-key"
	}
	keyAttrs := &quicbaassdk.KeyAttributes{
		CN:     cn,
		Parent: ssrkAttrs,
	}
	if password != "" {
		held, err := quicbaassdk.NewPassword([]byte(password))
		if err != nil {
			return nil, &WrappedError{Msg: "hold the sealing password", Err: err}
		}
		keyAttrs.Password = held
	}
	opts := &quicbaassdk.SealOptions{
		KeyAttributes: keyAttrs,
	}

	if len(pcrIndices) > 0 {
		hashAlg := pcrBankToTPMAlg(bank)
		pcrUints := make([]uint, len(pcrIndices))
		for i, p := range pcrIndices {
			pcrUints[i] = uint(p)
		}
		opts.TPMPolicy = &quicbaassdk.TPMSealPolicy{
			PCRSelection: tpmgo.TPMLPCRSelection{
				PCRSelections: []tpmgo.TPMSPCRSelection{
					{
						Hash:      hashAlg,
						PCRSelect: tpmgo.PCClientCompatible.PCRs(pcrUints...),
					},
				},
			},
			HashAlg: hashAlg,
		}
		if password != "" {
			held, err := quicbaassdk.NewPassword([]byte(password))
			if err != nil {
				return nil, &WrappedError{Msg: "hold the sealing policy password", Err: err}
			}
			opts.Password = held
		}
	}

	return opts, nil
}

// pcrBankToTPMAlg translates the proto PCRBank enum into the go-tpm
// TPMIAlgHash that xkms expects. Defaults to SHA-256, which is the
// canonical TPM 2.0 bank present on every device the platform
// supports.
func pcrBankToTPMAlg(bank platformv1.PCRBank) tpmgo.TPMAlgID {
	switch bank {
	case platformv1.PCRBank_PCR_BANK_SHA1:
		return tpmgo.TPMAlgSHA1
	case platformv1.PCRBank_PCR_BANK_SHA384:
		return tpmgo.TPMAlgSHA384
	case platformv1.PCRBank_PCR_BANK_SHA512:
		return tpmgo.TPMAlgSHA512
	default:
		return tpmgo.TPMAlgSHA256
	}
}

// encodeSealedData serializes the TPM2B_PUBLIC + TPM2B_PRIVATE pair
// into a length-prefixed byte stream that the SDK can round-trip
// back to the server during Unseal. Layout:
//
//	[4 bytes BE pubLen][pubBytes][4 bytes BE privLen][privBytes][cn]
//
// This keeps the wire format self-describing without needing a
// separate proto message for sealed-blob shape.
func encodeSealedData(s *quicbaassdk.SealedData) []byte {
	if s == nil {
		return nil
	}
	pub := s.TPMPublic
	priv := s.TPMPrivate
	cn := []byte(s.KeyID)
	out := make([]byte, 0, 8+len(pub)+len(priv)+len(cn))
	out = appendU32BE(out, uint32(len(pub)))
	out = append(out, pub...)
	out = appendU32BE(out, uint32(len(priv)))
	out = append(out, priv...)
	out = append(out, cn...)
	return out
}

func appendU32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// buildUnsealOptions mirrors buildSealOptions but returns the
// UnsealOptions shape xkms expects. Like seal, operator-initiated
// unseal goes through the Storage SRK at 0x81000001 — the same
// parent the sealed object was created under. PCR policy isn't
// needed at unseal time because the sealed object's policy digest
// already encodes the PCR binding.
func buildUnsealOptions(tpm quicbaassdk.TrustedPlatformModule, cn, password string) (*quicbaassdk.UnsealOptions, error) {
	ssrkAttrs, err := tpm.SSRKAttributes()
	if err != nil {
		return nil, &WrappedError{Msg: "read SSRK attributes", Err: err}
	}
	keyAttrs := &quicbaassdk.KeyAttributes{
		CN:     cn,
		Parent: ssrkAttrs,
	}
	if password != "" {
		held, err := quicbaassdk.NewPassword([]byte(password))
		if err != nil {
			return nil, &WrappedError{Msg: "hold the unsealing password", Err: err}
		}
		keyAttrs.Password = held
	}
	opts := &quicbaassdk.UnsealOptions{
		KeyAttributes: keyAttrs,
	}
	if password != "" {
		held, err := quicbaassdk.NewPassword([]byte(password))
		if err != nil {
			return nil, &WrappedError{Msg: "hold the unsealing password", Err: err}
		}
		opts.Password = held
	}
	return opts, nil
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

	cn := req.GetCn()
	if cn == "" {
		return nil, status.Error(codes.InvalidArgument, "common name (cn) is required")
	}

	s.logger.Debug("TPM Unseal request received",
		slog.String("cn", cn),
		slog.Int("pcr_count", len(req.GetPcrIndices())))

	sealed := &quicbaassdk.SealedData{
		Backend: quicbaassdk.BackendTypeTPM2,
		KeyID:   cn,
	}

	unsealOpts, err := buildUnsealOptions(tpm, cn, req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "build unseal options: "+err.Error())
	}

	data, err := tpm.Unseal(ctx, sealed, unsealOpts)
	if err != nil {
		s.logger.Slog().Error("TPM Unseal failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Unseal completed", slog.Int("data_bytes", len(data)))
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

// VerifyQuote validates a TPM 2.0 quote produced by this platform's
// IAK (or by a verifier-supplied AK public key). Verification covers:
//
//  1. The TPMS_ATTEST blob is well-formed and carries the canonical
//     TPM_GENERATED_VALUE magic (0xFF544347, "\xffTCG").
//  2. The structure is a quote (TPMSTAttestQuote, 0x8018) — not a
//     certify, NV-certify, or session-audit attest.
//  3. The ExtraData (qualifying data) field exactly matches the
//     verifier-supplied nonce — anti-replay.
//  4. The signature over the raw Quoted bytes validates against the
//     attestation key's public half. RSASSA-PKCS1v15, RSA-PSS, and
//     ECDSA are supported, with the digest algorithm taken from the
//     IAK's KeyAttributes (typically SHA-256).
//
// AK public key resolution order:
//   - If req.AkPublic is non-empty, parse it as PKIX DER and use it
//     verbatim. This lets a remote verifier validate a quote against
//     a known-good AK certificate without needing live TPM access.
//   - Otherwise fall back to the platform's own IAK at the
//     persistent handle configured in the platform's TPM section.
//
// PCR digest comparison against expected_pcrs is intentionally left
// to the caller for now — the request shape conveys expected
// values but PCR replay verification (recompute digest from
// expected_pcrs and compare with TPMSQuoteInfo.PCRDigest) will be
// added when the WebUI surfaces a "compare to golden" panel.
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

	s.logger.Debug("TPM VerifyQuote request received",
		slog.Int("quote_len", len(req.GetQuote())),
		slog.Int("sig_len", len(req.GetSignature())),
		slog.Int("nonce_len", len(req.GetNonce())))

	if len(req.GetQuote()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "quote is required")
	}
	if len(req.GetSignature()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature is required")
	}

	// Resolve the AK public key + signing/hash algorithms.
	pubKey, hashAlg, sigAlgo, keyAlgo, err := s.resolveVerifyKeyMaterial(req.GetAkPublic())
	if err != nil {
		s.logger.Slog().Error("Failed to resolve AK public key", slog.String("error", err.Error()))
		return &platformv1.VerifyQuoteResponse{
			Verified: false,
			Message:  "ak_public_resolution_failed: " + err.Error(),
		}, nil
	}

	// Decode the TPMS_ATTEST envelope and check magic / type.
	attest, err := tpmgo.Unmarshal[tpmgo.TPMSAttest](req.GetQuote())
	if err != nil {
		return &platformv1.VerifyQuoteResponse{
			Verified: false,
			Message:  "tpms_attest_unmarshal_failed: " + err.Error(),
		}, nil
	}
	if attest.Magic != tpmgo.TPMGeneratedValue {
		return &platformv1.VerifyQuoteResponse{
			Verified: false,
			Message:  fmt.Sprintf("invalid TPM_GENERATED magic: got 0x%x want 0x%x", uint32(attest.Magic), uint32(tpmgo.TPMGeneratedValue)),
		}, nil
	}
	if attest.Type != tpmgo.TPMSTAttestQuote {
		return &platformv1.VerifyQuoteResponse{
			Verified: false,
			Message:  fmt.Sprintf("attest type 0x%x is not a quote (0x%x)", uint16(attest.Type), uint16(tpmgo.TPMSTAttestQuote)),
		}, nil
	}

	// Anti-replay: ExtraData must equal the supplied nonce.
	if len(req.GetNonce()) > 0 {
		if !bytes.Equal(attest.ExtraData.Buffer, req.GetNonce()) {
			return &platformv1.VerifyQuoteResponse{
				Verified: false,
				Message: fmt.Sprintf("nonce mismatch: quote carries %d bytes of ExtraData, request supplied %d bytes",
					len(attest.ExtraData.Buffer), len(req.GetNonce())),
			}, nil
		}
	}

	// Verify the signature over the raw Quoted bytes.
	if err := s.verifyQuoteSignature(pubKey, hashAlg, sigAlgo, keyAlgo, req.GetQuote(), req.GetSignature()); err != nil {
		s.logger.Slog().Warn("TPM quote signature verification failed", slog.String("error", err.Error()))
		return &platformv1.VerifyQuoteResponse{
			Verified: false,
			Message:  "signature_verification_failed: " + err.Error(),
		}, nil
	}

	s.logger.Debug("TPM VerifyQuote succeeded")
	return &platformv1.VerifyQuoteResponse{
		Verified: true,
		Message:  "quote verified: magic ok, type=quote, nonce matches, signature valid",
	}, nil
}

// resolveVerifyKeyMaterial picks the AK public key + signing
// algorithms used to verify the quote. Caller-supplied AkPublic
// (PKIX DER) wins; otherwise we fall back to the IAK provisioned on
// this platform.
func (s *TPMGRPCService) resolveVerifyKeyMaterial(akPublic []byte) (crypto.PublicKey, crypto.Hash, x509.SignatureAlgorithm, x509.PublicKeyAlgorithm, error) {
	if len(akPublic) > 0 {
		pub, err := x509.ParsePKIXPublicKey(akPublic)
		if err != nil {
			return nil, 0, 0, 0, &WrappedError{Msg: "parse PKIX ak_public", Err: err}
		}
		// Without ak attrs from the caller, infer reasonable defaults:
		// SHA-256 is the canonical hash for TPM 2.0 quotes, RSASSA for
		// RSA keys, ECDSA for EC keys. Callers that need RSA-PSS need
		// to supply the IAK side-channel; this branch is primarily for
		// remote verifiers that accept the platform's signing
		// conventions.
		switch pub.(type) {
		case *rsa.PublicKey:
			return pub, crypto.SHA256, x509.SHA256WithRSA, x509.RSA, nil
		case *ecdsa.PublicKey:
			return pub, crypto.SHA256, x509.ECDSAWithSHA256, x509.ECDSA, nil
		default:
			return nil, 0, 0, 0, &MessageError{Msg: fmt.Sprintf("unsupported ak_public key type: %T", pub)}
		}
	}

	pub, err := s.tpm.IAK()
	if err != nil {
		return nil, 0, 0, 0, &WrappedError{Msg: "read IAK public", Err: err}
	}
	attrs, err := s.tpm.IAKAttributes()
	if err != nil {
		return nil, 0, 0, 0, &WrappedError{Msg: "read IAK attributes", Err: err}
	}
	hashAlg := attrs.Hash
	if hashAlg == 0 {
		hashAlg = crypto.SHA256
	}
	return pub, hashAlg, attrs.SignatureAlgorithm, attrs.KeyAlgorithm, nil
}

// verifyQuoteSignature validates `signature` over `quoted` using the
// supplied public key. Algorithm dispatch follows the IAK's
// configured signing scheme. The TPM emits raw RSA signature bytes
// for both RSASSA and RSA-PSS, and ASN.1-encoded R||S for ECDSA
// (matching go-xkms's Quote() encoding).
func (s *TPMGRPCService) verifyQuoteSignature(
	pub crypto.PublicKey,
	hashAlg crypto.Hash,
	sigAlgo x509.SignatureAlgorithm,
	keyAlgo x509.PublicKeyAlgorithm,
	quoted, signature []byte,
) error {
	if !hashAlg.Available() {
		return &MessageError{Msg: fmt.Sprintf("hash algorithm %v not linked into binary", hashAlg)}
	}
	h := hashAlg.New()
	h.Write(quoted)
	digest := h.Sum(nil)

	switch keyAlgo {
	case x509.RSA:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return &MessageError{Msg: fmt.Sprintf("public key is %T, not *rsa.PublicKey", pub)}
		}
		if quicbaassdk.IsRSAPSS(sigAlgo) {
			return rsa.VerifyPSS(rsaPub, hashAlg, digest, signature, nil)
		}
		return rsa.VerifyPKCS1v15(rsaPub, hashAlg, digest, signature)

	case x509.ECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return &MessageError{Msg: fmt.Sprintf("public key is %T, not *ecdsa.PublicKey", pub)}
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &rs); err != nil {
			return &WrappedError{Msg: "decode ECDSA R||S", Err: err}
		}
		if !ecdsa.Verify(ecPub, digest, rs.R, rs.S) {
			return &MessageError{Msg: "ECDSA signature does not validate"}
		}
		return nil

	default:
		return &MessageError{Msg: fmt.Sprintf("unsupported key algorithm: %v", keyAlgo)}
	}
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

	// Parse the binary log into structured rows. xkms's
	// ParsedEventLog walks the TCG2 (and falls back to TCG1.2) wire
	// format and yields one Event per PCR extend; we convert each to
	// the proto-shaped EventLogEntry for direct consumption by the
	// WebUI / external tools without a second decode pass.
	events, err := tpm.ParsedEventLog()
	var (
		eventCount uint64
		entries    []*platformv1.EventLogEntry
	)
	if err == nil {
		eventCount = uint64(len(events))
		entries = make([]*platformv1.EventLogEntry, 0, len(events))
		for _, ev := range events {
			digests := make([]*platformv1.EventDigest, 0, len(ev.Digests))
			for _, d := range ev.Digests {
				digests = append(digests, &platformv1.EventDigest{
					AlgorithmId: d.AlgorithmId,
					Digest:      d.Digest,
				})
			}
			entries = append(entries, &platformv1.EventLogEntry{
				EventNum:    uint32(ev.EventNum),
				PcrIndex:    uint32(ev.PCRIndex),
				EventType:   ev.EventType,
				DigestCount: uint32(ev.DigestCount),
				Digests:     digests,
				EventSize:   uint32(ev.EventSize),
				EventString: ev.EventString,
			})
		}
	} else {
		s.logger.Slog().Warn("Failed to parse event log, returning raw blob only", slog.String("error", err.Error()))
	}

	s.logger.Debug("TPM GetEventLog completed",
		slog.Uint64("event_count", eventCount),
		slog.Int("raw_log_bytes", len(rawLog)))
	return &platformv1.GetEventLogResponse{
		EventLog:   rawLog,
		Format:     "tcg2", // TCG PC Client event log format
		EventCount: eventCount,
		Entries:    entries,
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

	// Convert to proto format. When the caller supplies a Bank
	// filter (anything other than UNSPECIFIED) we drop banks that
	// don't match — the WebUI's PCR Banks page passes a specific
	// bank via this field; without the filter the response carried
	// every supported bank concatenated together and the page
	// rendered SHA-1 values under a "SHA-256" label.
	bankFilter := req.GetBank()
	pcrValues := make([]*platformv1.PCRValue, 0)
	for _, bank := range pcrBanks {
		protoBank := hashAlgToProtoPCRBank(bank.Algorithm)
		if bankFilter != platformv1.PCRBank_PCR_BANK_UNSPECIFIED && protoBank != bankFilter {
			continue
		}
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

// DefineNVRAM allocates a new NV index in owner-hierarchy storage.
//
// The proto's `attributes` field is a list of TPMA_NV bit names
// (AUTHREAD, AUTHWRITE, OWNERREAD, …). Sane defaults apply when
// the operator omits the list — AuthRead+AuthWrite on an
// ordinary index, NoDA so the operation can't lock out the
// hierarchy, and TPMSU_DEFAULT name-alg (SHA-256). The owner
// hierarchy authorization is empty by default; if the platform
// has set an owner password the operator hits this through a
// future CLI flow rather than the WebUI.
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
	if req.GetIndex() == 0 {
		return nil, status.Error(codes.InvalidArgument, "index is required")
	}
	if req.GetSize() == 0 {
		return nil, status.Error(codes.InvalidArgument, "size is required")
	}

	tr := tpm.Transport()
	if tr == nil {
		return nil, status.Error(codes.Unavailable, "TPM transport not available")
	}

	s.logger.Debug("TPM DefineNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())),
		slog.Uint64("size", uint64(req.GetSize())),
		slog.Any("attributes", req.GetAttributes()))

	attrs := buildNVAttributes(req.GetAttributes())
	var nvAuth []byte
	if p := req.GetPassword(); p != "" {
		nvAuth = []byte(p)
	}
	var ownerAuth []byte
	if p := req.GetParentPassword(); p != "" {
		ownerAuth = []byte(p)
	}

	define := tpmgo.NVDefineSpace{
		AuthHandle: tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHOwner,
			Auth:   tpmgo.PasswordAuth(ownerAuth),
		},
		Auth: tpmgo.TPM2BAuth{Buffer: nvAuth},
		PublicInfo: tpmgo.New2B(tpmgo.TPMSNVPublic{
			NVIndex:    tpmgo.TPMHandle(req.GetIndex()),
			NameAlg:    tpmgo.TPMAlgSHA256,
			Attributes: attrs,
			DataSize:   uint16(req.GetSize()),
		}),
	}
	if _, err := define.Execute(tr); err != nil {
		s.logger.Slog().Error("TPM NVDefineSpace failed",
			slog.Uint64("index", uint64(req.GetIndex())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM NVDefineSpace completed", slog.Uint64("index", uint64(req.GetIndex())))
	return &platformv1.DefineNVRAMResponse{}, nil
}

// buildNVAttributes converts the proto-level attribute name list
// into a TPMANV bitfield. Unknown names are ignored — the WebUI
// hands us a curated subset (AUTHREAD/AUTHWRITE/OWNERREAD/…)
// from the operator's checkbox row, so unknown values would only
// arise from malicious input. NoDA defaults to true to prevent
// an operator from locking out the dictionary-attack hierarchy
// by experimenting with NV indices.
func buildNVAttributes(names []string) tpmgo.TPMANV {
	if len(names) == 0 {
		return tpmgo.TPMANV{
			AuthRead:  true,
			AuthWrite: true,
			NT:        tpmgo.TPMNTOrdinary,
			NoDA:      true,
		}
	}
	a := tpmgo.TPMANV{NT: tpmgo.TPMNTOrdinary, NoDA: true}
	for _, n := range names {
		switch n {
		case "AUTHREAD":
			a.AuthRead = true
		case "AUTHWRITE":
			a.AuthWrite = true
		case "OWNERREAD":
			a.OwnerRead = true
		case "OWNERWRITE":
			a.OwnerWrite = true
		case "PPREAD":
			a.PPRead = true
		case "PPWRITE":
			a.PPWrite = true
		case "WRITELOCK":
			a.WriteDefine = true
		case "READLOCK":
			a.ReadSTClear = true
		case "NO_DA":
			a.NoDA = true
		case "DA":
			a.NoDA = false
		case "WRITTEN":
			a.Written = true
		case "WRITEALL":
			a.WriteAll = true
		case "GLOBALLOCK":
			a.GlobalLock = true
		case "POLICYREAD":
			a.PolicyRead = true
		case "POLICYWRITE":
			a.PolicyWrite = true
		}
	}
	return a
}

// WriteNVRAM writes a payload to a defined NV index. Auth
// dispatch mirrors ReadNVRAM: AUTHWRITE → index-self auth,
// OWNERWRITE → owner hierarchy, PPWRITE → platform hierarchy.
// Writes are chunked at 512-byte boundaries to stay below
// TPM_PT_NV_BUFFER_MAX on every supported device (Infineon
// SLB9665 reports 7 bytes; the conservative cap matches
// xkms/EK-cert / tpm2-tools default behavior).
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
	if req.GetIndex() == 0 {
		return nil, status.Error(codes.InvalidArgument, "index is required")
	}

	tr := tpm.Transport()
	if tr == nil {
		return nil, status.Error(codes.Unavailable, "TPM transport not available")
	}

	s.logger.Debug("TPM WriteNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())),
		slog.Int("data_bytes", len(req.GetData())),
		slog.Uint64("offset", uint64(req.GetOffset())))

	nvHandle := tpmgo.TPMHandle(req.GetIndex())
	pubRsp, err := tpmgo.NVReadPublic{NVIndex: nvHandle}.Execute(tr)
	if err != nil {
		return nil, s.mapError(err)
	}
	pub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return nil, status.Error(codes.Internal, "decode NVPublic: "+err.Error())
	}

	var pwd []byte
	if p := req.GetPassword(); p != "" {
		pwd = []byte(p)
	}
	authHandle := tpmgo.AuthHandle{
		Handle: nvHandle,
		Name:   pubRsp.NVName,
		Auth:   tpmgo.PasswordAuth(pwd),
	}
	if pub.Attributes.OwnerWrite && !pub.Attributes.AuthWrite {
		authHandle = tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHOwner,
			Auth:   tpmgo.PasswordAuth(pwd),
		}
	} else if pub.Attributes.PPWrite {
		authHandle = tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHPlatform,
			Auth:   tpmgo.PasswordAuth(pwd),
		}
	}

	const maxNVChunk = 512
	data := req.GetData()
	startOffset := uint16(req.GetOffset())
	for i := 0; i < len(data); {
		end := i + maxNVChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		_, err := tpmgo.NVWrite{
			AuthHandle: authHandle,
			NVIndex: tpmgo.AuthHandle{
				Handle: nvHandle,
				Name:   pubRsp.NVName,
				Auth:   tpmgo.PasswordAuth(pwd),
			},
			Data:   tpmgo.TPM2BMaxNVBuffer{Buffer: chunk},
			Offset: startOffset + uint16(i),
		}.Execute(tr)
		if err != nil {
			s.logger.Slog().Error("TPM NVWrite chunk failed",
				slog.Uint64("index", uint64(req.GetIndex())),
				slog.Int("offset", i),
				slog.Int("chunk_size", len(chunk)),
				slog.String("error", err.Error()))
			return nil, s.mapError(err)
		}
		i = end
	}

	s.logger.Debug("TPM NVWrite completed", slog.Int("bytes", len(data)))
	return &platformv1.WriteNVRAMResponse{}, nil
}

// ReadNVRAM reads payload bytes from a defined NV index.
//
// Implementation issues TPM2_NVReadPublic to learn the index's
// hash algorithm + auth-hierarchy attributes, then issues
// TPM2_NVRead with the operator-supplied password (empty for
// AuthRead-without-password indices like the TCG-reserved EK
// certificate at 0x1c00002). Reads are chunked at the device's
// NV buffer max size when the requested size exceeds it; this
// page calls in already with size <= NVBufferMax so the chunking
// path is rare in practice.
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

	if req.GetIndex() == 0 {
		return nil, status.Error(codes.InvalidArgument, "index is required")
	}

	s.logger.Debug("TPM ReadNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())),
		slog.Uint64("size", uint64(req.GetSize())),
		slog.Uint64("offset", uint64(req.GetOffset())))

	tr := tpm.Transport()
	if tr == nil {
		return nil, status.Error(codes.Unavailable, "TPM transport not available")
	}

	nvHandle := tpmgo.TPMHandle(req.GetIndex())
	pubRsp, err := tpmgo.NVReadPublic{NVIndex: nvHandle}.Execute(tr)
	if err != nil {
		s.logger.Slog().Error("TPM NVReadPublic failed",
			slog.Uint64("index", uint64(req.GetIndex())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}
	pub, err := pubRsp.NVPublic.Contents()
	if err != nil {
		return nil, status.Error(codes.Internal, "decode NVPublic: "+err.Error())
	}
	dataSize := uint16(pub.DataSize)
	if req.GetSize() > 0 && req.GetSize() < uint32(dataSize) {
		dataSize = uint16(req.GetSize())
	}

	// Build the auth value. nil (vs empty []byte) is meaningful
	// in go-tpm: nil PasswordAuth omits the auth value from the
	// command frame; an empty []byte sends a zero-length value
	// that some TPMs reject with TPM_RC_SIZE.
	var pwd []byte
	if p := req.GetPassword(); p != "" {
		pwd = []byte(p)
	}

	// Choose the auth-handle hierarchy based on the NV public
	// attributes. AUTHREAD authorizes against the index's own
	// AuthValue; OWNERREAD/PPREAD route through the owner /
	// platform hierarchy with their respective auth values. The
	// vast majority of indices on the WebUI's path (TCG-reserved
	// EK cert at 0x1c00002, user-defined ordinary indices) are
	// AUTHREAD with empty password.
	authHandle := tpmgo.AuthHandle{
		Handle: nvHandle,
		Name:   pubRsp.NVName,
		Auth:   tpmgo.PasswordAuth(pwd),
	}
	if pub.Attributes.OwnerRead && !pub.Attributes.AuthRead {
		authHandle = tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHOwner,
			Auth:   tpmgo.PasswordAuth(pwd),
		}
	} else if pub.Attributes.PPRead {
		authHandle = tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHPlatform,
			Auth:   tpmgo.PasswordAuth(pwd),
		}
	}

	// Chunk the read. TPM_PT_NV_BUFFER_MAX varies wildly between
	// vendors (Infineon SLB9665 reports 7 in one mode, 1024 in
	// another); a conservative 512-byte cap is what xkms's own
	// EKCertificate path uses and what tpm2-tools defaults to.
	const maxNVChunk uint16 = 512
	startOffset := uint16(req.GetOffset())
	out := make([]byte, 0, dataSize)
	for offset := startOffset; offset-startOffset < dataSize; {
		remaining := dataSize - (offset - startOffset)
		chunk := remaining
		if chunk > maxNVChunk {
			chunk = maxNVChunk
		}
		readRsp, err := tpmgo.NVRead{
			AuthHandle: authHandle,
			NVIndex: tpmgo.AuthHandle{
				Handle: nvHandle,
				Name:   pubRsp.NVName,
				Auth:   tpmgo.PasswordAuth(pwd),
			},
			Size:   chunk,
			Offset: offset,
		}.Execute(tr)
		if err != nil {
			s.logger.Slog().Error("TPM NVRead chunk failed",
				slog.Uint64("index", uint64(req.GetIndex())),
				slog.Uint64("offset", uint64(offset)),
				slog.Uint64("chunk_size", uint64(chunk)),
				slog.String("error", err.Error()))
			return nil, s.mapError(err)
		}
		out = append(out, readRsp.Data.Buffer...)
		offset += chunk
	}

	s.logger.Debug("TPM NVRead completed",
		slog.Int("bytes", len(out)))
	return &platformv1.ReadNVRAMResponse{
		Data: out,
	}, nil
}

// UndefineNVRAM frees a defined NV index. Owner-hierarchy
// authorization is required; the platform tracks no separate
// owner password by default, so an empty PasswordAuth is the
// common case. Platform-hierarchy indices (NV_PT_PLATFORM_BASE
// range) require platform auth — out of scope for the operator
// UI and intentionally not exposed here.
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
	if req.GetIndex() == 0 {
		return nil, status.Error(codes.InvalidArgument, "index is required")
	}

	tr := tpm.Transport()
	if tr == nil {
		return nil, status.Error(codes.Unavailable, "TPM transport not available")
	}

	s.logger.Debug("TPM UndefineNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())))

	nvHandle := tpmgo.TPMHandle(req.GetIndex())
	pubRsp, err := tpmgo.NVReadPublic{NVIndex: nvHandle}.Execute(tr)
	if err != nil {
		return nil, s.mapError(err)
	}

	var ownerAuth []byte
	if p := req.GetParentPassword(); p != "" {
		ownerAuth = []byte(p)
	}
	if _, err := (tpmgo.NVUndefineSpace{
		AuthHandle: tpmgo.AuthHandle{
			Handle: tpmgo.TPMRHOwner,
			Auth:   tpmgo.PasswordAuth(ownerAuth),
		},
		NVIndex: tpmgo.NamedHandle{
			Handle: nvHandle,
			Name:   pubRsp.NVName,
		},
	}.Execute(tr)); err != nil {
		s.logger.Slog().Error("TPM NVUndefineSpace failed",
			slog.Uint64("index", uint64(req.GetIndex())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM NVUndefineSpace completed")
	return &platformv1.UndefineNVRAMResponse{}, nil
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

// MakeCredential wraps TPM2_MakeCredential. When both the EK certificate
// and the IAK public area are supplied the call is routed to the verifier
// path (MakeCredentialWithExternalEK); otherwise the local TPM's EK is
// used together with the supplied AK name. It is a pure transport
// pass-through to the backing TPM module.
func (s *TPMGRPCService) MakeCredential(
	ctx context.Context,
	req *platformv1.MakeCredentialRequest,
) (*platformv1.MakeCredentialResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM MakeCredential request received")

	credentialBlob, encryptedSecret, secret, err := makeCredential(
		tpm, req.GetAkName(), req.GetSecret(), req.GetEkCert(), req.GetIakPub())
	if err != nil {
		s.logger.Slog().Error("Failed to make credential", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM MakeCredential completed")
	return &platformv1.MakeCredentialResponse{
		CredentialBlob:  credentialBlob,
		EncryptedSecret: encryptedSecret,
		Secret:          secret,
	}, nil
}

// ActivateCredential wraps TPM2_ActivateCredential. It is a pure transport
// pass-through to the backing TPM module via the shared activateCredential
// delegation point.
func (s *TPMGRPCService) ActivateCredential(
	ctx context.Context,
	req *platformv1.TPMActivateCredentialRequest,
) (*platformv1.TPMActivateCredentialResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	credentialBlob := req.GetCredentialBlob()
	encryptedSecret := req.GetEncryptedSecret()
	if len(credentialBlob) == 0 {
		return nil, status.Error(codes.InvalidArgument, "credential_blob is required")
	}
	if len(encryptedSecret) == 0 {
		return nil, status.Error(codes.InvalidArgument, "encrypted_secret is required")
	}

	s.logger.Debug("TPM ActivateCredential request received")

	secret, err := activateCredential(tpm, credentialBlob, encryptedSecret)
	if err != nil {
		s.logger.Slog().Error("Failed to activate credential", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM ActivateCredential completed")
	return &platformv1.TPMActivateCredentialResponse{
		Secret: secret,
	}, nil
}

// makeCredential is the single TPM2_MakeCredential delegation point shared
// by every transport in the daemon package. When ekCertDER and iakPub are
// both present the verifier path (no local EK) is used; otherwise the call
// uses the local TPM EK with akName.
func makeCredential(
	tpm quicbaassdk.TrustedPlatformModule,
	akName, secret, ekCertDER, iakPub []byte,
) (credentialBlob, encryptedSecret, plaintextSecret []byte, err error) {

	if len(ekCertDER) > 0 && len(iakPub) > 0 {
		ekCert, parseErr := x509.ParseCertificate(ekCertDER)
		if parseErr != nil {
			return nil, nil, nil, parseErr
		}
		return tpm.MakeCredentialWithExternalEK(ekCert, iakPub, secret)
	}
	return tpm.MakeCredential(tpmgo.TPM2BName{Buffer: akName}, secret)
}

// activateCredential is the single TPM2_ActivateCredential delegation point
// shared by the TPMService and IDevID RPCs across every transport in the
// daemon package, so there is exactly one underlying TPM call.
func activateCredential(
	tpm quicbaassdk.TrustedPlatformModule,
	credentialBlob, encryptedSecret []byte,
) ([]byte, error) {
	return tpm.ActivateCredential(credentialBlob, encryptedSecret)
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
