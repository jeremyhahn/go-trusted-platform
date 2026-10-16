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
	"crypto/x509"
	"fmt"
	"log/slog"
	"math"
	"sync"

	tpmgo "github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	attestvm "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmattrs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmcertify"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmpcr"
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

	srkAttrs, err := resolveTPMSRK(tpm, req.GetHandle())
	if err != nil {
		s.logger.Slog().Error("Failed to get SRK attributes",
			slog.Uint64("requested_handle", uint64(req.GetHandle())),
			slog.String("error", err.Error()))
		return nil, err
	}

	return &platformv1.GetSRKResponse{
		Handle:    uint32(srkAttrs.TPMAttributes.Handle),
		PublicKey: srkAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: keyAlgorithmToProto(srkAttrs.KeyAlgorithm),
	}, nil
}

// resolveTPMSRK resolves the SRK a caller names by handle (0 is the
// platform SSRK). A handle that names no SRK is NotFound on every
// transport; any other failure takes its class from mapTPMError.
func resolveTPMSRK(tpm quicbaassdk.TrustedPlatformModule, handle uint32) (*quicbaassdk.KeyAttributes, error) {
	srkAttrs, err := tpmsrk.Resolve(tpm, handle)
	if err == nil {
		return srkAttrs, nil
	}
	if tpmsrk.IsUnknownHandle(err) {
		return nil, status.Errorf(codes.NotFound, "GetSRK: %s", err.Error())
	}
	return nil, mapTPMError(err)
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

	iakAttrs, err := tpmIAKAttributes(tpm)
	if err != nil {
		s.logger.Slog().Error("Failed to get IAK attributes", slog.String("error", err.Error()))
		return nil, err
	}

	s.logger.Debug("TPM GetAK completed")
	return &platformv1.GetAKResponse{
		Handle:    uint32(iakAttrs.TPMAttributes.Handle),
		PublicKey: iakAttrs.TPMAttributes.PublicKeyBytes,
		Algorithm: keyAlgorithmToProto(iakAttrs.KeyAlgorithm),
	}, nil
}

// tpmIAKAttributes returns the IAK's attributes only when the IAK exists:
// attributes alone describe where an IAK would live, so a TPM without one
// answers NotFound on every transport.
func tpmIAKAttributes(tpm quicbaassdk.TrustedPlatformModule) (*quicbaassdk.KeyAttributes, error) {
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, mapTPMError(err)
	}
	pubKey, err := tpm.IAK()
	if err != nil {
		return nil, mapTPMError(err)
	}
	if pubKey == nil {
		return nil, status.Error(codes.NotFound, "IAK not found")
	}
	return iakAttrs, nil
}

// DeleteAK refuses: the attestation key this service names is the IAK, which
// is TPM-resident and not evicted here, so it answers like IDevIDService
// DeleteIAK whatever the request's handle, without touching the TPM.
func (s *TPMGRPCService) DeleteAK(
	ctx context.Context,
	req *platformv1.DeleteAKRequest,
) (*platformv1.DeleteAKResponse, error) {

	return nil, ErrDeviceIdentityKeyNotDeletable{Key: "IAK"}
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

	// The TPM quotes the nonce bound to the connection the request arrived
	// on, never the nonce as sent (#482); a request with no TLS connection
	// is refused.
	bound, err := bindQuote(ctx, req.GetNonce())
	if err != nil {
		return nil, err
	}

	sigAlg, err := attestvm.QuoteSignatureAlgorithm(tpm)
	if err != nil {
		s.logger.Slog().Error("TPM Quote refused", slog.String("error", err.Error()))
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	quote, err := tpm.Quote(pcrs, bound.QualifyingData)
	if err != nil {
		s.logger.Slog().Error("TPM Quote failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Quote completed")
	return &platformv1.QuoteResponse{
		Quote:              quote.Quoted,
		Signature:          quote.Signature,
		EventLog:           quote.EventLog,
		ChannelBinding:     bound.Binding,
		SignatureAlgorithm: sigAlg,
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
//     attestation key's public half under the scheme the request
//     declares in signature_algorithm (QuoteResponse.signature_algorithm),
//     through the platform's one quote verifier. No scheme, or one the
//     key cannot carry, fails; the scheme is never inferred from the key.
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

	akPublic, err := s.resolveVerifyAKPublic(req.GetAkPublic())
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

	// Anti-replay: ExtraData must equal the supplied nonce, or, for a quote
	// the node produced over a bound connection, SHA-256(nonce || binding).
	expectedNonce, err := channelbind.ExpectedQualifyingData(req.GetNonce(), req.GetChannelBinding())
	if err != nil {
		return nil, err
	}
	if len(expectedNonce) > 0 {
		if !bytes.Equal(attest.ExtraData.Buffer, expectedNonce) {
			return &platformv1.VerifyQuoteResponse{
				Verified: false,
				Message: fmt.Sprintf("nonce mismatch: quote carries %d bytes of ExtraData, request expects %d bytes",
					len(attest.ExtraData.Buffer), len(expectedNonce)),
			}, nil
		}
	}

	// Verify the signature over the raw Quoted bytes under the declared scheme.
	if err := attestvm.VerifyQuoteSignatureWithAlgorithm(akPublic, req.GetQuote(), req.GetSignature(), req.GetSignatureAlgorithm()); err != nil {
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

// Certify has the IAK certify that the key at a persistent handle is
// resident in this TPM (TPM2_Certify), over the caller's nonce.
func (s *TPMGRPCService) Certify(
	ctx context.Context,
	req *platformv1.CertifyRequest,
) (*platformv1.CertifyResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM Certify request received",
		slog.String("handle", fmt.Sprintf("0x%08X", req.GetKeyHandle())))

	res, err := tpmcertify.Certify(tpm, req.GetKeyHandle(), req.GetKeyPassword(), req.GetNonce())
	if err != nil {
		s.logger.Slog().Error("TPM Certify failed",
			slog.String("handle", fmt.Sprintf("0x%08X", req.GetKeyHandle())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM Certify completed")
	return &platformv1.CertifyResponse{
		CertifyInfo:            res.CertifyInfo,
		Signature:              res.Signature,
		SignatureAlgorithm:     res.SignatureAlgorithm,
		CertifyInfoSignature:   res.CertifyInfoSignature,
		AttestingKeyPublic:     res.AttestingKeyPublic,
		AttestedKeyPublic:      res.AttestedKeyPublic,
		AttestingKeyPublicArea: res.AttestingKeyPublicArea,
		AttestedKeyPublicArea:  res.AttestedKeyPublicArea,
		Nonce:                  res.Nonce,
	}, nil
}

// resolveVerifyAKPublic returns the PKIX DER of the AK public key the
// quote is verified against. Caller-supplied akPublic wins; otherwise
// the IAK provisioned on this platform is used.
func (s *TPMGRPCService) resolveVerifyAKPublic(akPublic []byte) ([]byte, error) {
	if len(akPublic) > 0 {
		return akPublic, nil
	}
	pub, err := s.tpm.IAK()
	if err != nil {
		return nil, &WrappedError{Msg: "read IAK public", Err: err}
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, &WrappedError{Msg: "marshal IAK public", Err: err}
	}
	return der, nil
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
	if err := tpmnv.CheckIndex(req.GetIndex()); err != nil {
		return nil, err
	}
	if err := tpmnv.CheckSpan(0, uint64(req.GetSize())); err != nil {
		return nil, err
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

// WriteNVRAM writes a payload to a defined NV index through
// tpmnv.Write, the path QUIC and MCP share. Auth dispatch mirrors
// ReadNVRAM: AUTHWRITE → index-self auth, OWNERWRITE → owner
// hierarchy, PPWRITE → platform hierarchy. Writes are chunked at
// 512-byte boundaries to stay below TPM_PT_NV_BUFFER_MAX on every
// supported device.
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
	offset, err := nvOffset(req.GetOffset())
	if err != nil {
		return nil, err
	}

	s.logger.Debug("TPM WriteNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())),
		slog.Int("data_bytes", len(req.GetData())),
		slog.Uint64("offset", uint64(offset)))

	err = tpmnv.Write(tpm.Transport(), req.GetIndex(), req.GetData(), offset, tpmnv.Password(req.GetPassword()))
	if err != nil {
		s.logger.Slog().Error("TPM NVWrite failed",
			slog.Uint64("index", uint64(req.GetIndex())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	s.logger.Debug("TPM NVWrite completed", slog.Int("bytes", len(req.GetData())))
	return &platformv1.WriteNVRAMResponse{}, nil
}

// ReadNVRAM reads payload bytes from a defined NV index through
// tpmnv.Read, the path QUIC and MCP share.
//
// tpmnv issues TPM2_NVReadPublic to learn the index's size and
// auth-hierarchy attributes, then TPM2_NVRead in 512-byte chunks
// with the operator-supplied password (empty for
// AuthRead-without-password indices like the TCG-reserved EK
// certificate at 0x1c00002). A size of 0, or one past the end of
// the index, reads to the end.
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
	offset, err := nvOffset(req.GetOffset())
	if err != nil {
		return nil, err
	}

	s.logger.Debug("TPM ReadNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())),
		slog.Uint64("size", uint64(req.GetSize())),
		slog.Uint64("offset", uint64(offset)))

	// No NV index exceeds 65535 bytes, so a larger size reads the whole
	// index, as any size past the index's DataSize does.
	size := uint16(min(req.GetSize(), math.MaxUint16))
	out, err := tpmnv.Read(tpm.Transport(), req.GetIndex(), size, offset, tpmnv.Password(req.GetPassword()))
	if err != nil {
		s.logger.Slog().Error("TPM NVRead failed",
			slog.Uint64("index", uint64(req.GetIndex())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
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

	s.logger.Debug("TPM UndefineNVRAM request received",
		slog.Uint64("index", uint64(req.GetIndex())))

	if err := tpmnv.Undefine(tpm.Transport(), req.GetIndex(), tpmnv.Password(req.GetParentPassword())); err != nil {
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

// GetCapabilities returns the algorithms, commands and ECC curves the TPM
// implements. QUIC 0x99·0x17 and MCP platform_tpm_capabilities read the
// same lists through tpmattrs.ReadCapabilities.
func (s *TPMGRPCService) GetCapabilities(
	ctx context.Context,
	req *platformv1.TPMCapabilitiesRequest,
) (*platformv1.TPMCapabilitiesResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	caps, err := tpmattrs.ReadCapabilities(tpm)
	if err != nil {
		s.logger.Slog().Error("TPM capability read failed", slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	return &platformv1.TPMCapabilitiesResponse{
		Algorithms: caps.Algorithms,
		Commands:   caps.Commands,
		EccCurves:  caps.ECCCurves,
	}, nil
}

// GetPlatformAttributes describes the TPM device and its provisioned
// identity keys. QUIC 0x99·0x1E and MCP platform_tpm_platform read the
// same attributes through tpmattrs.ReadPlatform.
func (s *TPMGRPCService) GetPlatformAttributes(
	ctx context.Context,
	req *platformv1.TPMPlatformAttributesRequest,
) (*platformv1.TPMPlatformAttributesResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	platform := tpmattrs.ReadPlatform(tpm)
	return &platformv1.TPMPlatformAttributesResponse{
		Device:       platform.Device,
		IsFips:       platform.IsFIPS,
		PcrExtended:  platform.PCRExtended,
		CanSeal:      platform.CanSeal,
		IsSimulator:  platform.IsSimulator,
		Manufacturer: platform.Manufacturer,
		Ek:           tpmKeyRefProto(platform.EK),
		Srk:          tpmKeyRefProto(platform.SRK),
		Iak:          tpmKeyRefProto(platform.IAK),
	}, nil
}

// tpmKeyRefProto converts a provisioned key reference; an absent key
// stays absent.
func tpmKeyRefProto(ref *tpmattrs.KeyRef) *platformv1.TPMKeyRef {
	if ref == nil {
		return nil
	}
	return &platformv1.TPMKeyRef{Handle: ref.Handle, Algorithm: ref.Algorithm}
}

// ExtendPCR extends one PCR through tpmpcr.Extend, the validation QUIC
// 0x99·0x12 and MCP platform_tpm_pcr_extend share.
func (s *TPMGRPCService) ExtendPCR(
	ctx context.Context,
	req *platformv1.ExtendPCRRequest,
) (*platformv1.ExtendPCRResponse, error) {

	s.mu.RLock()
	tpm := s.tpm
	s.mu.RUnlock()

	if tpm == nil {
		return nil, status.Error(codes.Unavailable, "TPM service not available")
	}

	s.logger.Debug("TPM ExtendPCR request received",
		slog.Uint64("index", uint64(req.GetIndex())),
		slog.String("hash_alg", req.GetHashAlg()))

	if err := tpmpcr.Extend(tpm, int(req.GetIndex()), req.GetHashAlg(), req.GetData()); err != nil {
		s.logger.Slog().Error("TPM ExtendPCR failed",
			slog.Uint64("index", uint64(req.GetIndex())),
			slog.String("error", err.Error()))
		return nil, s.mapError(err)
	}

	return &platformv1.ExtendPCRResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: tpmpcr.ExtendedMessage(int(req.GetIndex())),
		},
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

// nvOffset narrows a proto NV offset to the 16 bits the TPM command
// carries, rejecting one that does not fit.
func nvOffset(offset uint32) (uint16, error) {
	if offset > math.MaxUint16 {
		return 0, ErrNVOffsetOutOfRange{Offset: offset}
	}
	return uint16(offset), nil
}

// mapError converts service errors to gRPC status errors.
func (s *TPMGRPCService) mapError(err error) error {
	return mapTPMError(err)
}

// mapTPMError gives a TPM backend error its gRPC class. The MCP TPM tools
// return their errors through it too, so a tool and its gRPC twin answer
// the same input with the same class.
func mapTPMError(err error) error {
	if err == nil {
		return nil
	}

	// A typed error that already carries its gRPC class (the shared
	// tpmnv / tpmpcr validation errors) keeps it.
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return st.Err()
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
