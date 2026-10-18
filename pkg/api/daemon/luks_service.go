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
	"errors"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// LUKS service errors.

// ErrLUKSNotConfigured indicates the LUKS backend is not available.
var ErrLUKSNotConfigured = errors.New("luks: backend not configured")

// ErrLUKSDeviceRequired indicates the caller omitted the device path.
var ErrLUKSDeviceRequired = errors.New("luks: device path is required")

// ErrLUKSPassphraseRequired indicates a required passphrase was missing.
var ErrLUKSPassphraseRequired = errors.New("luks: passphrase is required")

// ErrLUKSNewPassphraseRequired indicates the new passphrase was missing.
var ErrLUKSNewPassphraseRequired = errors.New("luks: new passphrase is required")

// ErrLUKSCredentialIDRequired indicates the FIDO2 credential id was missing.
var ErrLUKSCredentialIDRequired = errors.New("luks: fido2 credential id is required")

// ErrLUKSSlotRequired indicates the keyslot index was missing.
var ErrLUKSSlotRequired = errors.New("luks: slot index is required")

// ErrLUKSRootRequired indicates the operation requires root privileges.
var ErrLUKSRootRequired = errors.New("luks: operation requires root privileges")

// ErrLUKSMalformedBody indicates a REST request body that is not valid JSON
// for the operation. It carries no decoder detail, because a JSON syntax
// error quotes the offending input and the body may hold a passphrase.
var ErrLUKSMalformedBody = errors.New("luks: malformed request body")

// LUKSKeyType enumerates the LUKS2 keyslot backends.
type LUKSKeyType string

const (
	// LUKSKeyTypeUnspecified indicates no key type was given.
	LUKSKeyTypeUnspecified LUKSKeyType = ""
	// LUKSKeyTypePassphrase is a passphrase keyslot.
	LUKSKeyTypePassphrase LUKSKeyType = "passphrase"
	// LUKSKeyTypeFIDO2 is a FIDO2 keyslot.
	LUKSKeyTypeFIDO2 LUKSKeyType = "fido2"
	// LUKSKeyTypeTPM is a TPM2-sealed keyslot.
	LUKSKeyTypeTPM LUKSKeyType = "tpm"
	// LUKSKeyTypeRecovery is a recovery keyslot.
	LUKSKeyTypeRecovery LUKSKeyType = "recovery"
)

// LUKSKeyslot describes a single LUKS2 keyslot.
type LUKSKeyslot struct {
	Slot     int32
	Type     LUKSKeyType
	KeySize  int32
	Priority int32
}

// LUKSStatus reports the high-level LUKS device state.
type LUKSStatus struct {
	Device      string
	IsLUKS      bool
	Version     int32
	UUID        string
	Label       string
	Cipher      string
	ActiveSlots []int32
}

// LUKSListSlotsResult lists active keyslots on a device.
type LUKSListSlotsResult struct {
	Device string
	Slots  []LUKSKeyslot
}

// LUKSInfo returns a detailed info dump.
type LUKSInfo struct {
	Device       string
	UUID         string
	Label        string
	Version      int32
	Cipher       string
	KeySize      int32
	SectorSize   int32
	Slots        []LUKSKeyslot
	MetadataJSON string
}

// LUKSEnrollPassphraseRequest adds a passphrase slot. The request structs'
// JSON tags are the REST body keys: the snake_case names QUIC and MCP use.
type LUKSEnrollPassphraseRequest struct {
	Device             string `json:"device"`
	ExistingPassphrase string `json:"existing_passphrase"`
	NewPassphrase      string `json:"new_passphrase"`
}

// LUKSEnrollPassphraseResult is returned by EnrollPassphrase.
type LUKSEnrollPassphraseResult struct {
	Slot int32
}

// LUKSEnrollFIDO2Request adds a FIDO2 slot.
type LUKSEnrollFIDO2Request struct {
	Device             string `json:"device"`
	ExistingPassphrase string `json:"existing_passphrase"`
	CredentialID       string `json:"credential_id"`
	RequirePIN         bool   `json:"require_pin"`
	RequireUV          bool   `json:"require_uv"`
}

// LUKSEnrollFIDO2Result is returned by EnrollFIDO2.
type LUKSEnrollFIDO2Result struct {
	Slot    int32
	TokenID string
}

// LUKSEnrollTPMRequest adds a TPM2-sealed slot.
type LUKSEnrollTPMRequest struct {
	Device             string  `json:"device"`
	ExistingPassphrase string  `json:"existing_passphrase"`
	PCRs               []int32 `json:"pcrs"`
}

// LUKSEnrollTPMResult is returned by EnrollTPM.
type LUKSEnrollTPMResult struct {
	Slot    int32
	TokenID string
}

// LUKSEnrollRecoveryRequest adds a recovery-key slot.
type LUKSEnrollRecoveryRequest struct {
	Device             string `json:"device"`
	ExistingPassphrase string `json:"existing_passphrase"`
}

// LUKSEnrollRecoveryResult is returned by EnrollRecovery.
type LUKSEnrollRecoveryResult struct {
	Slot        int32
	RecoveryKey string
}

// LUKSRemoveKeyRequest removes a keyslot.
type LUKSRemoveKeyRequest struct {
	Device string `json:"device"`
	Slot   int32  `json:"slot"`
}

// LUKSTestUnlockRequest tests a keyslot.
type LUKSTestUnlockRequest struct {
	Device string `json:"device"`
	Slot   int32  `json:"slot"`
}

// LUKSChangePassphraseRequest changes a passphrase slot.
type LUKSChangePassphraseRequest struct {
	Device        string `json:"device"`
	Slot          int32  `json:"slot"`
	OldPassphrase string `json:"old_passphrase"`
	NewPassphrase string `json:"new_passphrase"`
}

// LUKSBackend abstracts the upstream LUKS2 implementation.
type LUKSBackend interface {
	Status(ctx context.Context, device string) (*LUKSStatus, error)
	ListSlots(ctx context.Context, device string) (*LUKSListSlotsResult, error)
	Info(ctx context.Context, device string) (*LUKSInfo, error)
	EnrollPassphrase(ctx context.Context, req *LUKSEnrollPassphraseRequest) (*LUKSEnrollPassphraseResult, error)
	EnrollFIDO2(ctx context.Context, req *LUKSEnrollFIDO2Request) (*LUKSEnrollFIDO2Result, error)
	EnrollTPM(ctx context.Context, req *LUKSEnrollTPMRequest) (*LUKSEnrollTPMResult, error)
	EnrollRecovery(ctx context.Context, req *LUKSEnrollRecoveryRequest) (*LUKSEnrollRecoveryResult, error)
	RemoveKey(ctx context.Context, req *LUKSRemoveKeyRequest) error
	TestUnlock(ctx context.Context, req *LUKSTestUnlockRequest) (bool, error)
	ChangePassphrase(ctx context.Context, req *LUKSChangePassphraseRequest) error
}

// RootChecker reports whether the caller has root privileges. Injection
// keeps the service testable without touching the host.
type RootChecker interface {
	IsRoot() bool
}

// RootCheckerFunc is a function adapter for RootChecker.
type RootCheckerFunc func() bool

// IsRoot implements RootChecker.
func (f RootCheckerFunc) IsRoot() bool { return f() }

// LUKSService is the platformd-side LUKS2 business-logic layer.
type LUKSService struct {
	logger  *logging.Logger
	backend LUKSBackend
	root    RootChecker

	mu sync.RWMutex
}

// NewLUKSService constructs a new LUKS service.
//
// If root is nil a default checker that always reports non-root is used so
// tests never accidentally skip root-gating.
func NewLUKSService(logger *logging.Logger, backend LUKSBackend, root RootChecker) *LUKSService {
	if root == nil {
		root = RootCheckerFunc(func() bool { return false })
	}
	return &LUKSService{logger: logger, backend: backend, root: root}
}

// Backend returns the configured backend.
func (s *LUKSService) Backend() LUKSBackend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend
}

// SetBackend replaces the configured backend.
func (s *LUKSService) SetBackend(b LUKSBackend) {
	s.mu.Lock()
	s.backend = b
	s.mu.Unlock()
}

// requireRoot returns ErrLUKSRootRequired when not running as root.
func (s *LUKSService) requireRoot() error {
	if s.root == nil || !s.root.IsRoot() {
		return ErrLUKSRootRequired
	}
	return nil
}

// Status delegates to the backend.
func (s *LUKSService) Status(ctx context.Context, device string) (*LUKSStatus, error) {
	if device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.Status(ctx, device)
}

// ListSlots delegates to the backend.
func (s *LUKSService) ListSlots(ctx context.Context, device string) (*LUKSListSlotsResult, error) {
	if device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.ListSlots(ctx, device)
}

// Info delegates to the backend.
func (s *LUKSService) Info(ctx context.Context, device string) (*LUKSInfo, error) {
	if device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.Info(ctx, device)
}

// EnrollPassphrase adds a passphrase slot. Requires root.
func (s *LUKSService) EnrollPassphrase(ctx context.Context, req *LUKSEnrollPassphraseRequest) (*LUKSEnrollPassphraseResult, error) {
	if err := s.requireRoot(); err != nil {
		return nil, err
	}
	if req == nil || req.Device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	if req.NewPassphrase == "" {
		return nil, ErrLUKSNewPassphraseRequired
	}
	if req.ExistingPassphrase == "" {
		return nil, ErrLUKSPassphraseRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.EnrollPassphrase(ctx, req)
}

// EnrollFIDO2 adds a FIDO2 slot. Requires root.
func (s *LUKSService) EnrollFIDO2(ctx context.Context, req *LUKSEnrollFIDO2Request) (*LUKSEnrollFIDO2Result, error) {
	if err := s.requireRoot(); err != nil {
		return nil, err
	}
	if req == nil || req.Device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	if req.CredentialID == "" {
		return nil, ErrLUKSCredentialIDRequired
	}
	if req.ExistingPassphrase == "" {
		return nil, ErrLUKSPassphraseRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.EnrollFIDO2(ctx, req)
}

// EnrollTPM adds a TPM2-sealed slot. Requires root.
func (s *LUKSService) EnrollTPM(ctx context.Context, req *LUKSEnrollTPMRequest) (*LUKSEnrollTPMResult, error) {
	if err := s.requireRoot(); err != nil {
		return nil, err
	}
	if req == nil || req.Device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	if req.ExistingPassphrase == "" {
		return nil, ErrLUKSPassphraseRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.EnrollTPM(ctx, req)
}

// EnrollRecovery adds a recovery-key slot. Requires root.
func (s *LUKSService) EnrollRecovery(ctx context.Context, req *LUKSEnrollRecoveryRequest) (*LUKSEnrollRecoveryResult, error) {
	if err := s.requireRoot(); err != nil {
		return nil, err
	}
	if req == nil || req.Device == "" {
		return nil, ErrLUKSDeviceRequired
	}
	if req.ExistingPassphrase == "" {
		return nil, ErrLUKSPassphraseRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrLUKSNotConfigured
	}
	return b.EnrollRecovery(ctx, req)
}

// RemoveKey removes a keyslot. Requires root.
func (s *LUKSService) RemoveKey(ctx context.Context, req *LUKSRemoveKeyRequest) error {
	if err := s.requireRoot(); err != nil {
		return err
	}
	if req == nil || req.Device == "" {
		return ErrLUKSDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return ErrLUKSNotConfigured
	}
	return b.RemoveKey(ctx, req)
}

// TestUnlock verifies a keyslot can unlock a device.
func (s *LUKSService) TestUnlock(ctx context.Context, req *LUKSTestUnlockRequest) (bool, error) {
	if req == nil || req.Device == "" {
		return false, ErrLUKSDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return false, ErrLUKSNotConfigured
	}
	return b.TestUnlock(ctx, req)
}

// ChangePassphrase replaces an existing passphrase slot value. Requires root.
func (s *LUKSService) ChangePassphrase(ctx context.Context, req *LUKSChangePassphraseRequest) error {
	if err := s.requireRoot(); err != nil {
		return err
	}
	if req == nil || req.Device == "" {
		return ErrLUKSDeviceRequired
	}
	if req.NewPassphrase == "" {
		return ErrLUKSNewPassphraseRequired
	}
	if req.OldPassphrase == "" {
		return ErrLUKSPassphraseRequired
	}
	b := s.Backend()
	if b == nil {
		return ErrLUKSNotConfigured
	}
	return b.ChangePassphrase(ctx, req)
}
