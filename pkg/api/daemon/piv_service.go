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

// PIV service errors.

// ErrPIVNotConfigured indicates the PIV backend is not available on this
// server (no PIV manager wired).
var ErrPIVNotConfigured = errors.New("piv: backend not configured")

// ErrPIVSlotRequired indicates the caller failed to provide a slot id.
var ErrPIVSlotRequired = errors.New("piv: slot id is required")

// ErrPIVDeviceRequired indicates the caller failed to provide a device id.
var ErrPIVDeviceRequired = errors.New("piv: device id is required")

// ErrPIVPayloadRequired indicates the caller passed an empty payload to Sign.
var ErrPIVPayloadRequired = errors.New("piv: signing payload is required")

// ErrPIVPrivateKeyRequired indicates Import was called without a key PEM.
var ErrPIVPrivateKeyRequired = errors.New("piv: private_key_pem is required")

// PIVAlgorithm enumerates the supported PIV key algorithms.
type PIVAlgorithm string

const (
	// PIVAlgorithmUnspecified indicates no algorithm was chosen.
	PIVAlgorithmUnspecified PIVAlgorithm = ""
	// PIVAlgorithmRSA is an RSA key.
	PIVAlgorithmRSA PIVAlgorithm = "rsa"
	// PIVAlgorithmECDSA is an ECDSA key.
	PIVAlgorithmECDSA PIVAlgorithm = "ecdsa"
	// PIVAlgorithmEd25519 is an Ed25519 key.
	PIVAlgorithmEd25519 PIVAlgorithm = "ed25519"
)

// PIVDevice describes a PIV-capable device.
type PIVDevice struct {
	ID              string
	Name            string
	Manufacturer    string
	Model           string
	Serial          string
	FirmwareVersion string
}

// PIVSlot describes the contents of a PIV slot.
type PIVSlot struct {
	ID             string
	Name           string
	Algorithm      PIVAlgorithm
	HasKey         bool
	HasCertificate bool
}

// PIVSlotInfo is the detailed view of a PIV slot.
type PIVSlotInfo struct {
	Slot           PIVSlot
	PublicKeyPEM   string
	CertificatePEM string
}

// PIVGenerateRequest is the service-layer generate request.
type PIVGenerateRequest struct {
	Slot      string
	Algorithm PIVAlgorithm
	PIN       string
}

// PIVGenerateResult is the service-layer generate response.
type PIVGenerateResult struct {
	PublicKeyPEM string
}

// PIVImportRequest is the service-layer import request.
type PIVImportRequest struct {
	Slot          string
	PrivateKeyPEM string
	PIN           string
}

// PIVSignRequest is the service-layer sign request.
type PIVSignRequest struct {
	Slot    string
	Payload []byte
	PIN     string
}

// PIVAttestResult is the service-layer attest response.
type PIVAttestResult struct {
	AttestationCertPEM  string
	AttestationChainPEM string
}

// PIVBackend abstracts the upstream PIV implementation. Implementations are
// expected to be safe for concurrent use.
type PIVBackend interface {
	// ListDevices enumerates attached PIV devices.
	ListDevices(ctx context.Context) ([]PIVDevice, error)
	// ListSlots lists the slots available on a device.
	ListSlots(ctx context.Context, device string) ([]PIVSlot, error)
	// SlotInfo returns detailed info about a single slot.
	SlotInfo(ctx context.Context, device, slot string) (*PIVSlotInfo, error)
	// Generate asks the device to generate a fresh key in a slot.
	Generate(ctx context.Context, req *PIVGenerateRequest) (*PIVGenerateResult, error)
	// Import imports an existing private key into a slot.
	Import(ctx context.Context, req *PIVImportRequest) error
	// Sign signs a payload with the slot's key.
	Sign(ctx context.Context, req *PIVSignRequest) ([]byte, error)
	// Attest returns the attestation certificate(s) for a slot.
	Attest(ctx context.Context, slot string) (*PIVAttestResult, error)
	// Reset factory-resets a PIV device.
	Reset(ctx context.Context, device string) error
}

// PIVService is the platformd-side PIV business-logic layer.
type PIVService struct {
	logger  *logging.Logger
	backend PIVBackend

	mu sync.RWMutex
}

// NewPIVService constructs a new PIV service. When backend is nil every
// method returns ErrPIVNotConfigured.
func NewPIVService(logger *logging.Logger, backend PIVBackend) *PIVService {
	return &PIVService{logger: logger, backend: backend}
}

// Backend returns the configured backend.
func (s *PIVService) Backend() PIVBackend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend
}

// SetBackend replaces the configured backend.
func (s *PIVService) SetBackend(b PIVBackend) {
	s.mu.Lock()
	s.backend = b
	s.mu.Unlock()
}

// ListDevices delegates to the backend.
func (s *PIVService) ListDevices(ctx context.Context) ([]PIVDevice, error) {
	b := s.Backend()
	if b == nil {
		return nil, ErrPIVNotConfigured
	}
	return b.ListDevices(ctx)
}

// ListSlots delegates to the backend.
func (s *PIVService) ListSlots(ctx context.Context, device string) ([]PIVSlot, error) {
	if device == "" {
		return nil, ErrPIVDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrPIVNotConfigured
	}
	return b.ListSlots(ctx, device)
}

// SlotInfo delegates to the backend.
func (s *PIVService) SlotInfo(ctx context.Context, device, slot string) (*PIVSlotInfo, error) {
	if slot == "" {
		return nil, ErrPIVSlotRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrPIVNotConfigured
	}
	return b.SlotInfo(ctx, device, slot)
}

// Generate delegates to the backend.
func (s *PIVService) Generate(ctx context.Context, req *PIVGenerateRequest) (*PIVGenerateResult, error) {
	if req == nil || req.Slot == "" {
		return nil, ErrPIVSlotRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrPIVNotConfigured
	}
	return b.Generate(ctx, req)
}

// Import delegates to the backend.
func (s *PIVService) Import(ctx context.Context, req *PIVImportRequest) error {
	if req == nil || req.Slot == "" {
		return ErrPIVSlotRequired
	}
	if req.PrivateKeyPEM == "" {
		return ErrPIVPrivateKeyRequired
	}
	b := s.Backend()
	if b == nil {
		return ErrPIVNotConfigured
	}
	return b.Import(ctx, req)
}

// Sign delegates to the backend.
func (s *PIVService) Sign(ctx context.Context, req *PIVSignRequest) ([]byte, error) {
	if req == nil || req.Slot == "" {
		return nil, ErrPIVSlotRequired
	}
	if len(req.Payload) == 0 {
		return nil, ErrPIVPayloadRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrPIVNotConfigured
	}
	return b.Sign(ctx, req)
}

// Attest delegates to the backend.
func (s *PIVService) Attest(ctx context.Context, slot string) (*PIVAttestResult, error) {
	if slot == "" {
		return nil, ErrPIVSlotRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrPIVNotConfigured
	}
	return b.Attest(ctx, slot)
}

// Reset delegates to the backend. The handler is responsible for root / policy
// checks before invoking Reset.
func (s *PIVService) Reset(ctx context.Context, device string) error {
	if device == "" {
		return ErrPIVDeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return ErrPIVNotConfigured
	}
	return b.Reset(ctx, device)
}
