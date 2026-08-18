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
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
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

// The PIV service-layer requests hold PINs and private key material in a
// memguard.MemoryEnclave and release it with Destroy. Known gap: the
// transport decodes each field into an immutable Go string before the
// platform can take custody, so the enclave is the durable custodian from
// here inward but the decode buffer ahead of it cannot be wiped. Closing
// that needs wire and SDK changes; see docs/security/protected-memory.md.

// PIVGenerateRequest is the service-layer generate request.
type PIVGenerateRequest struct {
	Slot      string
	Algorithm PIVAlgorithm

	// PIN is the PIV PIN as a plain string.
	//
	// Deprecated: populate PINEnclave instead. A Go string cannot be
	// zeroized, so a PIN parked here stays readable in the process image
	// until the collector happens to reuse the memory. The field remains
	// for compatibility until the coordinated portfolio-wide
	// protected-memory wave removes it; WithPIN prefers PINEnclave and
	// falls back to this.
	PIN string

	// PINEnclave holds the PIV PIN in locked, zeroized memory. Transports
	// populate it directly from the decoded request and release it with
	// Destroy.
	PINEnclave *memguard.MemoryEnclave
}

// WithPIN invokes fn with the request PIN, preferring PINEnclave over the
// deprecated plain PIN field. See withEnclaveString for the string-copy
// caveat.
func (r *PIVGenerateRequest) WithPIN(fn func(pin string) error) error {
	return withEnclaveString(r.PINEnclave, r.PIN, fn)
}

// Destroy zeroizes the protected memory the request holds. It is safe to
// call on a request that carries no enclave, and safe to call twice.
func (r *PIVGenerateRequest) Destroy() {
	r.PINEnclave.Destroy()
}

// PIVGenerateResult is the service-layer generate response.
type PIVGenerateResult struct {
	PublicKeyPEM string
}

// PIVImportRequest is the service-layer import request.
type PIVImportRequest struct {
	Slot string

	// PrivateKeyPEM is the PEM-encoded key material as a plain string.
	//
	// Deprecated: populate PrivateKey instead. Private key material must
	// live in protected memory for its whole lifetime; a Go string cannot
	// be zeroized. The field remains for compatibility until the
	// coordinated portfolio-wide protected-memory wave removes it;
	// WithPrivateKeyPEM and HasPrivateKey prefer PrivateKey and fall back
	// to this.
	PrivateKeyPEM string

	// PrivateKey holds the PEM-encoded key material in locked, zeroized
	// memory.
	PrivateKey *memguard.MemoryEnclave

	// PIN is the PIV PIN as a plain string.
	//
	// Deprecated: populate PINEnclave instead. See
	// PIVGenerateRequest.PIN.
	PIN string

	// PINEnclave holds the PIV PIN in locked, zeroized memory.
	PINEnclave *memguard.MemoryEnclave
}

// WithPrivateKeyPEM invokes fn with the PEM-encoded key material, preferring
// PrivateKey over the deprecated plain PrivateKeyPEM field. The slice passed
// to fn is borrowed from locked memory: fn must not retain or modify it.
func (r *PIVImportRequest) WithPrivateKeyPEM(fn func(pem []byte) error) error {
	if !r.PrivateKey.IsAlive() {
		return fn([]byte(r.PrivateKeyPEM))
	}
	return r.PrivateKey.Open(fn)
}

// HasPrivateKey reports whether the request carries any key material,
// checking the protected field first.
func (r *PIVImportRequest) HasPrivateKey() bool {
	if r.PrivateKey.IsAlive() {
		return r.PrivateKey.Size() > 0
	}
	return r.PrivateKeyPEM != ""
}

// WithPIN invokes fn with the request PIN, preferring PINEnclave over the
// deprecated plain PIN field.
func (r *PIVImportRequest) WithPIN(fn func(pin string) error) error {
	return withEnclaveString(r.PINEnclave, r.PIN, fn)
}

// Destroy zeroizes the protected memory the request holds.
func (r *PIVImportRequest) Destroy() {
	r.PrivateKey.Destroy()
	r.PINEnclave.Destroy()
}

// PIVSignRequest is the service-layer sign request.
type PIVSignRequest struct {
	Slot    string
	Payload []byte

	// PIN is the PIV PIN as a plain string.
	//
	// Deprecated: populate PINEnclave instead. See PIVGenerateRequest.PIN.
	PIN string

	// PINEnclave holds the PIV PIN in locked, zeroized memory.
	PINEnclave *memguard.MemoryEnclave
}

// WithPIN invokes fn with the request PIN, preferring PINEnclave over the
// deprecated plain PIN field.
func (r *PIVSignRequest) WithPIN(fn func(pin string) error) error {
	return withEnclaveString(r.PINEnclave, r.PIN, fn)
}

// Destroy zeroizes the protected memory the request holds.
func (r *PIVSignRequest) Destroy() {
	r.PINEnclave.Destroy()
}

// withEnclaveString invokes fn with the value held in e, falling back to the
// deprecated plain-string field when no live enclave is set.
//
// The value is materialised as a Go string only for the duration of the
// call because the upstream xkms PIV API takes a string. That copy cannot
// itself be zeroized, so this narrows the exposure window to the call
// rather than closing it; the enclave remains the durable custodian.
func withEnclaveString(e *memguard.MemoryEnclave, fallback string, fn func(string) error) error {
	if !e.IsAlive() {
		return fn(fallback)
	}
	return e.Open(func(b []byte) error { return fn(string(b)) })
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
	if !req.HasPrivateKey() {
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
