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

package backends

import (
	"context"
	"errors"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	xkmstransport "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/transport"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// PIV backend typed errors.

// ErrPIVBackendUnavailable indicates the PIV manager singleton has not been
// initialised in the running xkms binary.
var ErrPIVBackendUnavailable = errors.New("piv backend: xkms piv manager is not initialised")

// ErrPIVSignFailed indicates signing via the xkms PIV manager failed after
// the request reached the upstream surface.
var ErrPIVSignFailed = errors.New("piv backend: sign request failed")

// ErrPIVAttestFailed indicates an attestation request failed after reaching
// the xkms PIV manager.
var ErrPIVAttestFailed = errors.New("piv backend: attestation request failed")

// ErrPIVResetNotConfirmed indicates a factory reset reached this backend
// without the required confirmation flag. Callers (REST / gRPC / CLI) are
// responsible for collecting the admin's confirmation before invoking Reset
// on the service; this guard catches any regression where that check is
// bypassed.
var ErrPIVResetNotConfirmed = errors.New("piv backend: factory reset requires explicit confirmation")

// DefaultPIVBackendName is the backend name used by the backend when the
// caller does not identify a specific device. It matches xkmsctl's default.
const DefaultPIVBackendName = "software"

// pivAlgorithmMap normalises service-layer enum values to the xkms wire
// algorithm strings.
var pivAlgorithmMap = map[daemon.PIVAlgorithm]string{
	daemon.PIVAlgorithmRSA:     "rsa2048",
	daemon.PIVAlgorithmECDSA:   "ecdsap256",
	daemon.PIVAlgorithmEd25519: "ed25519",
}

// pivAlgorithmReverseMap normalises xkms wire algorithm strings to the
// service-layer enum.
var pivAlgorithmReverseMap = map[string]daemon.PIVAlgorithm{
	"rsa2048":   daemon.PIVAlgorithmRSA,
	"rsa4096":   daemon.PIVAlgorithmRSA,
	"ecdsap256": daemon.PIVAlgorithmECDSA,
	"ecdsap384": daemon.PIVAlgorithmECDSA,
	"ed25519":   daemon.PIVAlgorithmEd25519,
	"RSA":       daemon.PIVAlgorithmRSA,
	"ECDSA":     daemon.PIVAlgorithmECDSA,
	"Ed25519":   daemon.PIVAlgorithmEd25519,
}

// PIVBackend implements daemon.PIVBackend by delegating to the go-xkms
// package-level PIV manager. The manager is a singleton inside go-xkms, so
// this backend keeps no state beyond a logger handle.
type PIVBackend struct {
	logger *logging.Logger
	// defaultBackend is the xkms backend name used when a caller doesn't
	// provide one. It's configurable so tests can point at a fake store.
	defaultBackend string
	// resetConfirmed gates the Reset path. The service handler flips this
	// to true after collecting the admin's confirmation token and then
	// releases it after the call completes. This defence-in-depth guard
	// ensures a Reset request that escapes the confirmation flow cannot
	// reach the destructive xkms call.
	resetConfirmed bool
}

// Compile-time assertion the backend satisfies the service contract.
var _ daemon.PIVBackend = (*PIVBackend)(nil)

// NewPIVBackend constructs a new PIV backend. The xkms PIV manager must have
// been initialised via xkmsbackend.InitializePIV before the backend is used;
// otherwise every call returns ErrPIVBackendUnavailable.
func NewPIVBackend(logger *logging.Logger) *PIVBackend {
	return &PIVBackend{logger: logger, defaultBackend: DefaultPIVBackendName}
}

// WithDefaultBackend overrides the default backend name. Returns the receiver
// so it can be chained off the constructor.
func (b *PIVBackend) WithDefaultBackend(name string) *PIVBackend {
	if name != "" {
		b.defaultBackend = name
	}
	return b
}

// ConfirmReset marks the backend as having received a valid administrator
// confirmation for a subsequent Reset call. It is the caller's responsibility
// to pair every ConfirmReset with exactly one Reset; the flag is one-shot
// and clears itself when Reset is invoked. The platformd PIV service layer
// handles the pairing on behalf of all protocol adapters.
func (b *PIVBackend) ConfirmReset() {
	b.resetConfirmed = true
}

// backendOr resolves the effective xkms backend name for a request.
func (b *PIVBackend) backendOr(name string) string {
	if name != "" {
		return name
	}
	return b.defaultBackend
}

// ListDevices returns a single synthetic entry per registered xkms backend.
// go-xkms's PIV manager is backend-name keyed rather than device-id keyed,
// so "device" here maps onto a backend identifier (software, pkcs11://..., etc).
func (b *PIVBackend) ListDevices(ctx context.Context) ([]daemon.PIVDevice, error) {
	if err := b.ensureInitialised(); err != nil {
		return nil, err
	}
	// go-xkms exposes a single software backend by default. We surface that
	// as a synthetic device so the CLI has a non-empty list to render.
	return []daemon.PIVDevice{{
		ID:           b.defaultBackend,
		Name:         b.defaultBackend,
		Manufacturer: "go-xkms",
		Model:        "software",
	}}, nil
}

// ListSlots enumerates all PIV slots on the resolved backend.
func (b *PIVBackend) ListSlots(ctx context.Context, device string) ([]daemon.PIVSlot, error) {
	if err := b.ensureInitialised(); err != nil {
		return nil, err
	}
	resp, err := xkmsbackend.ListPIVSlots(ctx, &xkmstransport.ListPIVSlotsRequest{
		Backend: b.backendOr(device),
	})
	if err != nil {
		return nil, err
	}
	out := make([]daemon.PIVSlot, 0, len(resp.Slots))
	for _, s := range resp.Slots {
		out = append(out, pivSlotFromStatus(s))
	}
	return out, nil
}

// SlotInfo returns detail for a specific slot. When the cert is present it's
// returned alongside the slot metadata.
func (b *PIVBackend) SlotInfo(ctx context.Context, device, slot string) (*daemon.PIVSlotInfo, error) {
	if err := b.ensureInitialised(); err != nil {
		return nil, err
	}
	slots, err := b.ListSlots(ctx, device)
	if err != nil {
		return nil, err
	}
	var match *daemon.PIVSlot
	for i := range slots {
		if slots[i].ID == slot {
			match = &slots[i]
			break
		}
	}
	if match == nil {
		return nil, xkmsbackend.ErrPIVInvalidSlot
	}

	info := &daemon.PIVSlotInfo{Slot: *match}
	if match.HasCertificate {
		certResp, certErr := xkmsbackend.GetPIVCertificate(ctx, &xkmstransport.GetPIVCertificateRequest{
			Backend: b.backendOr(device),
			Slot:    slot,
			Format:  "pem",
		})
		if certErr == nil && certResp != nil {
			info.CertificatePEM = string(certResp.Certificate)
		}
	}
	return info, nil
}

// Generate asks the backend to produce a fresh key in a slot. When the
// service-layer request omits algorithm or PIN the xkms defaults apply.
func (b *PIVBackend) Generate(ctx context.Context, req *daemon.PIVGenerateRequest) (*daemon.PIVGenerateResult, error) {
	if err := b.ensureInitialised(); err != nil {
		return nil, err
	}
	algo, ok := pivAlgorithmMap[req.Algorithm]
	if !ok {
		// Pass through the raw enum name for cases we don't recognise so
		// the caller can still drive non-standard algorithms.
		algo = string(req.Algorithm)
	}
	resp, err := xkmsbackend.GeneratePIVKey(ctx, &xkmstransport.GeneratePIVKeyRequest{
		Backend:      b.defaultBackend,
		Slot:         req.Slot,
		Algorithm:    algo,
		OutputFormat: "public-key",
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrPIVBackendUnavailable
	}
	return &daemon.PIVGenerateResult{
		PublicKeyPEM: string(resp.PublicKey),
	}, nil
}

// Import stores an external certificate. Note that xkms does not currently
// expose a public key-import path (software key generators hold the key
// internally); the Import service method maps onto certificate import only.
func (b *PIVBackend) Import(ctx context.Context, req *daemon.PIVImportRequest) error {
	if err := b.ensureInitialised(); err != nil {
		return err
	}
	// The PEM slice is borrowed from the request's locked memory for the
	// duration of the call; StorePIVCertificate must not retain it.
	return req.WithPrivateKeyPEM(func(pem []byte) error {
		return xkmsbackend.StorePIVCertificate(ctx, &xkmstransport.StorePIVCertificateRequest{
			Backend:     b.defaultBackend,
			Slot:        req.Slot,
			Certificate: pem,
			Format:      "pem",
		})
	})
}

// Sign signs the supplied payload with the slot's private key. It delegates
// to the xkms SDK which resolves the configured PIVKeyGenerator and applies
// a sensible default hash algorithm based on the key type. Ed25519 slots
// sign the raw payload.
func (b *PIVBackend) Sign(ctx context.Context, req *daemon.PIVSignRequest) ([]byte, error) {
	if err := b.ensureInitialised(); err != nil {
		return nil, err
	}
	var signature []byte
	// The PIN is materialised as a string only for the xkms call, which
	// takes one; the request's enclave stays the durable custodian.
	err := req.WithPIN(func(pin string) error {
		resp, err := xkmssdk.SignPIV(ctx, &xkmssdk.PIVSignRequest{
			Backend: b.defaultBackend,
			Slot:    req.Slot,
			Payload: req.Payload,
			PIN:     pin,
		})
		if err != nil {
			b.logger.Error(err, "op", "piv-sign", "slot", req.Slot)
			return err
		}
		if resp == nil || len(resp.Signature) == 0 {
			return ErrPIVSignFailed
		}
		signature = resp.Signature
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Attest returns the attestation statement for the slot. For software
// backends this is the slot's own certificate; hardware backends populate
// the attestation CA chain via the xkms PIV manager.
func (b *PIVBackend) Attest(ctx context.Context, slot string) (*daemon.PIVAttestResult, error) {
	if err := b.ensureInitialised(); err != nil {
		return nil, err
	}
	resp, err := xkmssdk.AttestPIV(ctx, &xkmssdk.PIVAttestRequest{
		Backend: b.defaultBackend,
		Slot:    slot,
	})
	if err != nil {
		b.logger.Error(err, "op", "piv-attest", "slot", slot)
		return nil, err
	}
	if resp == nil {
		return nil, ErrPIVAttestFailed
	}
	return &daemon.PIVAttestResult{
		AttestationCertPEM:  string(resp.Certificate),
		AttestationChainPEM: string(resp.Chain),
	}, nil
}

// Reset factory-resets the named PIV device. The caller must have invoked
// ConfirmReset immediately prior; otherwise ErrPIVResetNotConfirmed is
// returned without reaching the upstream xkms call. The flag is consumed
// on every call to prevent replay.
func (b *PIVBackend) Reset(ctx context.Context, device string) error {
	if err := b.ensureInitialised(); err != nil {
		return err
	}
	confirmed := b.resetConfirmed
	b.resetConfirmed = false
	if !confirmed {
		return ErrPIVResetNotConfirmed
	}
	backend := b.backendOr(device)
	if err := xkmssdk.ResetPIV(ctx, &xkmssdk.PIVResetDeviceRequest{
		Backend: backend,
		Confirm: true,
	}); err != nil {
		b.logger.Error(err, "op", "piv-reset", "backend", backend)
		return err
	}
	b.logger.Info("piv factory reset completed", "backend", backend)
	return nil
}

// ensureInitialised returns a typed error if the xkms PIV manager singleton
// is nil. We probe with an idempotent ListPIVSlots-equivalent: asking for the
// default backend's slots with an obviously-empty backend is the cheapest way
// to force-initialise or surface the error.
func (b *PIVBackend) ensureInitialised() error {
	// Using SetPIVBackendResolver(nil) would be the direct probe, but it
	// mutates state. Instead we attempt a no-op store lookup that triggers
	// the same error path without side-effects.
	if _, err := xkmsbackend.ListPIVSlots(context.Background(), &xkmstransport.ListPIVSlotsRequest{
		Backend: b.defaultBackend,
	}); err != nil {
		if errors.Is(err, xkmsbackend.ErrPIVNotInitialized) {
			return ErrPIVBackendUnavailable
		}
		// Other errors (e.g. backend-not-found) are benign — they still prove
		// the manager is initialised.
	}
	return nil
}

// pivSlotFromStatus translates an xkms PIVSlotStatus to the service-layer
// PIVSlot type.
func pivSlotFromStatus(s xkmstransport.PIVSlotStatus) daemon.PIVSlot {
	algo := daemon.PIVAlgorithmUnspecified
	if mapped, ok := pivAlgorithmReverseMap[s.Algorithm]; ok {
		algo = mapped
	}
	return daemon.PIVSlot{
		ID:             s.Slot,
		Name:           s.Name,
		Algorithm:      algo,
		HasKey:         s.HasKey,
		HasCertificate: s.HasCert,
	}
}
