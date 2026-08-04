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

package v1

import (
	"fmt"
	"log/slog"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
)

// AttestationCaptureInput is the per-enrollment evidence the
// registry.go capture hook hands off to the platform attestation
// service. Mirrors attestation/service.EnrollmentInput without the
// import to keep the package boundary one-way.
type AttestationCaptureInput struct {
	CN            string
	ProductModel  string
	ProductSerial string
	ClientIP      string
	EventLog      []byte
	QuoteData     []byte
	Signature     []byte
	Nonce         []byte
	PCRs          map[int][]byte
	PCRDigest     []byte
	MerkleRoot    []byte
	AKPublicKey   []byte
	IDevIDCert    []byte
}

// AttestationCaptureSvc is the narrow interface registry.go uses to
// hand captured evidence to the platform attestation service. The
// concrete implementation in pkg/attestation/service stores a
// HostManifest + emits a manifest_captured event.
//
// CaptureManifest is called from inside the ACME finalize hook chain;
// returning an error aborts finalization, so the implementation
// SHOULD swallow non-fatal storage hiccups (e.g. transient disk
// pressure) and only return errors that signal a true integrity
// problem with the captured evidence.
type AttestationCaptureSvc interface {
	CaptureManifest(input AttestationCaptureInput) error
}

// NewAttestationManifestCaptureHook returns an ACME finalize hook
// that turns the captured TCG enrollment evidence into a
// HostManifest via the platform attestation service. Mirrors
// NewAttestationImportHook (which writes the raw blobs into the CA
// store) — the two hooks coexist: the CA captures raw evidence for
// forensics, the manifest service captures the structured form for
// the WebUI + verification surfaces.
func NewAttestationManifestCaptureHook(svc AttestationCaptureSvc, logger *slog.Logger) trustedca.ACMEOrderFinalizeHook {
	return func(ctx *trustedca.ACMEOrderFinalizeHookContext) error {
		if svc == nil {
			return nil
		}
		if !ctx.IsTCGCSR || ctx.TCGData == nil {
			return nil
		}
		cn := ""
		if ctx.Certificate != nil {
			cn = ctx.Certificate.Subject.CommonName
		}
		input := AttestationCaptureInput{
			CN:            cn,
			ProductModel:  ctx.TCGData.ProductModel,
			ProductSerial: ctx.TCGData.ProductSerial,
			ClientIP:      ctx.ClientIP,
			EventLog:      ctx.TCGData.EventLog,
		}
		if len(ctx.TCGData.ProdCaData) > 0 {
			prodCaData, err := xkmssdk.UnpackProdCaData(ctx.TCGData.ProdCaData)
			if err != nil {
				logger.Warn("attestation capture: failed to unpack ProdCaData",
					slog.String("cn", cn), slog.String("error", err.Error()))
			} else if prodCaData != nil {
				quote := prodCaData.ToQuote()
				input.QuoteData = quote.Quoted
				input.Signature = quote.Signature
				input.Nonce = quote.Nonce
				if len(quote.PCRs) > 0 {
					// quote.PCRs is the raw concatenated PCR digest blob
					// the platform produces during enrollment. Stash it
					// as the PCRDigest field for downstream verifiers
					// + split into per-index entries on the manifest's
					// Host.PCRs slice when the bank width is known.
					input.PCRDigest = quote.PCRs
					input.PCRs = parsePCRBlob(quote.PCRs)
				}
			}
		}
		if err := svc.CaptureManifest(input); err != nil {
			logger.Warn("attestation capture: failed to store manifest",
				slog.String("cn", cn), slog.String("error", err.Error()))
		} else {
			logger.Info("attestation manifest captured", slog.String("cn", cn))
		}
		return nil
	}
}

// parsePCRBlob best-effort splits a serialized PCR blob into a
// per-index map. The on-wire representation produced by the existing
// quote pipeline is the TPM2 PCR_Read output: a sequence of digests
// each in their natural hash length. Phase 3 first-ship assumes
// SHA-256 (32 bytes per digest) starting at PCR 0 — the platform
// only requests SHA-256 banks via the existing config — and treats
// unrecognized lengths as "no individual PCRs available" rather than
// fabricating values. The manifest store still captures the full
// blob via PCRDigest so downstream verifiers have the raw bytes.
func parsePCRBlob(blob []byte) map[int][]byte {
	const sha256Len = 32
	if len(blob) == 0 || len(blob)%sha256Len != 0 {
		return nil
	}
	out := make(map[int][]byte, len(blob)/sha256Len)
	for i := 0; i*sha256Len < len(blob); i++ {
		end := (i + 1) * sha256Len
		v := make([]byte, sha256Len)
		copy(v, blob[i*sha256Len:end])
		out[i] = v
	}
	return out
}

// ensureNonEmptyHookContext is a lint-shield against accidental nil
// derefs when extending the hook. Logs a debug line so a future
// refactor doesn't silently produce empty manifests.
func ensureNonEmptyHookContext(ctx *trustedca.ACMEOrderFinalizeHookContext, logger *slog.Logger) bool {
	if ctx == nil {
		logger.Debug("attestation capture: nil hook context")
		return false
	}
	if !ctx.IsTCGCSR {
		return false
	}
	if ctx.Certificate == nil {
		logger.Warn(fmt.Sprintf("attestation capture: missing certificate in hook context"))
		return false
	}
	return true
}
