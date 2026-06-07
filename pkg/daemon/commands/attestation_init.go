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

package commands

import (
	"log/slog"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	attestationstore "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// attestationServices captures both the gRPC service and the
// underlying Service implementation so callers can wire the
// platform-internal capture hook (CaptureFromEnrollment) alongside
// the gRPC surface.
type attestationServices struct {
	GRPC    *daemon.AttestationServiceServer
	Service *attestationsvc.Service
}

// initAttestationServices stands up the manifest store, the
// platform Service, and the gRPC wrapper, all sharing a single
// store handle. Failure is non-fatal — the daemon continues without
// the attestation surface and REST callers see the structured
// "service not configured" envelope.
func initAttestationServices(logger *logging.Logger, a *app.App) *attestationServices {
	if a == nil {
		return nil
	}
	root := filepath.Join(a.PlatformDir, "attestation")
	store, err := attestationstore.NewFileStore(root)
	if err != nil {
		logger.Warnf("attestation: store unavailable: %v", err)
		return nil
	}
	svc := attestationsvc.NewService(store)
	grpcSvc := daemon.NewAttestationServiceServer(svc, slog.Default())
	logger.Info("attestation service wired", "root", root)
	return &attestationServices{GRPC: grpcSvc, Service: svc}
}

// attachAttestationServiceToDaemonConfig sets daemonConfig.AttestationService
// to the platform Service so daemon.New wires it into the gRPC
// server registration. No-op when the wiring is unavailable.
func attachAttestationServiceToDaemonConfig(cfg *daemon.Config, svcs *attestationServices) {
	if cfg == nil || svcs == nil || svcs.Service == nil {
		return
	}
	cfg.AttestationService = svcs.Service
}

// captureAdapter bridges the platform Service to the v1.AttestationCaptureSvc
// interface the registry hook chain expects. Defined here so the
// registry package doesn't import pkg/attestation/service.
type captureAdapter struct {
	svc *attestationsvc.Service
}

// CaptureManifest fulfills v1.AttestationCaptureSvc by translating
// the registry-side input shape into the service-side
// EnrollmentInput and invoking CaptureFromEnrollment.
func (c *captureAdapter) CaptureManifest(input v1.AttestationCaptureInput) error {
	if c == nil || c.svc == nil {
		return nil
	}
	_, err := c.svc.CaptureFromEnrollment(attestationsvc.EnrollmentInput{
		CN:            input.CN,
		ProductModel:  input.ProductModel,
		ProductSerial: input.ProductSerial,
		ClientIP:      input.ClientIP,
		EventLog:      input.EventLog,
		QuoteData:     input.QuoteData,
		Signature:     input.Signature,
		Nonce:         input.Nonce,
		PCRs:          input.PCRs,
		PCRDigest:     input.PCRDigest,
		MerkleRoot:    input.MerkleRoot,
		AKPublicKey:   input.AKPublicKey,
		IDevIDCert:    input.IDevIDCert,
	})
	return err
}

// attestationCaptureAdapter returns a v1.AttestationCaptureSvc bound
// to the supplied services bundle, or nil when no service is wired.
// The v1 package's AttestationCaptureSvc interface is satisfied
// structurally by captureAdapter.
func attestationCaptureAdapter(svcs *attestationServices) v1.AttestationCaptureSvc {
	if svcs == nil || svcs.Service == nil {
		return nil
	}
	return &captureAdapter{svc: svcs.Service}
}

// attestationEventReader returns the underlying store handle as the
// reader used by the REST /attestation/events surface. nil when no
// service is wired.
func attestationEventReader(svcs *attestationServices) restattestation.EventReader {
	if svcs == nil || svcs.Service == nil {
		return nil
	}
	return svcs.Service.Store()
}
