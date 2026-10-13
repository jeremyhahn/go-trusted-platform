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
	"context"
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
// store handle. A store that cannot be opened is an
// ErrAttestationStoreUnavailable; the caller treats it as non-fatal —
// the daemon continues without the attestation surface and REST callers
// see the structured "service not configured" envelope.
func initAttestationServices(logger *logging.Logger, a *app.App) (*attestationServices, error) {
	// An unset platform directory would root the store at a relative
	// "attestation" directory under whatever the working directory is.
	if a == nil || a.PlatformDir == "" {
		return nil, ErrAttestationStoreUnavailable{Cause: ErrAttestationPlatformDirUnset{}}
	}
	root := filepath.Join(a.PlatformDir, "attestation")
	store, err := attestationstore.NewFileStore(root)
	if err != nil {
		return nil, ErrAttestationStoreUnavailable{Root: root, Cause: err}
	}
	// The daemon already holds the node's TPM for IDevID/IAK work; the
	// attestation service needs the same handle to produce quotes. Without
	// it every quote-producing operation answers ErrTPMSessionNotConfigured
	// — honest, but it means no node can attest (#387).
	var opts []attestationsvc.ServiceOption
	if a.TPM != nil {
		opts = append(opts, attestationsvc.WithTPM(a.TPM))
	}
	svc := attestationsvc.NewService(store, opts...)
	grpcSvc := daemon.NewAttestationServiceServer(svc, slog.Default())
	logger.Info("attestation service wired", "root", root, "quote_production", a.TPM != nil)
	return &attestationServices{GRPC: grpcSvc, Service: svc}, nil
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

// attestationWiring is everything wireAttestationOnConfig built. The
// webservices path reads the services, the SDN policy and the REST view
// of the reporting surface back out for its REST-only consumers; both
// paths call Stop on shutdown.
type attestationWiring struct {
	Services      *attestationServices
	SDNPolicy     *sdnPolicyComponents
	ReportingRest *restattestation.Reporting
	stop          func()
}

// Stop ends the reporting collector, when one was started.
func (w *attestationWiring) Stop() {
	if w == nil || w.stop == nil {
		return
	}
	w.stop()
}

// wireAttestationOnConfig builds the attestation backend and everything
// that hangs off it — the quarantine observer, the caller-admission
// policy and the reporting collector — and sets cfg.AttestationService
// and cfg.AttestationReporting. It is the one place both run paths build
// them (#544): the daemon serves the attestation RPCs over gRPC, Unix and
// MCP whether or not a webservices section exists, and a config left
// without a backend registers the FailedPrecondition stub.
//
// cfg.DeviceService, cfg.DeviceProfileService and cfg.CAService must be
// set first: the observer, the control-plane device and the collector
// read them.
func wireAttestationOnConfig(ctx context.Context, logger *logging.Logger, a *app.App, cfg *daemon.Config) *attestationWiring {
	w := &attestationWiring{}
	if a == nil || cfg == nil {
		return w
	}

	// Attestation store + service back the attestation RPCs, the REST
	// /api/v1/attestation/manifests surface and the per-enrollment capture
	// hook. A store that cannot be opened leaves the surface unconfigured.
	svcs, err := initAttestationServices(logger, a)
	if err != nil {
		logger.Warnf("%v; the attestation surface is not configured", err)
	}
	attachAttestationServiceToDaemonConfig(cfg, svcs)
	w.Services = svcs

	// Build the shared SDN flow-policy machinery (engine + zone flow manager)
	// once; the quarantine observer and the SDN enrollment hook both consume
	// it so port-policy state lives in a single engine. Nil when SDN or OVS
	// is unavailable.
	w.SDNPolicy = initSDNPolicy(a, logger.Slog())

	// Wire the quarantine observer: when both attestation and SDN-OVS are
	// available, failed attestations move devices to the quarantine zone and
	// successful re-attestations restore them. No-op when either subsystem is
	// absent so boot behavior is unchanged on nodes without OVS.
	quarantine := wireQuarantineObserver(svcs, w.SDNPolicy, cfg.DeviceService, logger)

	// Attestation reporting (#226): the collector on a control plane, and
	// on every node the caller policy for the quote routes. The policy is
	// built after the collector so the any-attested strategy can consult
	// this node's own report cache. One surface, shared by every listener
	// and by the gRPC/Unix and MCP transports.
	// The control plane is a device in its own registry (#472): it writes
	// its own record from its own TPM through the same registration the
	// ACME finalize hook uses, so the collector below attests it exactly
	// like a node. Runs before the collector because the collector needs
	// the resulting device id to resolve the control plane's own endpoint.
	controlPlaneDevice := initControlPlaneDevice(ctx, logger.Slog(), a, cfg)

	w.ReportingRest = initCallerPolicy(logger.Slog(), a, svcs)
	if rep := initReportingCollector(ctx, logger.Slog(), a, cfg, svcs, controlPlaneDevice); rep != nil {
		w.stop = rep.Stop
		w.ReportingRest = withCollectorSurface(logger.Slog(), w.ReportingRest, rep, a, svcs)
		cfg.AttestationReporting = rep.Handles
		if w.ReportingRest != nil && w.ReportingRest.Policy != nil {
			rep.Handles.Policy = w.ReportingRest.Policy
		}
	} else if w.ReportingRest != nil && w.ReportingRest.Policy != nil {
		cfg.AttestationReporting = &daemon.ReportingHandles{Policy: w.ReportingRest.Policy}
	}

	// Operator Enable/Disable Device (#250) enforces through the quarantine
	// manager and re-attests through the collector, so it is wired last.
	wireDeviceLifecycle(cfg, quarantine, reportingRefresher(cfg), logger.Slog())
	return w
}

// ErrAttestationStoreUnavailable reports that the attestation manifest
// store could not be opened. The daemon still starts, without an
// attestation backend.
type ErrAttestationStoreUnavailable struct {
	Root  string
	Cause error
}

func (e ErrAttestationStoreUnavailable) Error() string {
	if e.Root == "" {
		return "attestation: store unavailable: " + e.Cause.Error()
	}
	return "attestation: store " + e.Root + " unavailable: " + e.Cause.Error()
}

func (e ErrAttestationStoreUnavailable) Unwrap() error { return e.Cause }

// ErrAttestationPlatformDirUnset reports that no platform directory is
// configured to root the attestation store under.
type ErrAttestationPlatformDirUnset struct{}

func (ErrAttestationPlatformDirUnset) Error() string {
	return "attestation: no platform directory is configured"
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
