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

package app

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// bmcCertInitOptions bundles every dependency that
// initBMCCertManagement needs from the surrounding platformd boot
// context. Callers populate from their *App without this function
// having to reach into App's internals — keeps the orchestrator
// testable with in-process fakes.
type bmcCertInitOptions struct {
	// BMCConfig is the BMC identity platformd manages. Expected to
	// come from app.BMCConfig. A nil BMCConfig or a BMCConfig with
	// no Certificate block means "TLS management disabled for this
	// node" — initBMCCertManagement returns nil without error, so
	// callers can call it unconditionally at boot.
	BMCConfig *bmc.Config

	// NodeID is the platformd node's stable identifier. It is used
	// as the device ID in the CertTarget name ("bmc.<nodeID>"), as
	// the ACME identifier when the cert has no explicit CN SANs,
	// and as the scheduler NodeAffinity so the cert-renewal job
	// fires on this node only.
	NodeID string

	// ACMEIssuerFunc resolves the ACME issuer lazily; see the field of the same
	// name on issueBMCCertificateOptions for why capture-by-value cannot work
	// on a restart path.
	ACMEIssuerFunc func() ACMEIssuer

	// ACMEIssuer is the low-level go-trusted-ca ACME client wrapped
	// into the narrow ACMEIssuer interface. Pass nil to force the
	// local CA fallback path. Production callers typically pass
	// app.ACMEClient.
	ACMEIssuer ACMEIssuer

	// LocalCAIssuer is the platform CA for the local fallback path.
	// Required even when ACMEIssuer is set — issueBMCCertificateCore
	// validates this up front so callers catch configuration
	// mistakes at boot, not on first renewal. Production callers
	// typically pass app.CA.
	LocalCAIssuer LocalCAIssuer

	// DNSUpdater is the platform DNS service used to write dns-01
	// challenge TXT records. Required when ACMEIssuer is non-nil.
	// Production callers typically pass app.DNSService.
	DNSUpdater dnsUpdater

	// Hostmaster is the operator contact email folded into SANs
	// when Certificate.SANS is absent. Production callers typically
	// pass app.Hostmaster.
	Hostmaster string

	// Scheduler is the embedded quicbaas scheduler engine — wired
	// to the platform's own cluster-aware scheduler. See pkg/bmc
	// and P1 scheduler clustering fix for semantics.
	Scheduler SchedulerService

	// Registry holds the managed cert targets. Typically created
	// once per platformd boot via NewCertTargetRegistry and shared
	// with other cert-managed services (webservice TLS, etc.) so
	// the renewal handler iterates all of them in one sweep.
	Registry *CertTargetRegistry

	// Logger receives structured boot/renewal events. May be nil.
	Logger *slog.Logger

	// DNSTTL is the DNS-01 challenge TXT record TTL. Zero falls
	// back to the provider default (60s).
	DNSTTL int

	// OnCertIssued is the optional pre-publication hook propagated
	// into issueBMCCertificateOptions. See its doc comment there
	// for full semantics. nil = no-op.
	OnCertIssued func(ctx context.Context, leaf *x509.Certificate) error

	// OnCertDeployed is the optional post-deploy hook propagated
	// into issueBMCCertificateOptions. See its doc comment there
	// for full semantics. nil = no-op.
	OnCertDeployed func(ctx context.Context, leaf, ca *x509.Certificate) error

	// TrustRoots are the roots a certificate already on the BMC must chain to
	// before boot accepts it as one we issued. Nil means every boot reissues,
	// so the production wiring always supplies them.
	TrustRoots *x509.CertPool

	// RequireACME refuses to issue from the local CA when the BMC declares ACME.
	//
	// (*bmc.Config).validateCertBlock REQUIRES certificate.acme.challenge ==
	// "dns-01" whenever a BMC certificate is configured, so a validated config
	// always asked for ACME. Substituting the local CA puts a certificate on the
	// BMC signed by an authority the operator did not select -- a trust decision,
	// not a degradation, so the production wiring sets this and issuance fails
	// loudly instead. The renewal handler and job are registered before issuance
	// is attempted, so a refusal here costs this one target, never the sweep.
	RequireACME bool

	// DeployerOverride replaces the live AutoCertManager for both reading the
	// BMC's current certificate and deploying a new one. Production leaves it
	// nil; it exists so boot-path behaviour is testable without a live BMC.
	DeployerOverride bmcDeployer
}

// dnsUpdater is the narrow DNS service interface for dns-01 challenge
// TXT record management. The platform's *dns.Service satisfies this.
type dnsUpdater interface {
	AddRecord(ctx context.Context, name, recordType, value string, ttl int) error
	DeleteRecord(ctx context.Context, name, recordType string) error
}

// initBMCCertManagement wires BMC TLS certificate management for a
// platformd node. It:
//
//  1. Short-circuits if BMC TLS management is disabled (BMCConfig
//     nil or BMCConfig.Certificate nil) so callers can call it
//     unconditionally at boot.
//  2. Issues an initial certificate via issueBMCCertificateCore
//     (fresh ECDSA keypair -> CSR -> ACME dns-01 or local CA -> deploy
//     to BMC via AutoCertManager).
//  3. Registers the returned CertTarget in the registry so the
//     renewal handler picks it up.
//  4. Registers the platform.cert-renewal handler + per-node
//     recurring job via RegisterCertRenewal (idempotent -- re-runs
//     of boot leave the job alone).
//
// Called by InitCertManagement; not exported.
func initBMCCertManagement(ctx context.Context, opts bmcCertInitOptions) error {
	if opts.BMCConfig == nil || opts.BMCConfig.Certificate == nil {
		if opts.Logger != nil {
			opts.Logger.Info("bmc-cert-init: no BMC TLS management configured; skipping")
		}
		return nil
	}
	if opts.NodeID == "" {
		return ErrInitBMCCertMissingNodeID
	}
	if opts.Registry == nil {
		return ErrInitBMCCertMissingRegistry
	}
	if opts.Scheduler == nil {
		return ErrInitBMCCertMissingScheduler
	}
	if opts.LocalCAIssuer == nil {
		return ErrMissingLocalCAIssuer
	}

	deviceID := deriveBMCDeviceID(opts.BMCConfig, opts.NodeID)

	core := issueBMCCertificateOptions{
		ACMEIssuer:     opts.ACMEIssuer,
		ACMEIssuerFunc: opts.ACMEIssuerFunc,
		LocalCAIssuer:  opts.LocalCAIssuer,
		DNSUpdater:     opts.DNSUpdater,
		DNSTTL:         opts.DNSTTL,
		Hostmaster:     opts.Hostmaster,
		Logger:         opts.Logger,
		OnCertIssued:   opts.OnCertIssued,
		OnCertDeployed: opts.OnCertDeployed,
		Deployer:       opts.DeployerOverride,
		RequireACME:    opts.RequireACME,
		TrustRoots:     opts.TrustRoots,
	}

	// Build and register the target WITHOUT issuing. The target's closures need
	// nothing from an issuance, so this works for an already-provisioned BMC.
	target := buildBMCCertTarget(deviceID, opts.BMCConfig, core)
	if err := opts.Registry.Replace(target); err != nil {
		return ErrInitBMCCertRegister{DeviceID: deviceID, Cause: err}
	}

	// Register the handler + job BEFORE touching the BMC. Ordering is the whole
	// point: the BMC is a remote device that can be down, mid-reboot, or
	// unreachable at platformd start. If registration came after issuance, one
	// unreachable BMC would take renewal down for every OTHER target on the node
	// -- every webservice certificate would stop being renewed because a BMC did
	// not answer.
	if err := RegisterCertRenewal(ctx, CertRenewalRegistration{
		Scheduler: opts.Scheduler,
		Registry:  opts.Registry,
		NodeID:    opts.NodeID,
		Logger:    opts.Logger,
	}); err != nil {
		return err
	}

	// Provision only when the BMC is not already carrying the certificate this
	// configuration asks for.
	//
	// This function previously called issueBMCCertificateCore unconditionally.
	// With no production caller that was invisible; wired into boot it means a
	// fresh keypair, a fresh certificate and a BMC web-interface restart on
	// EVERY platformd restart. Reissuing a healthy certificate is not a no-op on
	// a BMC: it churns the device identity, invalidates the TOFU pin and
	// republishes DANE records for nothing.
	//
	// Expiry alone cannot make this decision, because an unprovisioned BMC
	// presents a long-lived factory certificate that would read as "not due
	// yet" forever -- hence the identity check.
	if reason, need := bmcNeedsInitialProvisioning(ctx, target, deviceID); need {
		if _, err := issueBMCCertificateCore(ctx, deviceID, opts.BMCConfig, core); err != nil {
			// Non-fatal: the target and the renewal job are already registered,
			// and the target's DueOverride reports an identity mismatch as due
			// regardless of expiry, so the next sweep genuinely does retry this.
			// (Expiry alone would not: a factory certificate is valid for years
			// and would be skipped every day.) Failing hard here would leave the
			// node with no renewal at all because one device was unavailable at
			// boot.
			if opts.Logger != nil {
				opts.Logger.Error("bmc-cert-init: initial certificate provisioning failed; "+
					"the renewal sweep will retry",
					"device_id", deviceID, "reason", reason, "error", err)
			}
			return nil
		}
		if opts.Logger != nil {
			opts.Logger.Info("bmc-cert-init: issued initial BMC certificate",
				"device_id", deviceID, "reason", reason)
		}
	} else if opts.Logger != nil {
		opts.Logger.Info("bmc-cert-init: BMC already carries the configured certificate; "+
			"leaving it in place for the renewal sweep", "device_id", deviceID)
	}

	if opts.Logger != nil {
		opts.Logger.Info("bmc-cert-init: BMC TLS management initialized",
			"device_id", deviceID,
			"node_id", opts.NodeID,
			"backend", opts.BMCConfig.Backend)
	}
	return nil
}

// CertManagementScheduler returns the in-process scheduler engine
// for cert renewal wiring, adapted to the SchedulerService interface
// InitCertManagement expects. Returns nil when the scheduler is not
// enabled on the embedded quicbaas service.
func (app *App) CertManagementScheduler() SchedulerService {
	svc := app.QuicBaaSService()
	if svc == nil {
		return nil
	}
	eng := svc.SchedulerEngine()
	if eng == nil {
		return nil
	}
	return eng
}

// InitCertManagement is the single-call platform-wide cert management
// wiring. It:
//
//  1. Ensures app.CertTargets (the registry) is initialized.
//  2. Registers the platform.cert-renewal scheduler handler + per-node
//     recurring job (idempotent -- re-runs of boot leave jobs alone).
//  3. Optionally initializes BMC TLS management when app.BMCConfig is
//     present (issues the initial cert, registers the target).
//
// Webservice cert targets register themselves during
// issueWebServiceCertificate -- this wrapper does not iterate them.
// Call this AFTER InitWebServer so webservice targets already exist
// in the registry.
//
// scheduler and nodeID must come from the platform's quicbaas
// integration: the embedded SchedulerEngine for scheduler and the
// local node's stable identifier (Raft node ID, hostname, or
// deployment-level tag) for nodeID.
//
// Typical caller shape (in pkg/daemon/commands/serve.go after
// InitWebServer returns):
//
//	if err := App.InitCertManagement(ctx, App.Scheduler, App.NodeID); err != nil {
//	    logger.Error(err, "cert management init failed")
//	    // fatal or non-fatal per deployment policy
//	}
func (app *App) InitCertManagement(ctx context.Context, scheduler SchedulerService, nodeID string) error {
	if scheduler == nil {
		return ErrCertRenewalMissingScheduler
	}
	if nodeID == "" {
		return ErrInitBMCCertMissingNodeID
	}

	// Ensure registry is live so downstream calls have somewhere to
	// register/read.
	reg := app.certTargets()

	// If BMC is configured, run the BMC-specific init which also
	// registers its target into the same registry.
	if app.BMCConfig != nil && app.BMCConfig.Certificate != nil {
		onIssued, onDeployed := app.buildBMCRenewalHooks()
		if err := initBMCCertManagement(ctx, bmcCertInitOptions{
			BMCConfig: app.BMCConfig,
			NodeID:    nodeID,
			// Resolved at issuance time, not captured now. On an ordinary
			// restart InitWebServer loads the existing certificate and skips
			// issueWebServiceCertificate -- the very thing that initializes
			// App.ACMEClient -- so capturing it here would freeze a nil issuer
			// into the target's Reissue closure and the BMC could never
			// converge, no matter how many sweeps ran.
			ACMEIssuerFunc: func() ACMEIssuer {
				if app.ACMEClient == nil {
					return nil
				}
				return app.ACMEClient
			},
			LocalCAIssuer: app.CA,
			DNSUpdater:    app.DNSService,
			Hostmaster:    app.Hostmaster,
			Scheduler:     scheduler,
			Registry:      reg,
			// (*logging.Logger).Slog() is nil-safe on a nil receiver, so this
			// degrades to no logging rather than panicking. Previously hardcoded
			// nil, which silenced BMC cert init entirely -- including its warning
			// that the configured ACME issuer is missing and the local CA is being
			// used instead.
			Logger: app.Logger.Slog(),
			// Roots a certificate already on the BMC must chain to before boot
			// accepts it as ours. Without these every restart reissues.
			TrustRoots: app.bmcTrustRoots(),
			// The config declares ACME (validation requires dns-01 whenever a
			// BMC certificate is configured), so refuse a local-CA substitution.
			RequireACME: app.BMCConfig.Certificate.ACME != nil &&
				app.BMCConfig.Certificate.ACME.Challenge != "",
			OnCertIssued:   onIssued,
			OnCertDeployed: onDeployed,
		}); err != nil {
			return err
		}
		return nil // BMC path internally calls RegisterCertRenewal
	}

	// No BMC configured -- register the renewal handler + job just
	// so webservice targets (or any future target kind) still get
	// swept.
	return RegisterCertRenewal(ctx, CertRenewalRegistration{
		Scheduler: scheduler,
		Registry:  reg,
		NodeID:    nodeID,
	})
}

// buildBMCRenewalHooks constructs the OnCertIssued and OnCertDeployed
// hook closures for the platform's BMC certificate renewal lifecycle.
// Both hooks are nil-safe with respect to optional dependencies (DANE
// publisher, pin store, device service) so the platform can boot
// without DNS or a device-service and still renew certificates.
//
// OnCertIssued implements RFC 7671 §8.1 pre-publication: the new
// DANE-EE TLSA record is added alongside existing records BEFORE the
// new certificate is deployed, so DNS validators never see an
// unmatched cert during the transition window. Failure is non-fatal.
//
// OnCertDeployed:
//  1. Updates the stored TOFU SPKI pin for the BMC endpoint (host:443).
//  2. Re-publishes the full TLSA record set (DANE-TA from the CA +
//     DANE-EE per policy) under the device's enrolled DNS name, which is
//     loaded fresh from Device.BMCEnrollment.DNSName at call time so the
//     hook works correctly even when enrollment runs after this wiring
//     call.
//
// When the device has no enrolled DNS name, DANE calls are skipped but
// the TOFU pin is still updated (pin is keyed by host, not by DNS name).
func (app *App) buildBMCRenewalHooks() (
	onIssued func(context.Context, *x509.Certificate) error,
	onDeployed func(context.Context, *x509.Certificate, *x509.Certificate) error,
) {
	// Resolve DANE publisher once — nil when DANE is not configured.
	var dp daneRenewalPublisher
	if app.DNSConfig != nil &&
		app.DNSConfig.DANE != nil &&
		app.DNSConfig.DANE.Enabled &&
		app.DNSService != nil {
		dp = app.ensureDANEPublisher()
	}

	// Resolve the internal DNS zone name.
	internalZone := ""
	if app.DNSConfig != nil && app.DNSConfig.InternalServer != nil {
		internalZone = app.DNSConfig.InternalServer.Zone.Name
	}

	// Resolve pin-store factory once — nil when SDK client unavailable.
	pinUpdater := app.bmcPinUpdater()

	// BMC host address for pin keying (host only, no port in BMC address field).
	bmcHost := ""
	if app.BMCConfig != nil {
		bmcHost = app.BMCConfig.Address
	}

	// dnsNameLoader loads the enrolled DNS name fresh at each hook
	// call so enrollments that happen after boot are reflected. It is
	// keyed by the BMC host so the right device record is matched.
	dnsNameLoader := app.buildBMCDNSNameLoader(bmcHost)

	// OnCertIssued: pre-publish the new DANE-EE record before deploy.
	onIssued = func(issuedCtx context.Context, leaf *x509.Certificate) error {
		if dp == nil || internalZone == "" {
			return nil
		}
		dnsName := dnsNameLoader(issuedCtx)
		if dnsName == "" {
			if app.Logger != nil {
				app.Logger.Debug("bmc-cert renewal: no enrolled DNS name; skipping pre-publish",
					"host", bmcHost)
			}
			return nil
		}
		return dp.PrePublishRollover(issuedCtx, leaf, dnsName, 443, internalZone)
	}

	// OnCertDeployed: update TOFU pin + full TLSA re-publish after deploy.
	onDeployed = func(deployedCtx context.Context, leaf, ca *x509.Certificate) error {
		// Step 1: update TOFU SPKI pin (keyed by host, independent of DNS).
		if bmcHost != "" && pinUpdater != nil {
			spki := certSPKISHA256(leaf)
			fp := certDERSHA256(leaf)
			if err := pinUpdater(deployedCtx, bmcHost, 443, spki, fp); err != nil {
				if app.Logger != nil {
					app.Logger.Errorf("bmc-cert renewal: TOFU pin update failed: host=%s err=%v",
						bmcHost, err)
				}
				// Non-fatal per design: return the error so the caller
				// (issueBMCCertificateCore) logs it at Error level.
				return err
			}
		}

		// Step 2: full TLSA re-publish.
		if dp == nil || internalZone == "" {
			return nil
		}
		dnsName := dnsNameLoader(deployedCtx)
		if dnsName == "" {
			if app.Logger != nil {
				app.Logger.Debug("bmc-cert renewal: no enrolled DNS name; skipping TLSA re-publish",
					"host", bmcHost)
			}
			return nil
		}
		return dp.PublishForCertificate(deployedCtx, leaf, ca, dnsName, 443, internalZone)
	}

	return onIssued, onDeployed
}

// daneRenewalPublisher is the narrow subset of *bootstrap.DANEPublisher
// required by the renewal hooks. Unit tests substitute a fake.
type daneRenewalPublisher interface {
	PrePublishRollover(ctx context.Context, newCert *x509.Certificate, hostname string, port uint16, zoneName string) error
	PublishForCertificate(ctx context.Context, leafCert, caCert *x509.Certificate, hostname string, port uint16, zoneName string) error
}

// buildBMCDNSNameLoader returns a closure that loads the enrolled DNS
// name for the BMC at the given host from the Device entities at call
// time. The device is matched by BMCEnrollment.Host — the join key the
// enrollment ceremony stamps — so on a control plane holding many
// enrolled devices the renewal hooks never publish under another
// device's name. An empty string is returned when the device service
// is unavailable, no device matches the host, or the matched
// enrollment has no DNS name.
//
// The lookup is best-effort — failures are silently swallowed
// because the hooks are non-fatal and the DNS name is only needed for
// DANE publication. The trailing dot is stripped before returning.
func (app *App) buildBMCDNSNameLoader(bmcHost string) func(ctx context.Context) string {
	return func(ctx context.Context) string {
		if bmcHost == "" {
			return ""
		}
		sr := app.ServiceRegistry()
		if sr == nil {
			return ""
		}
		svc := sr.DeviceService()
		if svc == nil {
			return ""
		}
		page, err := svc.Page(ctx, datastore.NewPageQuery())
		if err != nil {
			return ""
		}
		return enrolledDNSNameForHost(page.Entities, bmcHost)
	}
}

// enrolledDNSNameForHost returns the enrolled DNS name (trailing dot
// stripped) of the device whose BMCEnrollment.Host matches bmcHost, or
// an empty string when no device matches or the matched enrollment has
// no DNS name. Pure function — testable without a device service.
func enrolledDNSNameForHost(devices []*entities.Device, bmcHost string) string {
	for _, dev := range devices {
		if dev == nil || dev.BMCEnrollment == nil || dev.BMCEnrollment.Host != bmcHost {
			continue
		}
		return strings.TrimSuffix(dev.BMCEnrollment.DNSName, ".")
	}
	return ""
}

// bmcPinUpdater returns a closure that persists an updated TOFU pin
// using the same quicbaas.NewTOFUPinStore path the enroll ceremony
// uses. Returns nil when the SDK client is unavailable.
func (app *App) bmcPinUpdater() func(ctx context.Context, host string, port int, spkiPin, certFP string) error {
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok || dbFactory == nil {
		return nil
	}
	sdkClient := dbFactory.SDKClient()
	if sdkClient == nil {
		return nil
	}
	pinStore, err := quicbaas.NewTOFUPinStore(sdkClient)
	if err != nil {
		return nil
	}
	return func(ctx context.Context, host string, port int, spkiPin, certFP string) error {
		return pinStore.Put(ctx, &trust.TOFUPin{
			Host:            host,
			Port:            port,
			SPKISHA256:      spkiPin,
			CertFingerprint: certFP,
			FirstSeen:       time.Now().UTC(),
			Source:          "renewal",
		})
	}
}

// deriveBMCDeviceID produces a stable device ID for the CertTarget
// Name. Prefers the BMC's CN (unique, stable) when present; falls
// back to the BMC address with colons/dots escaped; last resort is
// the NodeID itself.
func deriveBMCDeviceID(cfg *bmc.Config, nodeID string) string {
	if cfg == nil {
		return nodeID
	}
	if cfg.Certificate != nil {
		if cn := cfg.Certificate.Subject.CommonName; cn != "" {
			return cn
		}
	}
	if cfg.Address != "" {
		s := strings.NewReplacer(":", "-", ".", "-").Replace(cfg.Address)
		return fmt.Sprintf("%s-%d", s, cfg.Port)
	}
	return nodeID
}

// bmcNeedsInitialProvisioning reports whether boot should issue and deploy a
// certificate now, and why.
//
// Renewal of an already-provisioned BMC is the scheduled sweep's job; boot only
// covers the case the sweep cannot reach, namely a BMC that is not carrying our
// certificate at all.
func bmcNeedsInitialProvisioning(
	ctx context.Context,
	target *CertTarget,
	deviceID string,
) (reason string, need bool) {

	cert, err := target.Current(ctx)
	if err == nil && cert == nil {
		err = ErrNilCurrentCertificate{}
	}

	// Delegate to the target's own due rule rather than re-deciding here.
	//
	// Boot and the scheduled sweep must answer "is this the certificate we
	// want?" identically. Implementing the rule twice invites exactly one bug:
	// someone tightens one copy, and boot then provisions a BMC the sweep
	// considers fine (or the reverse), with the disagreement visible only as a
	// device that flaps or never converges. One implementation, two callers.
	if target.DueOverride == nil {
		// No due rule to consult: an unreadable endpoint still needs issuing,
		// but a readable one cannot be judged, so leave it to the sweep.
		if err != nil {
			return "no readable certificate on the BMC: " + err.Error(), true
		}
		return "", false
	}

	due, why := target.DueOverride(ctx, cert, err)
	if !due {
		return "", false
	}
	// cert is nil whenever the read failed, so the subject is only available on
	// the readable path.
	if cert != nil {
		return why + " (subject " + cert.Subject.CommonName + ")", true
	}
	return why, true
}

// bmcTrustRoots returns the roots a certificate found on a BMC must chain to
// before it is accepted as one this platform issued.
//
// Both issuance modes have to be covered. A BMC configured for ACME dns-01
// receives a certificate from the public ACME directory's CA, which lives in the
// system trust store; the local-CA fallback produces one signed by the platform
// root. A pool missing either would classify a legitimately-issued certificate
// as foreign and reissue it on every restart.
//
// It always returns a usable pool, never nil -- but that pool may be EMPTY when
// the system store cannot be read and no platform CA is loaded. An empty pool
// verifies nothing, so bmcCertMatchesConfiguredIdentity treats every deployed
// certificate as not ours and the node reissues. That is the safe direction: the
// cost is a redundant reissue, whereas trusting a certificate that could not be
// checked is silent and permanent.
func (app *App) bmcTrustRoots() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		app.Logger.Warn("cert renewal: cannot load system roots; BMC certificate "+
			"provenance will fall back to the platform CA only", "error", err)
		pool = x509.NewCertPool()
	}
	if app.CA == nil {
		return pool
	}
	rootCert, err := app.CA.TrustedRoot()
	if err != nil {
		app.Logger.Warn("cert renewal: cannot load the platform trusted root; a "+
			"locally-issued BMC certificate will not be recognised as ours and "+
			"will be reissued", "error", err)
		return pool
	}
	if rootCert != nil {
		pool.AddCert(rootCert)
	}
	return pool
}
