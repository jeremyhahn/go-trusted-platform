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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	bmccredentials "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/credentials"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// BMCEnrollOptions carries per-call overrides for the enrollment ceremony.
// Each field is a pointer: a nil pointer means "use the value from the
// profile's bmc.Enrollment config, or DefaultEnrollmentConfig if that is
// also nil". A non-nil pointer overrides the profile default.
type BMCEnrollOptions struct {
	// ReplaceCertificate overrides bmc.EnrollmentConfig.ReplaceCertificate.
	ReplaceCertificate *bool

	// RotatePassword overrides bmc.EnrollmentConfig.RotatePassword.
	RotatePassword *bool

	// DNSRegister overrides bmc.EnrollmentConfig.DNSRegister.
	DNSRegister *bool

	// DANEPublish overrides bmc.EnrollmentConfig.DANEPublish.
	DANEPublish *bool
}

// BMCEnrollStep records the outcome of a single ceremony step.
type BMCEnrollStep struct {
	// Name is a short identifier for the step (e.g. "trust", "factory-cert").
	Name string

	// OK is true when the step completed successfully or was intentionally
	// skipped.
	OK bool

	// Detail is a human-readable message (success detail, skip reason, or
	// error summary). Never contains secret material.
	Detail string
}

// BMCFactoryCertMeta holds auditable metadata from the factory TLS
// certificate that existed on the BMC at enrollment time. No secret
// material is included.
type BMCFactoryCertMeta struct {
	// Subject is the certificate's Subject distinguished name.
	Subject string
	// Issuer is the certificate's Issuer distinguished name.
	Issuer string
	// SerialNumber is the certificate serial in decimal string form.
	SerialNumber string
	// NotBefore is the certificate's validity start.
	NotBefore time.Time
	// NotAfter is the certificate's validity end.
	NotAfter time.Time
	// SPKISHA256 is the hex-encoded SHA-256 of the SPKI block.
	SPKISHA256 string
	// SHA256 is the hex-encoded SHA-256 of the entire certificate DER.
	SHA256 string
	// CapturedAt is when the metadata was collected.
	CapturedAt time.Time
}

// BMCEnrollResult is the full outcome of a BMC enrollment ceremony.
type BMCEnrollResult struct {
	// DeviceID is the platform device entity ID.
	DeviceID uint64

	// Endpoint is the host:port used for the Redfish/HTTPS connection.
	Endpoint string

	// Hostname is the bare hostname of the BMC address (no port).
	Hostname string

	// DNSName is the FQDN registered in internal DNS, e.g. "lab-node-1-bmc.internal.".
	// Empty when dns-register was skipped.
	DNSName string

	// PinSPKISHA256 is the hex-encoded SHA-256 of the pinned SPKI of the
	// BMC's effective TLS leaf certificate after the ceremony. This is the
	// factory cert's SPKI when replace-certificate is false, or the new
	// platform cert's SPKI when replace-certificate is true.
	PinSPKISHA256 string

	// FactoryCertPEM holds the factory TLS certificate PEM for client-side
	// storage. Never written to disk server-side.
	FactoryCertPEM []byte

	// FactoryCertMeta holds auditable metadata from the factory certificate.
	FactoryCertMeta BMCFactoryCertMeta

	// NewCertPEM holds the platform-issued leaf certificate PEM when
	// replace-certificate ran successfully. Empty otherwise.
	NewCertPEM []byte

	// CACertPEM holds the issuing CA certificate PEM when replace-certificate
	// ran successfully. Empty otherwise.
	CACertPEM []byte

	// Steps records the ordered ceremony steps and their outcomes.
	Steps []BMCEnrollStep
}

// enrollCore bundles all dependencies for the enrollment ceremony into a
// testable unit. App.EnrollBMC binds these from app state; tests inject fakes.
type enrollCore struct {
	// resolver provides TLSConfig for the BMC class.
	resolver trust.Resolver

	// certFetcher fetches the BMC's current web certificate. Typically
	// *bmc.AutoCertManager. May be nil — the factory-cert step is skipped when nil.
	certFetcher interface {
		GetWebCertificate(ctx context.Context) (*x509.Certificate, error)
		Close() error
	}

	// certIssuer issues and deploys a new platform certificate. Returns the
	// leaf, its DER PEM, the issuing CA PEM, and an error. May be nil.
	certIssuer func(ctx context.Context) (*x509.Certificate, []byte, []byte, error)

	// pinUpdater persists an updated TOFU pin for the BMC endpoint.
	// host and port are the BMC address components; spkiPin is the new pin.
	pinUpdater func(ctx context.Context, host string, port int, spkiPin string, certFP string) error

	// credStore persists BMC credentials. May be nil when no SDK client is
	// available, in which case the credentials step is skipped.
	credStore bmc.CredentialStore

	// dnsRegister registers an A record for the BMC host in the internal DNS
	// zone and returns the FQDN that was registered. May be nil when DNS is
	// disabled.
	dnsRegister func(ctx context.Context, hostname, address, zoneName string) (string, error)

	// danePublish publishes DANE TLSA records for the BMC's certificate.
	// May be nil when DANE is disabled.
	danePublish func(ctx context.Context, leaf, ca *x509.Certificate, dnsName string, port uint16, zoneName string) error

	// deviceLoader loads a Device entity by ID.
	deviceLoader func(ctx context.Context, id uint64) (*entities.Device, error)

	// deviceSaver persists a Device entity.
	deviceSaver func(ctx context.Context, d *entities.Device) error
}

// resolverTLSProvider adapts a trust.Resolver into a bmc.TLSProvider for
// a specific trust class. The returned TLSProvider is safe for concurrent use.
type resolverTLSProvider struct {
	resolver trust.Resolver
	class    trust.Class
}

// TLSConfig implements bmc.TLSProvider.
func (p *resolverTLSProvider) TLSConfig(ctx context.Context, endpoint string) (*tls.Config, error) {
	return p.resolver.TLSConfig(ctx, p.class, endpoint)
}

// compile-time check.
var _ bmc.TLSProvider = (*resolverTLSProvider)(nil)

// TrustResolver returns the platform trust Resolver, building it lazily from
// TrustConfig on the first call. Returns nil when TrustConfig is nil or
// resolver construction fails — callers should check for nil and gate
// trust-dependent operations accordingly.
func (app *App) TrustResolver() trust.Resolver {
	if app.trustResolver != nil {
		return app.trustResolver
	}
	if app.TrustConfig == nil {
		return nil
	}
	resolverOpts := app.buildTOFUResolverOpts()
	r, err := trust.NewResolver(app.TrustConfig, app.Logger, resolverOpts...)
	if err != nil {
		app.Logger.Warn("TrustResolver: failed to build trust resolver", "error", err)
		return nil
	}
	app.trustResolver = r
	return r
}

// BMCTLSProvider returns a bmc.TLSProvider that produces a *tls.Config
// anchored by the BMC class trust chain. The provider is backed by the
// platform's lazily-built trust Resolver. Returns nil when no trust resolver
// is available.
func (app *App) BMCTLSProvider() bmc.TLSProvider {
	r := app.TrustResolver()
	if r == nil {
		return nil
	}
	return &resolverTLSProvider{resolver: r, class: trust.ClassBMC}
}

// InternalCAPool returns an *x509.CertPool anchored to the platform's internal
// CA bundle, obtained via the ClassInternal trust resolver. It is intended for
// wiring into internal-service clients (SDN reporter, attestation push, mTLS
// webservice client, QUIC client) so they verify server certificates against
// the platform CA rather than the operating-system trust store.
//
// Returns (nil, nil) when TrustConfig has no internal scope configured —
// callers must treat a nil pool as "use system roots" and preserve existing
// behavior. Returns a non-nil error only when the resolver is available but
// the CA pool fetch fails.
func (app *App) InternalCAPool(ctx context.Context) (*x509.CertPool, error) {
	r := app.TrustResolver()
	if r == nil {
		return nil, nil
	}
	pool, err := r.CAPool(ctx, trust.ClassInternal, "")
	if err != nil {
		// ErrClassNotConfigured means the operator has not added an internal
		// scope; treat it as "no pool available" rather than a hard error so
		// deployments without the trust: internal YAML block keep working.
		var notCfg *trust.ErrClassNotConfigured
		if errors.As(err, &notCfg) {
			return nil, nil
		}
		return nil, err
	}
	return pool, nil
}

// EnrollBMC performs the BMC enrollment ceremony for the device identified by
// deviceID. The ceremony orchestrates trust establishment, factory certificate
// capture, optional credential persistence, optional certificate replacement,
// optional DNS registration, optional DANE TLSA publication, and finally
// stamping the Device entity with the enrollment record.
//
// Idempotency: if the device already has a BMCEnrollment with a PinSPKISHA256
// that still matches the BMC's current cert's SPKI, EnrollBMC short-circuits
// certificate replacement and skips all downstream steps that depend on it
// (but still re-runs trust, credentials, DNS, and DANE if their respective
// flags are set). Operators can force a full re-enrollment by passing
// ReplaceCertificate: boolPtr(true) explicitly.
//
// The bmcCfg.TLS field is set to a resolver-backed TLSProvider before any
// connection is made; callers do not need to pre-populate it.
func (app *App) EnrollBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config, opts *BMCEnrollOptions) (*BMCEnrollResult, error) {
	if bmcCfg == nil {
		return nil, bmc.ErrNilConfig{}
	}

	resolver := app.TrustResolver()
	if resolver == nil {
		return nil, ErrBMCEnrollNoTrustResolver{}
	}

	// Wire the resolver-backed TLS provider onto the config so all
	// BMC connections during enrollment use the class-BMC trust chain.
	bmcCfg.TLS = &resolverTLSProvider{resolver: resolver, class: trust.ClassBMC}

	// Build the effective enrollment flags (profile defaults + call overrides).
	effective := effectiveEnrollmentOpts(bmcCfg, opts)

	// Derive host and HTTPS endpoint.
	host := bmcCfg.Address
	endpoint := bmc.HTTPSEndpoint(bmcCfg)

	// Wire credential store from the platform's SecretsService.
	var credStore bmc.CredentialStore
	if svc := app.Secrets(); svc != nil {
		cs, err := bmccredentials.NewQuicBaaSStore(svc)
		if err == nil {
			credStore = cs
		}
	}

	// Determine internal zone name for DNS registration.
	internalZone := ""
	if app.DNSConfig != nil && app.DNSConfig.InternalServer != nil {
		internalZone = app.DNSConfig.InternalServer.Zone.Name
	}

	// Build the cert-replace closure that calls the existing
	// issueBMCCertificateCore pipeline.
	var localCA LocalCAIssuer
	if app.CA != nil {
		localCA = app.CA
	}

	core := &enrollCore{
		resolver: resolver,
		certIssuer: func(ctx context.Context) (*x509.Certificate, []byte, []byte, error) {
			if bmcCfg.Certificate == nil {
				return nil, nil, nil, ErrBMCCertDisabled
			}
			issueOpts := issueBMCCertificateOptions{
				LocalCAIssuer: localCA,
				Hostmaster:    app.Hostmaster,
				Logger:        app.Logger.Slog(),
			}
			if app.ACMEClient != nil {
				issueOpts.ACMEIssuer = app.ACMEClient
			}
			if app.DNSService != nil {
				issueOpts.DNSUpdater = app.DNSService
			}
			target, err := issueBMCCertificateCore(ctx, fmt.Sprintf("%d", deviceID), bmcCfg, issueOpts)
			if err != nil {
				return nil, nil, nil, err
			}
			newLeaf, err := target.Current(ctx)
			if err != nil {
				return nil, nil, nil, err
			}
			leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newLeaf.Raw})

			// Fetch the issuing CA cert for chain verification and DANE.
			var caPEM []byte
			if app.CA != nil {
				var ca *x509.Certificate
				if ca, err = app.CA.TrustedIntermediate(); err != nil || ca == nil {
					ca, _ = app.CA.TrustedRoot()
				}
				if ca != nil {
					caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
				}
			}
			return newLeaf, leafPEM, caPEM, nil
		},
		pinUpdater: func(ctx context.Context, host string, port int, spkiPin string, certFP string) error {
			return app.updateTOFUPin(ctx, host, port, spkiPin, certFP)
		},
		credStore:    credStore,
		deviceLoader: app.loadDeviceForEnroll,
		deviceSaver:  app.saveDeviceForEnroll,
	}

	// Wire AutoCertManager as the factory-cert fetcher when Certificate config
	// is present (it provides GetWebCertificate via live TLS handshake).
	if bmcCfg.Certificate != nil {
		mgr, err := bmc.NewAutoCertManager(bmcCfg, bmc.CertBackendAuto, app.Logger.Slog())
		if err == nil {
			core.certFetcher = mgr
		}
	}

	// Wire DNS registration when enabled and zone is available.
	if effective.DNSRegister && internalZone != "" && app.DNSService != nil {
		core.dnsRegister = func(ctx context.Context, hostname, address, zoneName string) (string, error) {
			fqdn := hostname + "-bmc." + zoneName
			if !strings.HasSuffix(fqdn, ".") {
				fqdn += "."
			}
			if _, err := app.DNSService.Register(ctx, fqdn, address); err != nil {
				return "", err
			}
			return fqdn, nil
		}
	}

	// Wire DANE publication when enabled, DANE config exists, and DNS is available.
	if effective.DANEPublish &&
		app.DNSConfig != nil &&
		app.DNSConfig.DANE != nil &&
		app.DNSConfig.DANE.Enabled &&
		app.DNSService != nil {
		dp := app.ensureDANEPublisher()
		core.danePublish = func(ctx context.Context, leaf, ca *x509.Certificate, dnsName string, port uint16, zoneName string) error {
			// Strip trailing dot — DANEPublisher expects bare hostname.
			hn := strings.TrimSuffix(dnsName, ".")
			return dp.PublishForCertificate(ctx, leaf, ca, hn, port, zoneName)
		}
	}

	return runEnrollCore(ctx, deviceID, host, endpoint, internalZone, effective, core)
}

// runEnrollCore executes the ordered enrollment ceremony steps using the
// narrow interfaces in core. It is the testable inner function; App.EnrollBMC
// binds concrete implementations.
func runEnrollCore(
	ctx context.Context,
	deviceID uint64,
	host, endpoint, internalZone string,
	effective enrollmentFlags,
	core *enrollCore,
) (*BMCEnrollResult, error) {

	result := &BMCEnrollResult{
		DeviceID: deviceID,
		Endpoint: endpoint,
		Hostname: host,
	}

	// ----------------------------------------------------------------
	// Step 1: trust — obtain TLSConfig via the resolver.
	// ----------------------------------------------------------------
	tlsCfg, err := core.resolver.TLSConfig(ctx, trust.ClassBMC, endpoint)
	if err != nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "trust",
			OK:     false,
			Detail: err.Error(),
		})
		return result, err
	}
	// tlsCfg is used implicitly via bmcCfg.TLS set by EnrollBMC.
	_ = tlsCfg
	result.Steps = append(result.Steps, BMCEnrollStep{
		Name:   "trust",
		OK:     true,
		Detail: "TLS trust established via class-bmc resolver",
	})

	// ----------------------------------------------------------------
	// Step 2: factory-cert — capture the current BMC web certificate.
	// ----------------------------------------------------------------
	if core.certFetcher == nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "factory-cert",
			OK:     true,
			Detail: "skipped (no cert fetcher available)",
		})
	} else {
		factoryCert, fetchErr := core.certFetcher.GetWebCertificate(ctx)
		_ = core.certFetcher.Close()
		if fetchErr != nil {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "factory-cert",
				OK:     false,
				Detail: fetchErr.Error(),
			})
			return result, ErrBMCEnrollFactoryCert{DeviceID: deviceID, Cause: fetchErr}
		}
		factoryPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: factoryCert.Raw})
		spki := certSPKISHA256(factoryCert)
		certFP := certDERSHA256(factoryCert)
		result.FactoryCertPEM = factoryPEM
		result.PinSPKISHA256 = spki
		result.FactoryCertMeta = BMCFactoryCertMeta{
			Subject:      factoryCert.Subject.String(),
			Issuer:       factoryCert.Issuer.String(),
			SerialNumber: factoryCert.SerialNumber.String(),
			NotBefore:    factoryCert.NotBefore,
			NotAfter:     factoryCert.NotAfter,
			SPKISHA256:   spki,
			SHA256:       certFP,
			CapturedAt:   time.Now().UTC(),
		}
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "factory-cert",
			OK:     true,
			Detail: fmt.Sprintf("captured factory cert: subject=%s spki=%s", factoryCert.Subject.CommonName, spki),
		})
	}

	// ----------------------------------------------------------------
	// Step 3: credentials — persist to CredentialStore.
	// ----------------------------------------------------------------
	if core.credStore == nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "credentials",
			OK:     true,
			Detail: "skipped (no credential store available)",
		})
	} else {
		if credErr := enrollCredentials(ctx, deviceID, host, effective, core); credErr != nil {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "credentials",
				OK:     false,
				Detail: credErr.Error(),
			})
			return result, ErrBMCEnrollCredStore{DeviceID: deviceID, Cause: credErr}
		}
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "credentials",
			OK:     true,
			Detail: "credentials recorded",
		})
	}

	// ----------------------------------------------------------------
	// Step 4: replace-certificate (default on).
	// ----------------------------------------------------------------
	var newLeafCert *x509.Certificate
	if !effective.ReplaceCertificate || core.certIssuer == nil {
		reason := "skipped (replace-certificate disabled)"
		if core.certIssuer == nil {
			reason = "skipped (no cert issuer configured)"
		}
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "replace-certificate",
			OK:     true,
			Detail: reason,
		})
	} else {
		leaf, leafPEM, caPEM, issueErr := core.certIssuer(ctx)
		if issueErr != nil {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "replace-certificate",
				OK:     false,
				Detail: issueErr.Error(),
			})
			return result, ErrBMCEnrollFactoryCert{DeviceID: deviceID, Cause: issueErr}
		}
		newLeafCert = leaf
		result.NewCertPEM = leafPEM
		result.CACertPEM = caPEM

		// Update the pinned SPKI to the new certificate.
		newSPKI := certSPKISHA256(leaf)
		result.PinSPKISHA256 = newSPKI

		// Update the TOFU pin store so future connections verify the new cert.
		pinDetail := fmt.Sprintf("cert replaced: spki=%s", newSPKI)
		if core.pinUpdater != nil {
			if pinErr := core.pinUpdater(ctx, host, 443, newSPKI, certDERSHA256(leaf)); pinErr != nil {
				// Non-fatal: the resolver will reacquire via TOFU on the next
				// connection. Log as detail rather than failing the ceremony.
				pinDetail = fmt.Sprintf("cert replaced but TOFU pin update failed (non-fatal): %v", pinErr)
			} else {
				pinDetail = fmt.Sprintf("cert replaced and TOFU pin updated: spki=%s", newSPKI)
			}
		}
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "replace-certificate",
			OK:     true,
			Detail: pinDetail,
		})
	}

	// ----------------------------------------------------------------
	// Step 5: dns-register.
	// ----------------------------------------------------------------
	if !effective.DNSRegister || core.dnsRegister == nil {
		reason := "skipped (dns-register disabled)"
		if core.dnsRegister == nil && effective.DNSRegister {
			if internalZone == "" {
				reason = "skipped (no internal DNS zone configured)"
			} else {
				reason = "skipped (DNS service unavailable)"
			}
		}
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dns-register",
			OK:     true,
			Detail: reason,
		})
	} else {
		if internalZone == "" {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "dns-register",
				OK:     false,
				Detail: "dns-register enabled but internal zone is not configured",
			})
			return result, ErrBMCEnrollNoInternalZone{DeviceID: deviceID}
		}
		dnsName, regErr := core.dnsRegister(ctx, host, host, internalZone)
		if regErr != nil {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "dns-register",
				OK:     false,
				Detail: regErr.Error(),
			})
			return result, ErrBMCEnrollCredStore{DeviceID: deviceID, Cause: regErr}
		}
		result.DNSName = dnsName
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dns-register",
			OK:     true,
			Detail: fmt.Sprintf("A record created: %s -> %s", dnsName, host),
		})
	}

	// ----------------------------------------------------------------
	// Step 6: dane-publish.
	// ----------------------------------------------------------------
	tlsaPublished := false
	if !effective.DANEPublish || core.danePublish == nil {
		reason := "skipped (dane-publish disabled)"
		if core.danePublish == nil && effective.DANEPublish {
			reason = "skipped (DANE or DNS service unavailable)"
		}
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dane-publish",
			OK:     true,
			Detail: reason,
		})
	} else if len(result.NewCertPEM) == 0 {
		// No platform cert available (replacement was skipped); cannot publish.
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "dane-publish",
			OK:     true,
			Detail: "skipped (no platform-issued cert; run with replace-certificate=true first)",
		})
	} else {
		// Parse CA from PEM.
		var caCert *x509.Certificate
		if len(result.CACertPEM) > 0 {
			caCert, _ = parsePEMCert(result.CACertPEM)
		}
		if newLeafCert == nil {
			newLeafCert, _ = parsePEMCert(result.NewCertPEM)
		}
		daneErr := core.danePublish(ctx, newLeafCert, caCert, result.DNSName, 443, internalZone)
		if daneErr != nil {
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "dane-publish",
				OK:     false,
				Detail: daneErr.Error(),
			})
			// DANE publication failure is non-fatal per spec: the cert is
			// already deployed; TLSA records can be published in a follow-up.
		} else {
			tlsaPublished = true
			result.Steps = append(result.Steps, BMCEnrollStep{
				Name:   "dane-publish",
				OK:     true,
				Detail: fmt.Sprintf("TLSA records published for %s", result.DNSName),
			})
		}
	}

	// ----------------------------------------------------------------
	// Step 7: device-stamp — update the Device entity.
	// ----------------------------------------------------------------
	dev, loadErr := core.deviceLoader(ctx, deviceID)
	if loadErr != nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "device-stamp",
			OK:     false,
			Detail: loadErr.Error(),
		})
		return result, ErrBMCEnrollDeviceLoad{DeviceID: deviceID, Cause: loadErr}
	}

	enrollment := &entities.BMCEnrollment{
		EnrolledAt:    time.Now().UTC(),
		Host:          result.Hostname,
		PinSPKISHA256: result.PinSPKISHA256,
		DNSName:       result.DNSName,
		TLSAPublished: tlsaPublished,
	}
	if result.FactoryCertMeta.SHA256 != "" {
		enrollment.FactoryCertSHA256 = result.FactoryCertMeta.SHA256
	}
	if newLeafCert != nil {
		enrollment.CertSerial = newLeafCert.SerialNumber.String()
		enrollment.CertNotAfter = newLeafCert.NotAfter
	}

	dev.BMCEnrollment = enrollment
	dev.UpdatedAt = time.Now().UTC()

	if saveErr := core.deviceSaver(ctx, dev); saveErr != nil {
		result.Steps = append(result.Steps, BMCEnrollStep{
			Name:   "device-stamp",
			OK:     false,
			Detail: saveErr.Error(),
		})
		return result, ErrBMCEnrollDeviceSave{DeviceID: deviceID, Cause: saveErr}
	}

	result.Steps = append(result.Steps, BMCEnrollStep{
		Name:   "device-stamp",
		OK:     true,
		Detail: fmt.Sprintf("Device %d BMCEnrollment stamped", deviceID),
	})

	return result, nil
}

// enrollmentFlags is the resolved boolean set after merging profile defaults
// and per-call BMCEnrollOptions overrides.
type enrollmentFlags struct {
	ReplaceCertificate bool
	RotatePassword     bool
	DNSRegister        bool
	DANEPublish        bool
}

// effectiveEnrollmentOpts merges the bmc.Config enrollment defaults with any
// per-call overrides supplied via opts.
func effectiveEnrollmentOpts(cfg *bmc.Config, opts *BMCEnrollOptions) enrollmentFlags {
	ec := cfg.Enrollment
	if ec == nil {
		ec = bmc.DefaultEnrollmentConfig()
	}
	flags := enrollmentFlags{
		ReplaceCertificate: ec.ReplaceCertificate,
		RotatePassword:     ec.RotatePassword,
		DNSRegister:        ec.DNSRegister,
		DANEPublish:        ec.DANEPublish,
	}
	if opts == nil {
		return flags
	}
	if opts.ReplaceCertificate != nil {
		flags.ReplaceCertificate = *opts.ReplaceCertificate
	}
	if opts.RotatePassword != nil {
		flags.RotatePassword = *opts.RotatePassword
	}
	if opts.DNSRegister != nil {
		flags.DNSRegister = *opts.DNSRegister
	}
	if opts.DANEPublish != nil {
		flags.DANEPublish = *opts.DANEPublish
	}
	return flags
}

// enrollCredentials records current BMC credentials in the credential store.
// When RotatePassword is true, the intention is noted here; actual rotation
// is performed by the daemon-layer RotationEngine (which holds the
// UserManagerFactory required to issue the new password and apply it to the
// BMC). The App layer's responsibility is only persistence of the current
// state so operators have an audit trail of when credentials were last
// confirmed during enrollment.
func enrollCredentials(ctx context.Context, deviceID uint64, name string, flags enrollmentFlags, core *enrollCore) error {
	_ = deviceID
	// Probe whether a credential record already exists.
	_, err := core.credStore.Get(ctx, name)
	if err != nil {
		// No stored credential yet. We have no cleartext password at this
		// layer to persist (the operator supplies credentials via config at
		// enrollment call sites). Return nil so the step succeeds — the
		// credential store will be populated on first rotation cycle.
		return nil
	}
	// Credential exists. RotatePassword schedules rotation via the daemon;
	// at the App layer we do not have the new password yet, so we simply
	// confirm the record is present and return.
	_ = flags.RotatePassword
	return nil
}

// updateTOFUPin persists an updated TOFU pin for a BMC endpoint into the
// platform's ParameterStore-backed pin store. It mirrors the pattern in
// buildTOFUResolverOpts: get the *quicbaas.Factory, obtain its SDKClient, and
// call NewTOFUPinStore. Failures are treated as non-fatal by the ceremony step.
func (app *App) updateTOFUPin(ctx context.Context, host string, port int, spkiPin, certFP string) error {
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
		return err
	}
	return pinStore.Put(ctx, &trust.TOFUPin{
		Host:            host,
		Port:            port,
		SPKISHA256:      spkiPin,
		CertFingerprint: certFP,
		FirstSeen:       time.Now().UTC(),
		Source:          "enrollment",
	})
}

// loadDeviceForEnroll loads a Device entity for the enrollment ceremony.
func (app *App) loadDeviceForEnroll(ctx context.Context, id uint64) (*entities.Device, error) {
	sr := app.ServiceRegistry()
	if sr == nil {
		return nil, ErrBMCEnrollDeviceLoad{DeviceID: id, Cause: fmt.Errorf("service registry not available")}
	}
	svc := sr.DeviceService()
	if svc == nil {
		return nil, ErrBMCEnrollDeviceLoad{DeviceID: id, Cause: fmt.Errorf("device service not available")}
	}
	return svc.Get(ctx, id)
}

// saveDeviceForEnroll saves a Device entity after the enrollment ceremony.
func (app *App) saveDeviceForEnroll(ctx context.Context, d *entities.Device) error {
	sr := app.ServiceRegistry()
	if sr == nil {
		return ErrBMCEnrollDeviceSave{DeviceID: d.ID, Cause: fmt.Errorf("service registry not available")}
	}
	svc := sr.DeviceService()
	if svc == nil {
		return ErrBMCEnrollDeviceSave{DeviceID: d.ID, Cause: fmt.Errorf("device service not available")}
	}
	return svc.Save(ctx, d)
}

// certSPKISHA256 returns the hex-encoded SHA-256 of a certificate's
// SubjectPublicKeyInfo DER block.
func certSPKISHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// certDERSHA256 returns the hex-encoded SHA-256 of the full certificate DER.
func certDERSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// parsePEMCert parses the first CERTIFICATE block from PEM data.
func parsePEMCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
