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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"net"
	"strings"

	acmeclient "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme/client"
	dns01 "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme/dns01"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/smc" // register CGI cert backend
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// defaultBMCCertValidDays is used when the Identity block doesn't
// specify a Valid duration. 90 days matches the ACME default and the
// platform's cert-renewal cadence.
const defaultBMCCertValidDays = 90

// ACMEIssuer is the narrow subset of acmeclient.Client that
// issueBMCCertificateCore uses. Unit tests substitute a fake.
type ACMEIssuer interface {
	RequestCertificate(ctx context.Context, req *acmeclient.CertificateRequest) (*x509.Certificate, error)
}

// LocalCAIssuer is the narrow subset of platform CA used for fallback
// issuance. Unit tests substitute a fake. The signature matches the native
// pkg/ca.TrustedCA.IssueCertificate surface, which returns an
// *IssuedCertificate wrapping the parsed certificate, its PEM encoding and
// chain metadata.
type LocalCAIssuer interface {
	IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error)
}

// resolveACMEIssuer returns the ACME issuer to use for this issuance,
// preferring the lazy resolver so a client initialized after the target was
// built is picked up.
//
// CONTRACT: the resolver must return a nil INTERFACE when it has no issuer, not
// a typed nil pointer. An interface holding a typed nil is not == nil, so it
// would be taken as a live issuer and nil-panic on the first call -- and worse,
// RequireACME would not fire, so the refusal that protects against a silent
// issuer substitution would be skipped too. InitCertManagement's resolver
// therefore checks app.ACMEClient == nil and returns a bare nil.
func (o issueBMCCertificateOptions) resolveACMEIssuer() ACMEIssuer {
	if o.ACMEIssuerFunc == nil {
		return o.ACMEIssuer
	}
	if issuer := o.ACMEIssuerFunc(); issuer != nil {
		return issuer
	}
	return o.ACMEIssuer
}

// bmcDeployer is the narrow interface the deployment step uses.
// *bmc.AutoCertManager satisfies this.
type bmcDeployer interface {
	ReplaceWebCertificate(ctx context.Context, certPEM []byte, keyPEM *memguard.MemoryEnclave) error
	GetWebCertificate(ctx context.Context) (*x509.Certificate, error)
	Close() error
}

// generateBMCKeyPair produces a fresh keypair for BMC TLS cert
// issuance. The key lives only in platformd memory long enough to
// build a CSR and ship PEM to the BMC; it is NOT persisted in the
// platform KMS. Each renewal generates a fresh key.
//
// Supported algorithms:
//   - "ECDSA" / "EC" (default) with curves "P-256" (default), "P-384", "P-521"
//   - "RSA" with configurable KeySize (default 2048)
//
// Empty KeyConfig defaults to ECDSA P-256 — the recommended baseline
// for BMC certs: fast, compact, widely supported by modern BMC
// firmware.
func generateBMCKeyPair(keyCfg *common.KeyConfig) (crypto.Signer, *memguard.MemoryEnclave, error) {
	alg := "ECDSA"
	curve := "P-256"
	rsaBits := 2048
	if keyCfg != nil {
		if keyCfg.KeyAlgorithm != "" {
			alg = strings.ToUpper(keyCfg.KeyAlgorithm)
		}
		if keyCfg.ECCConfig != nil && keyCfg.ECCConfig.Curve != "" {
			curve = keyCfg.ECCConfig.Curve
		}
		if keyCfg.RSAConfig != nil && keyCfg.RSAConfig.KeySize > 0 {
			rsaBits = keyCfg.RSAConfig.KeySize
		}
	}

	var priv crypto.Signer
	switch alg {
	case "ECDSA", "EC":
		c, err := namedCurve(curve)
		if err != nil {
			return nil, nil, err
		}
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, nil, ErrKeyGenerate{Cause: err}
		}
		priv = k
	case "RSA":
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, nil, ErrKeyGenerate{Cause: err}
		}
		priv = k
	default:
		return nil, nil, ErrUnsupportedKeyAlgorithm{Algorithm: alg}
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, ErrKeyGenerate{Cause: err}
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return priv, memguard.NewMemoryEnclave(pemBytes), nil
}

// namedCurve maps a curve name string to an elliptic.Curve.
func namedCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "", "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, ErrUnsupportedKeyCurve{Curve: name}
	}
}

// buildBMCSubjectAltNames constructs SANs for a BMC certificate.
// Uses configured SANS when present; otherwise derives from CN +
// hostmaster.
func buildBMCSubjectAltNames(bmcCfg *bmc.Config, hostmaster string) *quicbaasca.CASubjectAlternativeNames {
	if bmcCfg == nil || bmcCfg.Certificate == nil {
		return &quicbaasca.CASubjectAlternativeNames{}
	}
	if bmcCfg.Certificate.SANS != nil {
		return bmcCfg.Certificate.SANS
	}
	sans := &quicbaasca.CASubjectAlternativeNames{}
	if cn := bmcCfg.Certificate.Subject.CommonName; cn != "" {
		sans.DNS = []string{cn}
	}
	if hostmaster != "" {
		sans.Email = []string{hostmaster}
	}
	return sans
}

// casdkSubjectToPKIXName converts a CA SDK subject into a pkix.Name
// for CSR construction. quicbaasca.CASubject carries scalar strings;
// pkix.Name expects []string per multi-valued RDN, so we wrap when
// non-empty.
func casdkSubjectToPKIXName(s quicbaasca.CASubject) pkix.Name {
	name := pkix.Name{CommonName: s.CommonName}
	if s.Organization != "" {
		name.Organization = []string{s.Organization}
	}
	if s.Country != "" {
		name.Country = []string{s.Country}
	}
	if s.Province != "" {
		name.Province = []string{s.Province}
	}
	if s.Locality != "" {
		name.Locality = []string{s.Locality}
	}
	if s.Address != "" {
		name.StreetAddress = []string{s.Address}
	}
	if s.PostalCode != "" {
		name.PostalCode = []string{s.PostalCode}
	}
	return name
}

// buildBMCCSR builds and signs a CSR with the given private key.
func buildBMCCSR(bmcCfg *bmc.Config, privKey crypto.Signer, hostmaster string) ([]byte, error) {
	if bmcCfg.Certificate == nil {
		return nil, ErrBMCCertDisabled
	}
	subj := bmcCfg.Certificate.Subject
	sans := buildBMCSubjectAltNames(bmcCfg, hostmaster)

	tmpl := &x509.CertificateRequest{
		Subject: casdkSubjectToPKIXName(subj),
	}
	if sans != nil {
		tmpl.DNSNames = sans.DNS
		tmpl.EmailAddresses = sans.Email
		for _, ipStr := range sans.IPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			}
		}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, privKey)
	if err != nil {
		return nil, ErrCSRCreate{Cause: err}
	}
	return csrDER, nil
}

// buildBMCACMERequest assembles the per-call CertificateRequest for
// ACME issuance. The ChallengeSetup/Cleanup closures use the
// dns01.ComputeChallengeValue helper from go-trusted-ca and the
// platform dnsUpdater to write TXT records directly.
func buildBMCACMERequest(
	ctx context.Context,
	bmcCfg *bmc.Config,
	csrDER []byte,
	dns dnsUpdater,
	ttl int,
	logger *slog.Logger,
) (*acmeclient.CertificateRequest, error) {
	if bmcCfg.Certificate == nil || bmcCfg.Certificate.ACME == nil || bmcCfg.Certificate.ACME.Challenge == "" {
		return nil, ErrMissingACMEConfig
	}
	acmeCfg := bmcCfg.Certificate.ACME
	if acmeCfg.Challenge != "dns-01" {
		// P2 config validation should have caught this — defense in depth.
		return nil, ErrInvalidChallengeType{Got: acmeCfg.Challenge}
	}
	// dns-01 cannot be answered without a DNS updater, and production passes
	// app.DNSService, which is nil whenever DNS is disabled or failed to
	// initialize. Caught HERE rather than inside the challenge closures: those
	// run deep inside the ACME client, so a nil dereference there becomes a
	// panic on the boot goroutine -- outside the sweep's safeEvaluate -- and
	// takes platformd down, in the exact code path that promises
	// warn-and-continue.
	if dns == nil {
		return nil, ErrMissingDNSUpdater{AuthzValue: acmeCfg.AuthzValue}
	}
	authzValue := acmeCfg.AuthzValue
	if authzValue == "" {
		authzValue = bmcCfg.Certificate.Subject.CommonName
	}
	if authzValue == "" {
		return nil, ErrMissingAuthzValue
	}
	authzType := acmeCfg.AuthzType
	if authzType == "" {
		authzType = "dns"
	}

	if ttl <= 0 {
		ttl = 60 // default
	}

	return &acmeclient.CertificateRequest{
		AuthzType:     authzType,
		AuthzValue:    authzValue,
		ChallengeType: "dns-01",
		CSR:           csrDER,
		ChallengeSetup: func(challengeType, token, keyAuth string) error {
			if challengeType != "dns-01" {
				return nil
			}
			txtValue := dns01.ComputeChallengeValue(keyAuth)
			name := "_acme-challenge." + strings.TrimSuffix(strings.TrimSpace(authzValue), ".")
			return dns.AddRecord(ctx, name, "TXT", txtValue, ttl)
		},
		ChallengeCleanup: func(challengeType string) {
			if challengeType != "dns-01" {
				return
			}
			name := "_acme-challenge." + strings.TrimSuffix(strings.TrimSpace(authzValue), ".")
			if err := dns.DeleteRecord(ctx, name, "TXT"); err != nil && logger != nil {
				logger.Info("bmc-cert: dns-01 cleanup error (best-effort)", "err", err)
			}
		},
	}, nil
}

// buildBMCLocalCARequest constructs the CACertificateRequest for
// local-CA fallback issuance.
func buildBMCLocalCARequest(bmcCfg *bmc.Config, hostmaster string) *quicbaasca.CACertificateRequest {
	valid := defaultBMCCertValidDays
	if bmcCfg.Certificate.Valid > 0 {
		valid = bmcCfg.Certificate.Valid
	}
	return &quicbaasca.CACertificateRequest{
		Subject: bmcCfg.Certificate.Subject,
		SANS:    buildBMCSubjectAltNames(bmcCfg, hostmaster),
		Valid:   valid,
	}
}

// issueBMCCertificateOptions bundles the dependencies that
// issueBMCCertificateCore needs. The *App method wrapper fills these
// from app state; unit tests inject in-process fakes.
type issueBMCCertificateOptions struct {
	// ACMEIssuerFunc resolves the ACME issuer at ISSUANCE time rather than at
	// target-construction time. Optional; ACMEIssuer is used when nil.
	//
	// It exists because the renewal target's Reissue closure captures these
	// options by value. A nil ACMEIssuer captured at boot stays nil for the
	// lifetime of the process, so a BMC target built before the ACME client
	// existed could never converge: every scheduled retry would re-use the same
	// nil issuer and fail identically, forever. Resolving lazily lets a client
	// initialized later in boot -- or re-initialized after a transient failure
	// -- be picked up on the next sweep.
	ACMEIssuerFunc func() ACMEIssuer

	// ACMEIssuer is used when bmcCfg.Certificate.ACME is configured.
	// nil forces local-CA issuance.
	ACMEIssuer ACMEIssuer

	// LocalCAIssuer must be non-nil and serves as the fallback.
	LocalCAIssuer LocalCAIssuer

	// DNSUpdater is required when ACMEIssuer is non-nil.
	DNSUpdater dnsUpdater

	// DNSTTL is the TXT record TTL. Zero falls back to provider default.
	DNSTTL int

	// Hostmaster is the operator email folded into derived SANs.
	Hostmaster string

	// TrustRoots are the roots a certificate found on the BMC must chain to
	// before it is accepted as one we issued. Nil means provenance cannot be
	// established, and an unverifiable certificate is treated as NOT ours.
	TrustRoots *x509.CertPool

	// RequireACME turns the local-CA fallback into a typed error when the BMC
	// declares ACME issuance. Off by default so the primitive's long-standing
	// behaviour is unchanged for callers that accept the fallback; the platform
	// boot wiring turns it on.
	RequireACME bool

	// BackendOverride pins the deploy backend, bypassing bmcCfg.Backend.
	BackendOverride bmc.CertBackend

	// Logger receives structured events. May be nil.
	Logger *slog.Logger

	// Deployer is an optional override for the deployment step.
	// When nil, a fresh *bmc.AutoCertManager is constructed.
	Deployer bmcDeployer

	// OnCertIssued is an optional hook called after the certificate DER
	// is obtained and parsed, BEFORE it is deployed to the BMC. It is
	// used for RFC 7671 §8.1 DANE pre-publication during cert renewal:
	// the new DANE-EE TLSA record is added alongside the existing records
	// so DNS validators never see an unmatched certificate during the
	// transition window. Hook errors are NON-FATAL: the error is logged
	// at warn level and issuance continues to the deploy step.
	// nil = no-op; existing tests are unaffected.
	OnCertIssued func(ctx context.Context, leaf *x509.Certificate) error

	// OnCertDeployed is an optional hook called after
	// deployer.ReplaceWebCertificate succeeds. It is used to (a) update
	// the stored TOFU SPKI pin to the new certificate and (b) re-publish
	// the full TLSA record set (DANE-TA from the CA + EE per policy)
	// under the device's enrolled DNS name. Hook errors are NON-FATAL
	// but are logged at error level: a stale pin or TLSA record is
	// operator-actionable; the deploy itself succeeded and must not be
	// rolled back. The ca argument may be nil when the CA cert is
	// unavailable (ACME path without chain access); the hook
	// implementation must tolerate nil ca.
	// nil = no-op; existing tests are unaffected.
	OnCertDeployed func(ctx context.Context, leaf, ca *x509.Certificate) error
}

// issueBMCCertificateCore is the issuance engine shared by the
// App-bound method and unit tests. It:
//
//  1. Generates a fresh in-memory keypair (NOT persisted to KMS).
//  2. Builds and signs a CSR for the BMC's configured Subject + SANs.
//  3. Drives ACME (dns-01 via platform DNS) or local-CA fallback.
//  4. Invokes OnCertIssued (if set) — non-fatal pre-publish hook.
//  5. Deploys cert+key PEM to the BMC via AutoCertManager.
//  6. Invokes OnCertDeployed (if set) — non-fatal pin-update + TLSA hook.
//  7. Returns a CertTarget whose Current/Reissue closures re-enter
//     this function for renewal.
func issueBMCCertificateCore(
	ctx context.Context,
	deviceID string,
	bmcCfg *bmc.Config,
	opts issueBMCCertificateOptions,
) (*CertTarget, error) {
	if bmcCfg == nil {
		return nil, bmc.ErrNilConfig{}
	}
	if err := bmcCfg.Validate(); err != nil {
		return nil, err
	}
	if bmcCfg.Certificate == nil {
		return nil, ErrBMCCertDisabled
	}
	if opts.LocalCAIssuer == nil {
		return nil, ErrMissingLocalCAIssuer
	}

	privKey, keyPEM, err := generateBMCKeyPair(bmcCfg.Key)
	if err != nil {
		return nil, err
	}
	// If we bail before Deploy takes ownership, scrub the key PEM.
	scrubOnError := true
	defer func() {
		if scrubOnError {
			keyPEM.Destroy()
		}
	}()

	csrDER, err := buildBMCCSR(bmcCfg, privKey, opts.Hostmaster)
	if err != nil {
		return nil, err
	}

	var certDER []byte
	// caCert is populated on the local-CA path (from CACertificatePEM) and
	// passed to OnCertDeployed. It remains nil on the ACME path unless a
	// chain is available in the future; the hook must tolerate nil ca.
	var caCert *x509.Certificate

	acmeRequested := bmcCfg.Certificate.ACME != nil &&
		bmcCfg.Certificate.ACME.Challenge != ""

	// (*bmc.Config).validateCertBlock REQUIRES certificate.acme.challenge ==
	// "dns-01" whenever a BMC certificate is configured, so a validated config
	// reaching issuance always asked for ACME. Falling back to the local CA
	// therefore puts a certificate on the BMC signed by an issuer the operator
	// did not choose. That fallback is deliberate and long-standing (see
	// TestIssueBMCCertificateCore_LocalCAFallback) so it is left in place, but it
	// must not be silent: the only other evidence is the issuer field of a
	// certificate nobody inspects until it fails a trust check.
	acmeIssuer := opts.resolveACMEIssuer()
	if acmeRequested && acmeIssuer == nil && opts.RequireACME {
		return nil, ErrBMCACMEIssuerUnavailable{DeviceID: deviceID}
	}
	if acmeRequested && acmeIssuer == nil && opts.Logger != nil {
		opts.Logger.Warn("BMC certificate: configured for ACME issuance but no ACME "+
			"issuer is wired; issuing from the local CA instead. The BMC will present "+
			"a certificate from an issuer the configuration did not select.",
			"device", deviceID)
	}

	useACME := acmeIssuer != nil && acmeRequested
	if useACME {
		acmeReq, buildErr := buildBMCACMERequest(ctx, bmcCfg, csrDER, opts.DNSUpdater, opts.DNSTTL, opts.Logger)
		if buildErr != nil {
			return nil, buildErr
		}
		cert, reqErr := acmeIssuer.RequestCertificate(ctx, acmeReq)
		if reqErr != nil {
			return nil, ErrBMCACMEIssuance{DeviceID: deviceID, Cause: reqErr}
		}
		certDER = cert.Raw
	} else {
		caReq := buildBMCLocalCARequest(bmcCfg, opts.Hostmaster)
		issued, issueErr := opts.LocalCAIssuer.IssueCertificate(ctx, caReq)
		if issueErr != nil {
			return nil, ErrBMCLocalIssuance{DeviceID: deviceID, Cause: issueErr}
		}
		certDER = issued.Certificate.Raw
		// Parse the issuing CA cert for DANE-TA publication. A parse failure
		// is non-fatal for the issuance itself — caCert remains nil and the
		// hook receives nil ca, which is permitted.
		if len(issued.CACertificatePEM) > 0 {
			caCert, _ = parsePEMCert(issued.CACertificatePEM)
		}
	}

	leaf, parseErr := x509.ParseCertificate(certDER)
	if parseErr != nil {
		return nil, ErrBMCLocalIssuance{DeviceID: deviceID, Cause: parseErr}
	}

	// OnCertIssued — pre-publish hook (RFC 7671 §8.1 rollover).
	// Failure is non-fatal: pre-publication is a best-effort optimisation.
	if opts.OnCertIssued != nil {
		if hookErr := opts.OnCertIssued(ctx, leaf); hookErr != nil {
			if opts.Logger != nil {
				opts.Logger.Warn("bmc-cert: OnCertIssued hook failed (non-fatal, continuing deploy)",
					"device_id", deviceID, "error", hookErr)
			}
		}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	deployer := opts.Deployer
	ownDeployer := false
	if deployer == nil {
		backend := opts.BackendOverride
		if backend == "" {
			backend = bmcCfg.Backend
		}
		mgr, deployErr := bmc.NewAutoCertManager(bmcCfg, backend, opts.Logger)
		if deployErr != nil {
			return nil, deployErr
		}
		deployer = mgr
		ownDeployer = true
	}
	if err := deployer.ReplaceWebCertificate(ctx, certPEM, keyPEM); err != nil {
		if ownDeployer {
			_ = deployer.Close()
		}
		return nil, ErrBMCDeploy{DeviceID: deviceID, Cause: err}
	}
	if ownDeployer {
		_ = deployer.Close()
	}
	// keyPEM ownership was transferred to the deploy chain which is
	// responsible for scrubbing it; mark success so our deferred
	// scrub is a no-op.
	scrubOnError = false

	// OnCertDeployed — pin update + full TLSA re-publish hook.
	// Failure is non-fatal: the deploy succeeded; stale state is
	// operator-actionable.
	if opts.OnCertDeployed != nil {
		if hookErr := opts.OnCertDeployed(ctx, leaf, caCert); hookErr != nil {
			if opts.Logger != nil {
				opts.Logger.Error("bmc-cert: OnCertDeployed hook failed (non-fatal, deploy succeeded)",
					"device_id", deviceID, "error", hookErr)
			}
		}
	}

	return buildBMCCertTarget(deviceID, bmcCfg, opts), nil
}

// buildBMCCertTarget constructs the renewal target for a BMC.
//
// It is deliberately independent of issuance: both closures capture only
// deviceID, bmcCfg and opts, and neither needs anything produced by a preceding
// issue-and-deploy. That lets boot register a target for an already-provisioned
// BMC and let the sweep decide whether renewal is due, instead of rotating the
// BMC identity on every daemon restart.
func buildBMCCertTarget(
	deviceID string, bmcCfg *bmc.Config, opts issueBMCCertificateOptions) *CertTarget {

	return &CertTarget{
		Name: "bmc." + deviceID,
		Kind: CertKindBMC,
		Current: func(ctx context.Context) (*x509.Certificate, error) {
			// Honour the Deployer override the deploy step already honours.
			// GetWebCertificate is part of bmcDeployer, so reading and writing
			// went through different objects for no reason -- which also left
			// this closure untestable without a live BMC.
			if opts.Deployer != nil {
				return opts.Deployer.GetWebCertificate(ctx)
			}
			mgr, err := bmc.NewAutoCertManager(bmcCfg, bmcCfg.Backend, opts.Logger)
			if err != nil {
				return nil, err
			}
			defer mgr.Close()
			return mgr.GetWebCertificate(ctx)
		},
		Reissue: func(ctx context.Context) error {
			_, err := issueBMCCertificateCore(ctx, deviceID, bmcCfg, opts)
			return err
		},
		// An identity mismatch makes the target due regardless of expiry.
		//
		// Without this, a BMC still on its factory certificate is never
		// provisioned by the sweep: that certificate is typically valid for
		// years, so the expiry test skips it every single day. Boot-time
		// provisioning is deliberately non-fatal, so this is the path that
		// actually recovers a BMC that was unreachable or failed issuance at
		// startup -- otherwise "the sweep will retry" would be untrue.
		DueOverride: func(_ context.Context, cert *x509.Certificate, readErr error) (bool, string) {
			if readErr != nil {
				// Nothing readable on the BMC. On a device that has never been
				// provisioned this is the normal state, and it is precisely the
				// case issuance fixes -- so converge rather than reporting
				// "failed" every day for the life of the process.
				return true, "no readable certificate on the BMC: " + readErr.Error()
			}
			if bmcCertMatchesConfiguredIdentity(cert, bmcCfg, opts.Hostmaster, opts.TrustRoots) {
				return false, ""
			}
			return true, "deployed certificate does not chain to the configured issuer " +
				"or does not match the configured identity"
		},
	}
}

// bmcCertMatchesConfiguredIdentity reports whether an already-deployed
// certificate is the one this platform configuration asks for.
//
// It is the discriminator between "this BMC is already provisioned" and "this
// BMC still presents its factory self-signed certificate". A factory cert is
// typically long-lived, so expiry alone cannot tell them apart: without an
// identity check, boot would look at a factory cert, decide renewal is not due,
// and never provision the BMC at all.
func bmcCertMatchesConfiguredIdentity(
	cert *x509.Certificate, bmcCfg *bmc.Config, hostmaster string, roots *x509.CertPool) bool {

	if cert == nil || bmcCfg == nil || bmcCfg.Certificate == nil {
		return false
	}

	cn := bmcCfg.Certificate.Subject.CommonName
	sans := buildBMCSubjectAltNames(bmcCfg, hostmaster)
	var dnsNames, ips []string
	if sans != nil {
		dnsNames = sans.DNS
		ips = sans.IPs
	}

	// Nothing configured to match against: we cannot claim the BMC carries our
	// identity, so treat it as unprovisioned rather than guessing.
	if cn == "" && len(dnsNames) == 0 && len(ips) == 0 {
		return false
	}

	// PROVENANCE FIRST. Names alone prove nothing: anyone can mint a
	// self-signed certificate carrying the expected CN and SANs, and a factory
	// certificate or a substituted one would then be read as "already
	// provisioned". Boot would skip provisioning and DueOverride would report
	// not-due on every sweep, leaving the BMC on an unauthenticated certificate
	// indefinitely -- the exact failure the identity check was added to prevent,
	// inverted.
	//
	// No roots means provenance cannot be established, so the certificate is
	// NOT ours. That direction is deliberate: the cost of being wrong is one
	// reissue, whereas trusting an unverifiable certificate is silent and
	// permanent.
	if roots == nil {
		return false
	}
	verifyName := cn
	if verifyName == "" && len(dnsNames) > 0 {
		verifyName = dnsNames[0]
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   verifyName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return false
	}

	// The subject CN the CSR requests must be present. This alone is NOT
	// sufficient -- CN is not a hostname for validation purposes and modern TLS
	// ignores it -- which is why every configured SAN is checked below too.
	if cn != "" && cert.Subject.CommonName != cn {
		return false
	}

	// EVERY configured identity must verify, not merely one of them. A
	// certificate covering a subset is not the certificate this configuration
	// asked for: leaving it in place would strand the remaining names
	// undeployed while boot reported the BMC as already provisioned.
	for _, name := range dnsNames {
		if cert.VerifyHostname(name) != nil {
			return false
		}
	}
	for _, ip := range ips {
		if cert.VerifyHostname(ip) != nil {
			return false
		}
	}
	return true
}
