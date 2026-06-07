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
	IssueCertificate(req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error)
}

// bmcDeployer is the narrow interface the deployment step uses.
// *bmc.AutoCertManager satisfies this.
type bmcDeployer interface {
	ReplaceWebCertificate(ctx context.Context, certPEM []byte, keyPEM *memguard.Secret) error
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
func generateBMCKeyPair(keyCfg *common.KeyConfig) (crypto.Signer, *memguard.Secret, error) {
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
	return priv, memguard.New(pemBytes), nil
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

	// BackendOverride pins the deploy backend, bypassing bmcCfg.Backend.
	BackendOverride bmc.CertBackend

	// Logger receives structured events. May be nil.
	Logger *slog.Logger

	// Deployer is an optional override for the deployment step.
	// When nil, a fresh *bmc.AutoCertManager is constructed.
	Deployer bmcDeployer
}

// issueBMCCertificateCore is the issuance engine shared by the
// App-bound method and unit tests. It:
//
//  1. Generates a fresh in-memory keypair (NOT persisted to KMS).
//  2. Builds and signs a CSR for the BMC's configured Subject + SANs.
//  3. Drives ACME (dns-01 via platform DNS) or local-CA fallback.
//  4. Deploys cert+key PEM to the BMC via AutoCertManager.
//  5. Returns a CertTarget whose Current/Reissue closures re-enter
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
	useACME := opts.ACMEIssuer != nil &&
		bmcCfg.Certificate.ACME != nil &&
		bmcCfg.Certificate.ACME.Challenge != ""
	if useACME {
		acmeReq, buildErr := buildBMCACMERequest(ctx, bmcCfg, csrDER, opts.DNSUpdater, opts.DNSTTL, opts.Logger)
		if buildErr != nil {
			return nil, buildErr
		}
		cert, reqErr := opts.ACMEIssuer.RequestCertificate(ctx, acmeReq)
		if reqErr != nil {
			return nil, ErrBMCACMEIssuance{DeviceID: deviceID, Cause: reqErr}
		}
		certDER = cert.Raw
	} else {
		caReq := buildBMCLocalCARequest(bmcCfg, opts.Hostmaster)
		issued, issueErr := opts.LocalCAIssuer.IssueCertificate(caReq)
		if issueErr != nil {
			return nil, ErrBMCLocalIssuance{DeviceID: deviceID, Cause: issueErr}
		}
		certDER = issued.Certificate.Raw
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

	target := &CertTarget{
		Name: "bmc." + deviceID,
		Kind: CertKindBMC,
		Current: func(ctx context.Context) (*x509.Certificate, error) {
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
	}
	return target, nil
}
