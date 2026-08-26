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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// enclaveNTSKey marshals a freshly generated NTS private key straight into
// the platform's protected-memory primitive and clears the two buffers it
// passed through on the way: NewMemoryEnclave wipes the PEM slice as it
// copies it into the locked region, and the intermediate DER is cleared
// here. From this point the platform's own copy of the plaintext exists
// only inside the enclave, and only for the duration of a scoped Open.
//
// It does NOT scrub the *ecdsa.PrivateKey the caller generated, and cannot:
// as of Go 1.26 the scalar lives in an internal FIPS representation behind
// a package-level cache, PrivateKey.D is a deprecated legacy view of it,
// and crypto/ecdsa exposes no zeroization API. Wiping D would clear one
// copy, leave the cached one, and read as a stronger guarantee than it is.
//
// That residue is the reason key generation belongs behind a
// non-exportable KMS key handle instead of here — the SDK does not expose
// one yet (go-quicbaas#136, tracked here as #60). The enclave is the
// strongest custody this layer can actually take today; the limit is
// registered in docs/security/protected-memory.md.
func enclaveNTSKey(key *ecdsa.PrivateKey) (*memguard.MemoryEnclave, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	clear(keyDER)

	// NewMemoryEnclave wipes keyPEM as it copies it into the locked region;
	// the repeat clear covers the path where the region could not be
	// allocated and the copy therefore never happened.
	enclave := memguard.NewMemoryEnclave(keyPEM)
	clear(keyPEM)
	if !enclave.IsAlive() {
		return nil, &MessageError{Msg: "NTS private key could not be placed in protected memory"}
	}
	return enclave, nil
}

// storeNTSKey writes the enclaved private key to the secret store.
//
// The SDK request field is a plain []byte whose retention is the SDK's
// business, so the store gets an ordinary COPY rather than a view of the
// locked region: handing it the borrow would leave it holding memory that
// Destroy later frees, and wiping the copy after the call would corrupt
// the stored secret if the SDK kept it. Per
// docs/security/protected-memory.md rule 3 the copy's lifetime is the
// call and the enclave remains the durable custodian.
func storeNTSKey(
	ctx context.Context,
	store secretStore,
	keyPath, description string,
	keyEnclave *memguard.MemoryEnclave,
	metadata map[string]string,
) error {
	return keyEnclave.Open(func(keyPEM []byte) error {
		_, err := store.StoreSecret(ctx, &baasservice.StoreSecretRequest{
			Name:        keyPath,
			Description: description,
			Data:        append([]byte(nil), keyPEM...),
			Metadata:    metadata,
		})
		return err
	})
}

// ntsProvisionSource identifies KMS entries created by this provisioner.
const ntsProvisionSource = "nts-provision"

// ntsCertValidity is the self-signed NTS certificate lifetime. The
// certificate-renewal registry rotates it well before expiry; the horizon
// only bounds the damage of a node that never renews.
const ntsCertValidity = 2 * 365 * 24 * time.Hour

// ErrNTSProvision wraps a failure while provisioning the NTS key material.
type ErrNTSProvision struct {
	Stage string
	Cause error
}

// Error returns a human-readable description of the error.
func (e *ErrNTSProvision) Error() string {
	return "nts-provision: " + e.Stage + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrNTSProvision) Unwrap() error { return e.Cause }

// ProvisionNTSKeys generates and stores the NTS-KE server TLS certificate
// and private key in the KMS so the kms:// URIs in ntp.serve.nts resolve on
// first boot. Same pre-walk contract as ProvisionSecureBootKeys: these URIs
// carry no ?ensure=true (they are a keypair + certificate, not random
// bytes), so nothing else creates them and the fail-closed config walk in
// Init would abort startup with "secret not found" — the deployed daemon
// then never comes up (#55).
//
// It must run after initStores (SecretsService online) and before
// ProcessSecrets. No-op when NTP or NTS is not enabled or the URIs are not
// KMS-managed; idempotent when the key already exists.
func (app *App) ProvisionNTSKeys(ctx context.Context) error {
	if app.NTPConfig == nil || !app.NTPConfig.Enabled ||
		app.NTPConfig.Serve == nil || app.NTPConfig.Serve.NTS == nil ||
		!app.NTPConfig.Serve.NTS.Enabled {
		return nil
	}
	nts := app.NTPConfig.Serve.NTS

	keyPath, keyIsKMS := secureBootKMSPath(nts.KeyURI)
	certPath, certIsKMS := secureBootKMSPath(nts.CertURI)
	if !keyIsKMS && !certIsKMS {
		app.Logger.Debug("nts-provision: no kms:// URIs configured, nothing to provision")
		return nil
	}
	if keyIsKMS != certIsKMS {
		return &ErrNTSProvision{
			Stage: "resolve uris",
			Cause: &MessageError{Msg: "cert-uri and key-uri must both be KMS-managed or both not"},
		}
	}

	// Snapshot the object paths NOW, before ProcessSecrets replaces the
	// config fields with resolved PEM: RegisterNTSCertTarget runs after
	// resolution and can no longer derive them from the config.
	app.ntsRenewalKeyPath = keyPath
	app.ntsRenewalCertPath = certPath

	store := app.secureBootSecretStore()
	if store == nil {
		return &ErrNTSProvision{Stage: "secret store", Cause: &ErrSecureBootSecretsUnavailable{}}
	}
	return app.provisionNTSKeys(ctx, store, keyPath, certPath)
}

// provisionNTSKeys generates and stores the NTS key material against an
// explicit secret store. Split from ProvisionNTSKeys so generation and
// idempotence are exercisable without a live QuicBaaS.
func (app *App) provisionNTSKeys(ctx context.Context, store secretStore, keyPath, certPath string) error {
	// The idempotence probe treats the keypair as ONE validity unit: a torn
	// write (from bootstrap or a failed renewal), a missing half, or a
	// mismatched pair must be re-provisioned at the next boot — otherwise
	// secret resolution hands chronyd an invalid pair and the daemon serves
	// broken NTS until the first renewal sweep repairs it.
	healthy, err := ntsPairHealthy(ctx, store, keyPath, certPath)
	if err != nil {
		return &ErrNTSProvision{Stage: "probe existing pair", Cause: err}
	}
	if healthy {
		app.Logger.Info("nts-provision: coherent keypair already present, leaving untouched",
			"key_path", keyPath, "cert_path", certPath)
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return &ErrNTSProvision{Stage: "generate key", Cause: err}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return &ErrNTSProvision{Stage: "generate serial", Cause: err}
	}

	cn := app.Hostname
	dnsNames := []string{app.Hostname}
	if app.Domain != "" {
		fqdn := app.Hostname + "." + app.Domain
		cn = fqdn
		dnsNames = append(dnsNames, fqdn)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ntsCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return &ErrNTSProvision{Stage: "self-sign certificate", Cause: err}
	}

	keyEnclave, err := enclaveNTSKey(key)
	if err != nil {
		return &ErrNTSProvision{Stage: "marshal private key", Cause: err}
	}
	defer keyEnclave.Destroy()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	createdAt := time.Now().UTC().Format(time.RFC3339)
	meta := func(kind string) map[string]string {
		return map[string]string{
			"source":       ntsProvisionSource,
			"category":     "ntp-nts",
			"kind":         kind,
			"cn":           cn,
			"algorithm":    "ecdsa-p256",
			"created_at":   createdAt,
			"content_type": secureBootPEMContentType,
		}
	}

	// A crash between the writes leaves a half-written pair, which the
	// pair-coherence probe re-provisions cleanly on the next boot.
	if _, err := store.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		Name:        certPath,
		Description: "NTS server certificate",
		Data:        certPEM,
		Metadata:    meta("certificate"),
	}); err != nil {
		return &ErrNTSProvision{Stage: "store certificate at " + certPath, Cause: err}
	}
	if err := storeNTSKey(ctx, store, keyPath, "NTS server private key",
		keyEnclave, meta("private-key")); err != nil {
		return &ErrNTSProvision{Stage: "store private key at " + keyPath, Cause: err}
	}

	app.Logger.Info("nts-provision: NTS server key material provisioned",
		"cn", cn, "cert_path", certPath, "key_path", keyPath)
	return nil
}

// ntsPairHealthy reports whether the KMS holds a coherent NTS keypair: both
// entries present, both parseable, and the certificate's public key matching
// the private key. A clean not-found on either half answers false (provision
// or repair); any other store error is returned so the caller fails closed
// instead of overwriting live key material.
func ntsPairHealthy(ctx context.Context, store secretStore, keyPath, certPath string) (bool, error) {
	keyExists, err := secureBootSecretExists(ctx, store, keyPath)
	if err != nil {
		return false, err
	}
	if !keyExists {
		return false, nil
	}
	certExists, err := secureBootSecretExists(ctx, store, certPath)
	if err != nil {
		return false, err
	}
	if !certExists {
		return false, nil
	}

	keyResp, err := store.GetSecret(ctx, &baasservice.GetSecretRequest{SecretID: keyPath})
	if err != nil {
		return false, err
	}
	certResp, err := store.GetSecret(ctx, &baasservice.GetSecretRequest{SecretID: certPath})
	if err != nil {
		return false, err
	}

	keyBlock, _ := pem.Decode(keyResp.Data)
	if keyBlock == nil {
		return false, nil
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return false, nil
	}
	certBlock, _ := pem.Decode(certResp.Data)
	if certBlock == nil {
		return false, nil
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, nil
	}

	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return false, nil
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false, nil
	}
	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false, nil
	}
	return bytes.Equal(certPub, keyPub), nil
}

// ntsCertTargetName is the renewal-registry name for the NTS-KE server
// certificate.
const ntsCertTargetName = "nts-server"

// ntsKMSPaths resolves the configured NTS kms:// paths, returning ok=false
// when NTS is disabled or the URIs are not KMS-managed.
func (app *App) ntsKMSPaths() (keyPath, certPath string, ok bool) {
	if app.NTPConfig == nil || !app.NTPConfig.Enabled ||
		app.NTPConfig.Serve == nil || app.NTPConfig.Serve.NTS == nil ||
		!app.NTPConfig.Serve.NTS.Enabled {
		return "", "", false
	}
	nts := app.NTPConfig.Serve.NTS
	kp, kOK := secureBootKMSPath(nts.KeyURI)
	cp, cOK := secureBootKMSPath(nts.CertURI)
	if !kOK || !cOK {
		return "", "", false
	}
	return kp, cp, true
}

// ntsRenewalPaths returns the KMS object paths the renewal target manages.
// The snapshot ProvisionNTSKeys captured wins: by the time registration runs
// (initCertManagement, after App.Init), ProcessSecrets has already replaced
// the config's kms:// URIs with PEM material, so deriving from the config
// would silently register nothing. Derivation remains for callers running
// before resolution.
func (app *App) ntsRenewalPaths() (keyPath, certPath string, ok bool) {
	if app.ntsRenewalKeyPath != "" && app.ntsRenewalCertPath != "" {
		return app.ntsRenewalKeyPath, app.ntsRenewalCertPath, true
	}
	return app.ntsKMSPaths()
}

// ntsKEDialAddr is where the renewal sweep reads the NTS-KE certificate the
// running chronyd actually serves. chrony listens on the fixed IANA NTS-KE
// port. Variable so tests point it at a local listener.
var ntsKEDialAddr = "127.0.0.1:4460"

// ntsKEALPN is the RFC 8915 ALPN protocol identifier for NTS-KE.
const ntsKEALPN = "ntske/1"

// ntsServedCertificate dials the local NTS-KE endpoint and returns the leaf
// certificate chronyd is serving. The DEPLOYED certificate — not the KMS
// copy — is the renewal authority: KMS entries that were written but never
// reached chrony (torn write, failed restart) must keep the target due so
// the sweep repairs them.
func ntsServedCertificate(ctx context.Context) (*x509.Certificate, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			// Inspection only: the sweep decides trust from the parsed
			// certificate itself and no data is exchanged on this
			// connection, so there is nothing for verification to protect.
			InsecureSkipVerify: true, // #nosec G402
			NextProtos:         []string{ntsKEALPN},
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", ntsKEDialAddr)
	if err != nil {
		return nil, &ErrNTSProvision{Stage: "read served certificate", Cause: err}
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, &ErrNTSProvision{
			Stage: "read served certificate",
			Cause: &MessageError{Msg: "no peer certificates from " + ntsKEDialAddr},
		}
	}
	return certs[0], nil
}

// RegisterNTSCertTarget registers the NTS-KE server certificate as a
// renewal target. The bootstrap self-signed certificate ProvisionNTSKeys
// creates exists only so the fail-closed secret walk passes and the daemon
// starts; this target's DueOverride marks a self-signed current certificate
// due immediately, so the first renewal sweep replaces it with a
// CA-issued one that NTS clients trusting the platform CA accept.
//
// The renewal authority is the certificate chronyd actually serves on the
// NTS-KE port, mirroring the webservice targets: a reissue counts only once
// the running server presents the new identity, so torn KMS writes and
// failed deployments keep the target due and the sweep converges.
//
// Failure is non-fatal, mirroring the webservice registration: the server
// still serves, but the certificate will not upgrade or renew.
func (app *App) RegisterNTSCertTarget(ctx context.Context) {
	keyPath, certPath, ok := app.ntsRenewalPaths()
	if !ok {
		return
	}

	target := &CertTarget{
		Name:    ntsCertTargetName,
		Kind:    CertKindNTS,
		Current: ntsServedCertificate,
		Reissue: func(ctx context.Context) error {
			return app.reissueNTSCertificateFromCA(ctx, keyPath, certPath)
		},
		DueOverride: func(ctx context.Context, cert *x509.Certificate, readErr error) (bool, string) {
			if readErr != nil || cert == nil {
				// This target registers only when NTS serving is enabled,
				// so an unreadable NTS-KE endpoint means the identity was
				// never deployed or chronyd cannot serve it (torn KMS
				// pair). Reissue-and-redeploy repairs both; reporting
				// "failed" alone would re-read and re-fail every sweep.
				return true, "NTS-KE endpoint unreadable; reissuing and redeploying"
			}
			// The bootstrap certificate is self-signed — identified
			// cryptographically, since Subject/Issuer strings can be
			// crafted to differ on a self-signed certificate. Upgrade it
			// to a CA-issued identity on the first sweep.
			if certIsSelfSigned(cert) {
				return true, "bootstrap self-signed NTS certificate must be upgraded to CA-issued"
			}
			// Anything else must be an identity NTS clients trusting the
			// platform CA actually accept: chained to the platform roots
			// and valid for this host. A wrong-host or foreign-CA
			// certificate would otherwise sit "healthy" until expiry
			// while every client rejects it.
			if reason, invalid := app.ntsServedCertInvalid(cert); invalid {
				return true, reason
			}
			return false, ""
		},
	}

	if err := app.certTargets().Replace(target); err != nil {
		app.Logger.Warn("cert renewal: cannot register the NTS cert target; "+
			"the NTS certificate will NOT be upgraded or renewed automatically", "error", err)
	}
}

// certIsSelfSigned reports whether cert's signature verifies under its own
// public key. This is the cryptographic form of "self-signed": comparing
// Subject and Issuer strings can be defeated by a certificate crafted with
// differing names.
func certIsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// ntsExpectedHostname returns the DNS identity the NTS certificate must be
// valid for — the same identity provisioning and reissue put in the SANs.
func (app *App) ntsExpectedHostname() string {
	if app.Domain != "" {
		return app.Hostname + "." + app.Domain
	}
	return app.Hostname
}

// ntsServedCertInvalid verifies a served, non-self-signed certificate
// against the platform CA roots and the NTS hostname. It returns a due
// reason when the identity is not one NTS clients trusting the platform CA
// would accept, so the sweep repairs it instead of reporting it healthy
// until expiry.
func (app *App) ntsServedCertInvalid(cert *x509.Certificate) (string, bool) {
	if app.CA == nil {
		return "platform CA unavailable to verify the served NTS certificate", true
	}
	rootCert, err := app.CA.TrustedRoot()
	if err != nil {
		return "cannot load the platform CA root: " + err.Error(), true
	}
	pool, err := app.CA.TrustedRootCertPool(rootCert)
	if err != nil {
		return "cannot build the platform CA pool: " + err.Error(), true
	}
	intermediates := x509.NewCertPool()
	if inter, interErr := app.CA.TrustedIntermediate(); interErr == nil && inter != nil {
		intermediates.AddCert(inter)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		DNSName:       app.ntsExpectedHostname(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return "served NTS certificate is not a valid platform identity: " + err.Error(), true
	}
	return "", false
}

// reissueNTSCertificateFromCA generates a fresh key, has the platform CA
// sign it via CSR, replaces both KMS entries, and deploys the pair into the
// running chrony. Clients that trust the platform CA then accept the NTS-KE
// identity. Deployment failure is renewal failure: the served certificate
// is the sweep's authority, so an undeployed pair keeps the target due and
// the next sweep repairs it.
func (app *App) reissueNTSCertificateFromCA(ctx context.Context, keyPath, certPath string) error {
	if app.CA == nil {
		return &ErrNTSProvision{Stage: "reissue", Cause: &MessageError{Msg: "platform CA not available"}}
	}
	store := app.secureBootSecretStore()
	if store == nil {
		return &ErrNTSProvision{Stage: "secret store", Cause: &ErrSecureBootSecretsUnavailable{}}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return &ErrNTSProvision{Stage: "generate key", Cause: err}
	}

	cn := app.Hostname
	dnsNames := []string{app.Hostname}
	if app.Domain != "" {
		fqdn := app.Hostname + "." + app.Domain
		cn = fqdn
		dnsNames = append(dnsNames, fqdn)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		return &ErrNTSProvision{Stage: "create CSR", Cause: err}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cert, err := app.CA.SignCSR(ctx, csrPEM, &quicbaasca.SignOptions{ValidityDays: 365})
	if err != nil {
		return &ErrNTSProvision{Stage: "CA sign", Cause: err}
	}

	keyEnclave, err := enclaveNTSKey(key)
	if err != nil {
		return &ErrNTSProvision{Stage: "marshal private key", Cause: err}
	}
	defer keyEnclave.Destroy()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	createdAt := time.Now().UTC().Format(time.RFC3339)
	meta := func(kind string) map[string]string {
		return map[string]string{
			"source":       ntsProvisionSource,
			"category":     "ntp-nts",
			"kind":         kind,
			"cn":           cn,
			"algorithm":    "ecdsa-p256",
			"issuer":       "platform-ca",
			"created_at":   createdAt,
			"content_type": secureBootPEMContentType,
		}
	}

	if err := storeNTSPair(ctx, store, keyPath, certPath, keyEnclave, certPEM, meta); err != nil {
		return err
	}

	if err := app.deployNTSMaterial(ctx, keyEnclave, certPEM); err != nil {
		return err
	}

	app.Logger.Info("nts: certificate reissued from the platform CA and deployed",
		"cn", cn, "serial", cert.SerialNumber.String())
	return nil
}

// storeNTSPair writes the renewed keypair to the KMS, key FIRST. The order
// matters for the torn-write window: the next daemon restart resolves
// whatever the KMS holds, and the sweep's authority is the certificate the
// running chronyd serves — a key-without-new-cert tear leaves the served
// certificate stale (still self-signed or near expiry), so the target stays
// due and the next sweep regenerates and redeploys the whole pair.
func storeNTSPair(
	ctx context.Context,
	store secretStore,
	keyPath, certPath string,
	keyEnclave *memguard.MemoryEnclave,
	certPEM []byte,
	meta func(kind string) map[string]string,
) error {
	if err := storeNTSKey(ctx, store, keyPath, "NTS server private key",
		keyEnclave, meta("private-key")); err != nil {
		return &ErrNTSProvision{Stage: "store private key at " + keyPath, Cause: err}
	}
	if _, err := store.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		Name: certPath, Description: "NTS server certificate (CA-issued)",
		Data: certPEM, Metadata: meta("certificate"),
	}); err != nil {
		return &ErrNTSProvision{Stage: "store certificate at " + certPath, Cause: err}
	}
	return nil
}

// deployNTSMaterial installs a renewed NTS pair into the running chrony via
// the NTP service's serialized rotation: the service holds its own lock,
// keeps the rotated material in service-private override state, and
// restarts chronyd. The shared NTPConfig is NOT mutated — configuration
// readers cannot race the renewal, and a daemon restart converges to the
// same material through normal secret resolution (the KMS was written
// first). Called only after both KMS writes succeeded.
func (app *App) deployNTSMaterial(ctx context.Context, keyEnclave *memguard.MemoryEnclave, certPEM []byte) error {
	if app.ntpApplier == nil {
		return &ErrNTSProvision{
			Stage: "deploy",
			Cause: &MessageError{Msg: "NTP service not started; renewed NTS material not deployed"},
		}
	}
	if err := app.ntpApplier.RotateNTSMaterial(ctx, keyEnclave, certPEM); err != nil {
		return &ErrNTSProvision{Stage: "deploy", Cause: err}
	}
	return nil
}
